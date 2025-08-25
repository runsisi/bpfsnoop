// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// hasBuiltinBTF checks if kernel module has built-in BTF
func hasBuiltinBTF(moduleName string) bool {
	if moduleName == "" || moduleName == "vmlinux" {
		return true // vmlinux always has BTF
	}

	// Check if module BTF exists under /sys/kernel/btf/
	btfPath := filepath.Join("/sys/kernel/btf", moduleName)
	return fileExists(btfPath)
}

// checkKprobeArgLimits warns about parameter limitations when using kprobe
func checkKprobeArgLimits(fn *KFunc) {
	if fn.Func == nil {
		return
	}

	funcProto, ok := fn.Func.Type.(*btf.FuncProto)
	if !ok {
		return
	}

	paramCount := len(funcProto.Params)

	// Determine max register arguments based on architecture
	var maxKprobeArgs int
	switch runtime.GOARCH {
	case "amd64":
		maxKprobeArgs = 6 // x86_64: RDI, RSI, RDX, RCX, R8, R9
	case "arm64":
		maxKprobeArgs = 8 // ARM64: X0-X7
	default:
		maxKprobeArgs = 6 // Conservative default for other architectures
		WarnLog("Warning: Unknown architecture %s, assuming 6 register arguments for kprobe", runtime.GOARCH)
	}

	if paramCount > maxKprobeArgs {
		WarnLog("Warning: Function %s has %d parameters, but kprobe can only access first %d register arguments on %s. Parameters %d+ will be 0.",
			fn.Name(), paramCount, maxKprobeArgs, runtime.GOARCH, maxKprobeArgs+1)
	}
}

// needsKprobe determines if we should use kprobe instead of ftrace
func needsKprobe(fn *KFunc) bool {
	// For tracepoints, keep using original method
	if fn.IsTp {
		return false
	}

	// Check the module of the function
	if fn.Ksym != nil && fn.Ksym.mod != "" && fn.Ksym.mod != "vmlinux" {
		if !hasBuiltinBTF(fn.Ksym.mod) {
			checkKprobeArgLimits(fn)
			return true
		}
	}

	return false // vmlinux functions use ftrace
}

// NeedsKprobe checks if any functions need kprobe attachment
func NeedsKprobe(kfuncs KFuncs) bool {
	for _, fn := range kfuncs {
		if needsKprobe(fn) {
			return true
		}
	}
	return false
}

type tracingFunc struct {
	l link.Link
	p *ebpf.Program
}

func (t *tracingFunc) Close() {
	_ = t.l.Close()
	_ = t.p.Close()
}

func ignoreFuncTraceErr(err error, fnName string) bool {
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, ebpf.ErrNotSupported) {
		return true
	}
	if errors.Is(err, unix.EBUSY) /* Because no nop5 at the function entry, especially non-traceable funcs */ {
		VerboseLog("Cannot trace kfunc %s", fnName)
		return true
	}
	// Add kprobe specific error handling
	if errors.Is(err, unix.EADDRNOTAVAIL) {
		VerboseLog("Cannot attach kprobe to %s", fnName)
		return true
	}
	return false
}

func ignoreFuncTraceVerifierErr(err error, fnName string) bool {
	if errors.Is(err, unix.ENOENT) {
		return true
	}

	s := err.Error()

	// STRUCT arg is unsupported since
	// commit fec56f5890 ("bpf: Introduce BPF trampoline") kernel 5.5.
	// STRUCT arg is supported if size <= 16 since
	// commit 720e6a4351 ("bpf: Allow struct argument in trampoline based programs")
	// kernel 6.1.
	if strings.Contains(s, "type STRUCT is unsupported") {
		VerboseLog("Cannot trace STRUCT-arg kfunc %s: %s", fnName, s)
		return true
	}

	// UNION arg is unsupported since
	// commit ??? ("bpf: Support fentry/fexit for functions with union args")
	if strings.Contains(s, "type UNION is unsupported") {
		VerboseLog("Cannot trace UNION-arg kfunc %s: %s", fnName, s)
		return true
	}

	return false
}

func (t *bpfTracing) traceFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn *KFunc, bothEntryExit, isExit, stack bool) error {
	spec = spec.Copy()

	isTracepoint := fn.IsTp
	tracingFuncName := TracingProgName()
	useKprobe := false
	if _, ok := spec.Programs["bpfsnoop_kprobe"]; ok {
		useKprobe = true

		if isExit {
			tracingFuncName = "bpfsnoop_kretprobe"
		} else {
			tracingFuncName = "bpfsnoop_kprobe"
		}
	}

	traceeName := fn.Func.Name
	progSpec := spec.Programs[tracingFuncName]
	funcProto := fn.Func.Type.(*btf.FuncProto)
	params := funcProto.Params
	fn.Pkt = t.injectPktOutput(fn.Flag.pkt, progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, fn.Btf, traceeName); err != nil {
		return err
	}
	args, argDataSize, err := t.injectArgOutput(progSpec, params, fn.Btf, false, traceeName)
	if err != nil {
		return err
	}
	fn.Args = args
	fn.Data = argDataSize

	withRet := !isTracepoint && isExit
	fnArgsBufSize, err := injectOutputFuncArgs(progSpec, fn.Prms, fn.Ret, withRet)
	if err != nil {
		return fmt.Errorf("failed to inject output func args: %w", err)
	}
	if isExit {
		fn.Exit = fnArgsBufSize
	} else {
		fn.Ent = fnArgsBufSize
	}

	if err := setBpfsnoopConfig(spec, fn.Ksym.addr, len(fn.Prms), fnArgsBufSize,
		argDataSize, fn.Flag.lbr, stack, fn.Pkt, bothEntryExit, withRet); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	attachType := ebpf.AttachTraceFEntry
	if isExit {
		attachType = ebpf.AttachTraceFExit
	}
	if isTracepoint {
		attachType = ebpf.AttachTraceRawTp
	}

	fnName := fn.Func.Name
	progSpec.AttachTo = fnName
	progSpec.AttachType = attachType

	if useKprobe {
		progSpec.AttachTo = ""
		progSpec.AttachType = ebpf.AttachNone
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if ignoreFuncTraceVerifierErr(err, fnName) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing %s: %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)

	var l link.Link
	if !useKprobe {
		l, err = link.AttachTracing(link.TracingOptions{
			Program:    prog,
			AttachType: attachType,
		})
	} else {
		// Use kprobe/kretprobe
		if isExit {
			l, err = link.Kretprobe(fnName, prog, &link.KprobeOptions{})
		} else {
			l, err = link.Kprobe(fnName, prog, &link.KprobeOptions{})
		}
	}

	if err != nil {
		_ = prog.Close()
		if ignoreFuncTraceErr(err, fnName) {
			return nil
		}
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	verboseLogIf(!isTracepoint && isExit, "Tracing(fexit) kernel function %s", fnName)
	verboseLogIf(!isTracepoint && !isExit, "Tracing(fentry) kernel function %s", fnName)
	verboseLogIf(isTracepoint, "Tracing kernel tracepoint %s", fnName)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.kfns = append(t.kfns, tracingFunc{
		l: l,
		p: prog,
	})
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceFuncs(errg *errgroup.Group, spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, kfuncs KFuncs) {
	if len(kfuncs) == 0 {
		return
	}

	if _, ok := spec.Programs["bpfsnoop_kprobe"]; !ok {
		for _, fn := range kfuncs {
			bothEntryExit := fn.Insn || fn.Flag.graph || fn.Flag.both
			fn := fn

			if fn.IsTp {
				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, false, false, fn.Flag.stack)
				})
				continue
			}

			if bothEntryExit {
				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, true, false, false)
				})

				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, true, true, fn.Flag.stack)
				})
			} else {
				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, false, hasModeExit(), fn.Flag.stack)
				})
			}
		}
	} else {
		for _, fn := range kfuncs {
			bothEntryExit := fn.Insn || fn.Flag.graph || fn.Flag.both
			fn := fn

			if fn.IsTp {
				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, false, false, fn.Flag.stack)
				})
				continue
			}

			if !hasModeExit() {
				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, false, false, fn.Flag.stack)
				})
			} else {
				fn.Flag.both = false

				if !bothEntryExit {
					// kretprobe has no entry args - automatically enable both entry and exit
					DebugLog("Function %s: kprobe exit-only mode requires entry for argument capture, enabling both entry/exit", fn.Func.Name)
				}

				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, true, false, fn.Flag.stack)
				})

				errg.Go(func() error {
					// do not enable stack tracing on kretprobe, it makes CPU stuck
					return t.traceFunc(spec, reusedMaps, fn, true, true, false)
				})
			}
		}
	}
}
