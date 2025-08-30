// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const (
	kfuncBpfRdonlyCast = "bpf_rdonly_cast"
	kfuncFastcall      = "bpf_fastcall"
)

type compiler struct {
	regalloc RegisterAllocator
	insns    asm.Instructions

	vars []string
	btfs []btf.Type

	btfSpec  *btf.Spec
	krnlSpec *btf.Spec

	labelExit     string
	labelExitUsed bool

	reservedStack int

	memMode MemoryReadMode

	rdonlyCastTypeID   btf.TypeID
	rdonlyCastFastcall bool
}

func newCompiler(opts CompileExprOptions) (*compiler, error) {
	if opts.Expr == "" || opts.LabelExit == "" {
		return nil, fmt.Errorf("expression and label exit cannot be empty")
	}
	if opts.Spec == nil || opts.Kernel == nil {
		return nil, fmt.Errorf("btf spec cannot be empty")
	}

	c := &compiler{
		btfSpec:       opts.Spec,
		krnlSpec:      opts.Kernel,
		labelExit:     opts.LabelExit,
		reservedStack: opts.ReservedStack,
		memMode:       opts.MemoryReadMode,
	}

	c.vars = make([]string, len(opts.Params))
	c.btfs = make([]btf.Type, len(opts.Params))
	for i := range opts.Params {
		c.vars[i] = opts.Params[i].Name
		c.btfs[i] = opts.Params[i].Type
	}

	if c.reservedStack <= 0 {
		c.reservedStack = 8
	} else {
		c.reservedStack = (c.reservedStack + 7) & -8 // align to 8 bytes
	}

	typ, err := opts.Kernel.AnyTypeByName(kfuncBpfRdonlyCast)
	if err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return c, nil
		}

		return nil, fmt.Errorf("failed to find kfunc %s: %w", kfuncBpfRdonlyCast, err)
	}
	fn, ok := typ.(*btf.Func)
	if !ok {
		return nil, fmt.Errorf("%s should be a function", kfuncBpfRdonlyCast)
	}

	rdonlyCastID, err := opts.Kernel.TypeID(fn)
	if err != nil {
		return nil, fmt.Errorf("failed to get type ID for kfunc %s: %w", kfuncBpfRdonlyCast, err)
	}

	c.rdonlyCastFastcall = slices.Contains(fn.Tags, kfuncFastcall)
	c.rdonlyCastTypeID = rdonlyCastID

	return c, nil
}

func (c *compiler) findType(name string) (btf.Type, error) {
	typ, err := c.krnlSpec.AnyTypeByName(name)
	if err == nil {
		return typ, nil
	}

	return c.btfSpec.AnyTypeByName(name)
}
