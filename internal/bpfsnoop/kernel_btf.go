// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/ebpf/btf"
)

const (
	kernelBTFPath = "/sys/kernel/btf"
)

func iterateKernelBtfs(allKmods bool, kmods []string, iter func(*btf.Spec) bool) error {
	if allKmods {
		files, err := os.ReadDir(kernelBTFPath)
		if err != nil {
			return fmt.Errorf("failed to read /sys/kernel/btf: %w", err)
		}

		fileNames := make([]string, 0, len(files))
		for _, file := range files {
			if file.IsDir() || file.Name() == "vmlinux" {
				continue // skip directories and vmlinux
			}
			fileNames = append(fileNames, file.Name())
		}

		slices.Sort(fileNames)
		fileNames = append([]string{"vmlinux"}, fileNames...) // search vmlinux first

		for _, file := range fileNames {
			kmodBtf, err := btf.LoadKernelModuleSpec(file)
			if err != nil {
				return fmt.Errorf("failed to load kernel module BTF: %w", err)
			}

			if iter(kmodBtf) {
				break // stop iterating if the iterator returns true
			}
		}
	} else if len(kmods) != 0 {
		kmods = sortCompact(kmods)
		if idx := slices.Index(kmods, "vmlinux"); idx != -1 {
			// ensure vmlinux is searched first
			kmods = append([]string{"vmlinux"}, slices.Delete(kmods, idx, idx+1)...)
		} else {
			// ensure vmlinux is always searched
			kmods = append([]string{"vmlinux"}, kmods...)
		}

		for _, kmod := range kmods {
			if !fileExists(filepath.Join(kernelBTFPath, kmod)) {
				continue
			}

			kmodBtf, err := btf.LoadKernelModuleSpec(kmod)
			if err != nil {
				return fmt.Errorf("failed to load kernel module BTF: %w", err)
			}

			if iter(kmodBtf) {
				break // stop iterating if the iterator returns true
			}
		}
	} else {
		kernelBtf := getKernelBTF()
		iter(kernelBtf)
	}

	kmodBtfs, err := LoadKmodBtfs(kfuncKmods, kmodBTFDir)
	if err != nil {
		return err
	}
	for _, kmodBtf := range kmodBtfs {
		if iter(kmodBtf) {
			break // stop iterating if the iterator returns true
		}
	}

	return nil
}

func LoadKmodBtfs(kmods []string, kmodBTFDir string) (map[string]*btf.Spec, error) {
	if kmodBTFDir == "" {
		return nil, nil
	}

	btfs := map[string]*btf.Spec{}
	if len(kmods) != 0 {
		kmods = sortCompact(kmods)
		if idx := slices.Index(kmods, "vmlinux"); idx != -1 {
			kmods = slices.Delete(kmods, idx, idx+1)
		}

		btfs = make(map[string]*btf.Spec, len(kmods))
		for _, kmod := range kmods {
			btfPath := filepath.Join(kmodBTFDir, kmod+".btf")
			if !fileExists(btfPath) {
				return nil, fmt.Errorf("split BTF file %s does not exist", btfPath)
			}

			kmodBtf, err := btf.LoadSpec(btfPath)
			if err != nil {
				if errors.Is(err, btf.ErrNotFound) {
					WarnLog("BTF not found for %s", btfPath)
					continue
				}
				return nil, fmt.Errorf("failed to load %s btf: %w", btfPath, err)
			}

			btfs[kmod] = kmodBtf
		}
	} else {
		files, err := os.ReadDir(kmodBTFDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read /sys/kernel/btf: %w", err)
		}

		fileNames := make([]string, 0, len(files))
		for _, file := range files {
			if file.IsDir() || file.Name() == "vmlinux" {
				continue // skip directories and vmlinux
			}
			if !strings.HasSuffix(file.Name(), ".btf") {
				continue
			}
			fileNames = append(fileNames, file.Name())
		}

		btfs = make(map[string]*btf.Spec, len(fileNames))
		for _, fileName := range fileNames {
			btfPath := filepath.Join(kmodBTFDir, fileName)

			kmodBtf, err := btf.LoadSpec(btfPath)
			if err != nil {
				if errors.Is(err, btf.ErrNotFound) {
					WarnLog("BTF not found for %s", btfPath)
					continue
				}
				return nil, fmt.Errorf("failed to load %s BTF: %w", btfPath, err)
			}

			btfs[strings.TrimSuffix(fileName, ".btf")] = kmodBtf
		}
	}

	return btfs, nil
}
