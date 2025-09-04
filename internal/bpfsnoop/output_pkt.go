// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	outputPktFunc      = "output_pkt"
	outputSkbFunc      = "output_skb"
	outputPskbFunc     = "output_pskb"
	outputXdpBuffFunc  = "output_xdp_buff"
	outputXdpFrameFunc = "output_xdp_frame"
)

var pktOutput packetOutput

type packetOutput struct{}

func (p *packetOutput) injectStub(prog *ebpf.ProgramSpec, index int, stub string, clears ...string) {
	for _, clear := range clears {
		clearOutputSubprog(prog, clear)
	}

	// R1: args
	// R2: pkt data
	// R3: session ID

	var insns asm.Instructions
	insns = append(insns, genAccessArg(index, asm.R1)...)
	insns = append(insns, asm.Instructions{
		asm.Call.Label(stub), // call stub()
		asm.Return(),
	}...)

	injectInsns(prog, outputPktFunc, insns)
}

func (p *packetOutput) outputSkb(prog *ebpf.ProgramSpec, index int) {
	p.injectStub(prog, index, outputSkbFunc, outputPskbFunc, outputXdpBuffFunc, outputXdpFrameFunc)
}

func (p *packetOutput) outputPskb(prog *ebpf.ProgramSpec, index int) {
	p.injectStub(prog, index, outputPskbFunc, outputXdpBuffFunc, outputXdpFrameFunc)
}

func (p *packetOutput) outputXdpBuff(prog *ebpf.ProgramSpec, index int) {
	p.injectStub(prog, index, outputXdpBuffFunc, outputSkbFunc, outputPskbFunc, outputXdpFrameFunc)
}

func (p *packetOutput) outputXdpFrame(prog *ebpf.ProgramSpec, index int) {
	p.injectStub(prog, index, outputXdpFrameFunc, outputSkbFunc, outputPskbFunc, outputXdpBuffFunc)
}

func (p *packetOutput) clear(prog *ebpf.ProgramSpec) {
	clearOutputSubprog(prog, outputPktFunc)
	clearOutputSubprog(prog, outputSkbFunc)
	clearOutputSubprog(prog, outputPskbFunc)
	clearOutputSubprog(prog, outputXdpBuffFunc)
	clearOutputSubprog(prog, outputXdpFrameFunc)
}
