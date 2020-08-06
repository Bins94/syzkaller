// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/log"
)

type CoverFilter struct {
	enableFilter    bool
	kcovFilterStart uint32
	kcovFilterSize  uint32
	kcovFilterEnd   uint32
	weightedPCs     map[uint32]float32

	pcsBitmapPath      string
	targetLittleEndian bool
	targetArch         string
}

func (mgr *Manager) initKcovFilter() {
	covFilterConfig := make(map[string][]string)
	if err := json.Unmarshal(mgr.cfg.CovFilter, &covFilterConfig); err != nil {
		log.Logf(0, "no coverage filter is enabled")
		mgr.kcovFilter.enableFilter = false
		return
	}
	files := covFilterConfig["files"]
	funcs := covFilterConfig["functions"]
	rawPCs := covFilterConfig["pcs"]
	if len(files) == 0 && len(funcs) == 0 && len(rawPCs) == 0 {
		mgr.kcovFilter.enableFilter = false
		return
	}
	mgr.kcovFilter.enableFilter = true
	log.Logf(0, "initialize coverage information...")
	if err := initCover(mgr.sysTarget, mgr.cfg.KernelObj, mgr.cfg.KernelSrc, mgr.cfg.KernelBuildSrc); err != nil {
		log.Logf(0, "failed to generate coverage profile: %v", err)
		log.Fatalf("coverage filter cannot be initialized without coverage profile")
	}

	mgr.kcovFilter.targetLittleEndian = mgr.sysTarget.LittleEndian
	mgr.kcovFilter.targetArch = mgr.sysTarget.Arch
	mgr.kcovFilter.pcsBitmapPath = mgr.cfg.Workdir + "/" + "syz-cover-bitmap"
	mgr.kcovFilter.initWeightedPCs(files, funcs, rawPCs)
}

func (mgr *Manager) getWeightedPCs() bool {
	return mgr.kcovFilter.enableFilter
}

func (filter *CoverFilter) initWeightedPCs(files, functions, rawPCsFiles []string) {
	filter.weightedPCs = make(map[uint32]float32)
	filesRegexp := getFileRegexp(files)
	funcsRegexp := getFuncRegexp(functions)

	enabledFiles := make(map[string]bool)
	enabledFuncs := make(map[string]bool)
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			log.Logf(0, "failed to open raw PCs file: %v", err)
		}
		for {
			var encode uint64
			_, err := fmt.Fscanf(rawFile, "0x%x\n", &encode)
			if err != nil {
				break
			}
			pc := uint32(encode & 0xffffffff)
			weight := float32((encode >> 32) & 0xffff)
			filter.weightedPCs[pc] = weight
		}
		rawFile.Close()
	}
	pcs := reportGenerator.PCs()
	for _, e := range pcs {
		frame := e[len(e)-1]
		fullpc := cover.NextInstructionPC(filter.targetArch, frame.PC)
		pc := uint32(fullpc & 0xffffffff)
		for _, r := range funcsRegexp {
			if ok := r.MatchString(frame.Func); ok {
				enabledFuncs[frame.Func] = true
				filter.weightedPCs[pc] = 1.0
			}
		}
		for _, r := range filesRegexp {
			if ok := r.MatchString(frame.File); ok {
				enabledFiles[frame.File] = true
				enabledFuncs[frame.Func] = true
				filter.weightedPCs[pc] = 1.0
			}
		}
		if _, ok := filter.weightedPCs[pc]; ok {
			enabledFuncs[frame.Func] = true
		}
	}
	for f := range enabledFuncs {
		log.Logf(1, "enabled func: %s", f)
	}
	for f := range enabledFiles {
		log.Logf(1, "enabled file: %s", f)
	}
}

func getFileRegexp(files []string) []regexp.Regexp {
	var regexps []regexp.Regexp
	// `\*{2}$` match net/dccp/**
	rMatchDoubleStart, err := regexp.Compile(`\*{2}$`)
	if err != nil {
		log.Fatalf("regular expression failed: %s", err)
	}
	// `[^\\*]\\*$` match net/sctp/*
	rMatchOneStart, err := regexp.Compile(`[^\*]\*$`)
	if err != nil {
		log.Fatalf("regular expression failed: %s", err)
	}
	for _, f := range files {
		if ok1 := rMatchDoubleStart.MatchString(f); ok1 {
			f = `^` + f[:len(f)-2]
		} else if ok2 := rMatchOneStart.MatchString(f); ok2 {
			f = `^` + f[:len(f)-1] + `[^\/]*$`
		} else {
			f = f + `$`
		}
		r, err := regexp.Compile(f)
		if err != nil {
			log.Fatalf("regular expression failed: %s", err)
		}
		regexps = append(regexps, *r)
	}
	return regexps
}

func getFuncRegexp(funcs []string) []regexp.Regexp {
	var regexps []regexp.Regexp
	// `^[^\*].*\*$` match bar*
	rMatchOneStart, err := regexp.Compile(`^[^\*].*\*$`)
	if err != nil {
		log.Fatalf("regular expression failed: %s", err)
	}
	// `^\*.*\*$` match *baz*
	rMatchDoubleStart, err := regexp.Compile(`^\*.*\*$`)
	if err != nil {
		log.Fatalf("regular expression failed: %s", err)
	}
	for _, f := range funcs {
		if ok1 := rMatchOneStart.MatchString(f); ok1 {
			f = `^` + f[:len(f)-1]
		} else if ok2 := rMatchDoubleStart.MatchString(f); ok2 {
			f = f[1 : len(f)-1]
		} else {
			f = `^` + f + `$`
		}
		r, err := regexp.Compile(f)
		if err != nil {
			log.Fatalf("regular expression failed: %s", err)
		}
		regexps = append(regexps, *r)
	}
	return regexps
}

func (filter *CoverFilter) createBitmap() {
	filter.detectRegion()
	if filter.kcovFilterSize > 0 {
		log.Logf(0, "coverage filter from %x to %x, size %x",
			filter.kcovFilterStart, filter.kcovFilterEnd, filter.kcovFilterSize)
	} else {
		log.Fatalf("coverage filter is enabled but nothing will be filtered")
	}

	bitmapFile, err := os.OpenFile(filter.pcsBitmapPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("failed to open or create bitmap: %s", err)
	}
	defer bitmapFile.Close()
	bitmap := filter.bitmapBytes()
	_, err = bitmapFile.Write(bitmap)
	if err != nil {
		log.Fatalf("failed to write bitmap: %s", err)
	}
}

func (filter *CoverFilter) detectRegion() {
	filter.kcovFilterStart = 0xffffffff
	filter.kcovFilterEnd = 0x0
	for pc := range filter.weightedPCs {
		if pc < filter.kcovFilterStart {
			filter.kcovFilterStart = pc
		}
		if pc > filter.kcovFilterEnd {
			filter.kcovFilterEnd = pc
		}
	}
	// align
	filter.kcovFilterStart &= 0xfffffff0
	filter.kcovFilterEnd |= 0xf
	filter.kcovFilterEnd++
	filter.kcovFilterSize = 0
	if filter.kcovFilterStart < filter.kcovFilterEnd {
		filter.kcovFilterSize = filter.kcovFilterEnd - filter.kcovFilterStart
	} else {
		filter.kcovFilterSize = 0
	}
}

func (filter *CoverFilter) bitmapBytes() []byte {
	// The file starts with two uint32: kcovFilterStart and kcovFilterSize,
	// and a bitmap with size (kcovFilterSize>>4)/8 + 1 bytes follow them.
	start := make([]byte, 4)
	filter.putUint32(start, filter.kcovFilterStart)
	size := make([]byte, 4)
	filter.putUint32(size, filter.kcovFilterSize)

	// The lowest 4-bit is dropped,
	// 8-bit = 1-byte, additional 1-byte to prevent overflow
	bitmapSize := (filter.kcovFilterSize>>4)/8 + 1
	bitmap := make([]byte, bitmapSize)
	for pc := range filter.weightedPCs {
		pc -= filter.kcovFilterStart
		pc = pc >> 4
		idx := pc / 8
		shift := pc % 8
		bitmap[idx] |= (1 << shift)
	}
	start = append(start, size...)
	bitmap = append(start, bitmap...)
	return bitmap
}

func (filter *CoverFilter) putUint32(bytes []byte, value uint32) {
	if filter.targetLittleEndian {
		binary.LittleEndian.PutUint32(bytes, value)
	} else {
		binary.BigEndian.PutUint32(bytes, value)
	}
}
