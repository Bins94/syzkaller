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
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

type CoverFilter struct {
	pcsStart    uint32
	pcsSize     uint32
	pcsEnd      uint32
	weightedPCs map[uint32]float32

	bitmapFilename string
	target         *targets.Target
}

func createCoverageFilter(cfg *mgrconfig.Config, target *targets.Target) (covFilterFilename string, err error) {
	covFilterConfig := make(map[string][]string)
	if err := json.Unmarshal(cfg.CovFilter, &covFilterConfig); err != nil {
		log.Logf(0, "no coverage filter is enabled")
		return "", nil
	}
	files := covFilterConfig["files"]
	funcs := covFilterConfig["functions"]
	rawPCs := covFilterConfig["pcs"]
	if len(files) == 0 && len(funcs) == 0 && len(rawPCs) == 0 {
		return "", nil
	}
	log.Logf(0, "initialize coverage information...")
	if err = initCover(target, cfg.KernelObj, cfg.KernelSrc, cfg.KernelBuildSrc); err != nil {
		return "", fmt.Errorf("failed to generate coverage profile: %v", err)
	}

	covFilter := CoverFilter{
		weightedPCs:    make(map[uint32]float32),
		target:         target,
		bitmapFilename: cfg.Workdir + "/" + "syz-cover-bitmap",
	}
	err = covFilter.initWeightedPCs(files, funcs, rawPCs)
	if err != nil {
		return "", fmt.Errorf("failed to init coverage filter weightedPCs")
	}
	err = covFilter.createBitmap()
	if err != nil {
		return "", fmt.Errorf("failed to create coverage bitmap")
	}
	return covFilter.bitmapFilename, nil
}

func (covFilter *CoverFilter) initWeightedPCs(files, functions, rawPCsFiles []string) error {
	covFilter.weightedPCs = make(map[uint32]float32)
	filesRegexp := getFileRegexp(files)
	funcsRegexp := getFuncRegexp(functions)

	enabledFiles := make(map[string]bool)
	enabledFuncs := make(map[string]bool)
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			log.Logf(0, "failed to open raw PCs file: %v", err)
			return err
		}
		for {
			var encode uint64
			_, err := fmt.Fscanf(rawFile, "0x%x\n", &encode)
			if err != nil {
				break
			}
			pc := uint32(encode & 0xffffffff)
			weight := float32((encode >> 32) & 0xffff)
			covFilter.weightedPCs[pc] = weight
		}
		rawFile.Close()
	}
	pcs := reportGenerator.PCs()
	for _, e := range pcs {
		frame := e[len(e)-1]
		fullpc := cover.NextInstructionPC(covFilter.target, frame.PC)
		pc := uint32(fullpc & 0xffffffff)
		for _, r := range funcsRegexp {
			if ok := r.MatchString(frame.Func); ok {
				enabledFuncs[frame.Func] = true
				covFilter.weightedPCs[pc] = 1.0
			}
		}
		for _, r := range filesRegexp {
			if ok := r.MatchString(frame.File); ok {
				enabledFiles[frame.File] = true
				enabledFuncs[frame.Func] = true
				covFilter.weightedPCs[pc] = 1.0
			}
		}
		if _, ok := covFilter.weightedPCs[pc]; ok {
			enabledFuncs[frame.Func] = true
		}
	}
	for f := range enabledFuncs {
		log.Logf(1, "enabled func: %s", f)
	}
	for f := range enabledFiles {
		log.Logf(1, "enabled file: %s", f)
	}
	return nil
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

func (covFilter *CoverFilter) createBitmap() error {
	covFilter.detectRegion()
	if covFilter.pcsSize > 0 {
		log.Logf(0, "coverage filter from %x to %x, size %x",
			covFilter.pcsStart, covFilter.pcsEnd, covFilter.pcsSize)
	} else {
		return fmt.Errorf("coverage filter is enabled but nothing will be filtered")
	}

	bitmapFile, err := os.OpenFile(covFilter.bitmapFilename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open or create bitmap: %s", err)
	}
	defer bitmapFile.Close()
	bitmap := covFilter.bitmapBytes()
	_, err = bitmapFile.Write(bitmap)
	if err != nil {
		return fmt.Errorf("failed to write bitmap: %s", err)
	}
	return nil
}

func (covFilter *CoverFilter) detectRegion() {
	covFilter.pcsStart = 0xffffffff
	covFilter.pcsEnd = 0x0
	for pc := range covFilter.weightedPCs {
		if pc < covFilter.pcsStart {
			covFilter.pcsStart = pc
		}
		if pc > covFilter.pcsEnd {
			covFilter.pcsEnd = pc
		}
	}
	// align
	covFilter.pcsStart &= 0xfffffff0
	covFilter.pcsEnd |= 0xf
	covFilter.pcsEnd++
	covFilter.pcsSize = 0
	if covFilter.pcsStart < covFilter.pcsEnd {
		covFilter.pcsSize = covFilter.pcsEnd - covFilter.pcsStart
	} else {
		covFilter.pcsSize = 0
	}
}

func (covFilter *CoverFilter) bitmapBytes() []byte {
	// The file starts with two uint32: covFilterStart and covFilterSize,
	// and a bitmap with size (covFilterSize>>4)/8 + 1 bytes follow them.
	start := make([]byte, 4)
	covFilter.putUint32(start, covFilter.pcsStart)
	size := make([]byte, 4)
	covFilter.putUint32(size, covFilter.pcsSize)

	// The lowest 4-bit is dropped,
	// 8-bit = 1-byte, additional 1-byte to prevent overflow
	bitmapSize := (covFilter.pcsSize>>4)/8 + 1
	bitmap := make([]byte, bitmapSize)
	for pc := range covFilter.weightedPCs {
		pc -= covFilter.pcsStart
		pc = pc >> 4
		idx := pc / 8
		shift := pc % 8
		bitmap[idx] |= (1 << shift)
	}
	start = append(start, size...)
	bitmap = append(start, bitmap...)
	return bitmap
}

func (covFilter *CoverFilter) putUint32(bytes []byte, value uint32) {
	if covFilter.target.LittleEndian {
		binary.LittleEndian.PutUint32(bytes, value)
	} else {
		binary.BigEndian.PutUint32(bytes, value)
	}
}

func (mgr *Manager) getWeightedPCs() bool {
	if mgr.coverFilterFilename != "" {
		return true
	} else {
		return false
	}
}
