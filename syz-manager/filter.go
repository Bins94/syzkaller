// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"

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
	//covFilterConfig := make(map[string][]string)
	//if err := json.Unmarshal(cfg.CovFilter, &covFilterConfig); err != nil {
	//	log.Logf(0, "no coverage filter is enabled")
	//	return "", nil
	//}
	files := cfg.CovFilter.Files
	funcs := cfg.CovFilter.Functions
	rawPCs := cfg.CovFilter.RawPCs
	if len(files) == 0 && len(funcs) == 0 && len(rawPCs) == 0 {
		return "", nil
	}
	filesRegexp, err := getRegexps(files)
	if err != nil {
		return "", err
	}
	funcsRegexp, err := getRegexps(funcs)
	if err != nil {
		return "", err
	}
	if len(filesRegexp) > 0 || len(funcsRegexp) > 0 {
		log.Logf(0, "initialize coverage information...")
		if err = initCover(target, cfg.KernelObj, cfg.KernelSrc, cfg.KernelBuildSrc); err != nil {
			log.Logf(0, "failed to generate coverage profile: %v", err)
			return "", err
		}
	}

	covFilter := CoverFilter{
		weightedPCs:    make(map[uint32]float32),
		target:         target,
		bitmapFilename: cfg.Workdir + "/" + "syz-cover-bitmap",
	}
	err = covFilter.initWeightedPCs(filesRegexp, funcsRegexp, rawPCs)
	if err != nil {
		return "", err
	}
	err = covFilter.createBitmap()
	if err != nil {
		return "", err
	}
	return covFilter.bitmapFilename, nil
}

func (covFilter *CoverFilter) initWeightedPCs(filesRegexp, funcsRegexp []regexp.Regexp, rawPCsFiles []string) error {
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("failed to open raw PCs file: %v", err)
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

	enabledFuncs := make(map[string]bool)
	enabledFiles := make(map[string]bool)
	if len(filesRegexp) > 0 || len(funcsRegexp) > 0 {
		if reportGenerator == nil {
			return fmt.Errorf("ReportGenerator used without initialization")
		}
		pcs := make([]uint64, 0)
		symNames, cuNames, symPCs := reportGenerator.GetSymbolsInfo()
		for i, symName := range symNames {
			for _, r := range funcsRegexp {
				if ok := r.MatchString(symName); ok {
					enabledFuncs[symName] = true
					pcs = append(pcs, symPCs[i]...)
				}
			}
			for _, r := range filesRegexp {
				if ok := r.MatchString(cuNames[i]); ok {
					enabledFuncs[symName] = true
					enabledFiles[cuNames[i]] = true
					pcs = append(pcs, symPCs[i]...)
				}
			}
		}
		for _, pc := range pcs {
			covFilter.weightedPCs[uint32(pc)] = 1.0
		}
	}
	for f, _ := range enabledFuncs {
		log.Logf(0, "enabled kernel function: %s", f)
	}
	for f, _ := range enabledFiles {
		log.Logf(0, "enabled kernel file: %s", f)
	}
	return nil
}

func getRegexps(regexpStrings []string) ([]regexp.Regexp, error) {
	var regexps []regexp.Regexp
	for _, rs := range regexpStrings {
		r, err := regexp.Compile(rs)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		regexps = append(regexps, *r)
	}
	return regexps, nil
}

func (covFilter *CoverFilter) createBitmap() error {
	covFilter.detectRegion()
	if covFilter.pcsSize > 0 {
		log.Logf(0, "coverage filter from %x to %x, size %x",
			covFilter.pcsStart, covFilter.pcsEnd, covFilter.pcsSize)
	} else {
		return fmt.Errorf("coverage filter is enabled but nothing will be filtered")
	}

	bitmapFile, err := os.OpenFile(covFilter.bitmapFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
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
	// and a bitmap with size ((covFilterSize>>4) + 7)/8 bytes follow them.
	start := make([]byte, 4)
	covFilter.putUint32(start, covFilter.pcsStart)
	size := make([]byte, 4)
	covFilter.putUint32(size, covFilter.pcsSize)

	// The lowest 4-bit is dropped,
	// 8-bit = 1-byte, additional 1-byte to prevent overflow
	bitmapSize := ((covFilter.pcsSize >> 4) + 7) / 8
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

func (mgr *Manager) enableCoverFilter() bool {
	enabledCoverFilter := false
	if mgr.coverFilterFilename != "" {
		enabledCoverFilter = true
	}
	return enabledCoverFilter
}
