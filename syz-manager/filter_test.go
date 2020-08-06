// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"regexp"
	"testing"

	"github.com/google/syzkaller/prog"
)

func TestGetFileOrFuncRegExp(t *testing.T) {
	files := []string{"net/ipv4/tcp.c", "net/socket.c"}
	configFiles := []string{"net/**", "net/*", "net/socket.c"}
	filesRegexp := getFileRegexp(configFiles)
	if ok := testRegExp(filesRegexp[0], files, 2); !ok {
		t.Fatalf("format \"net/**\" file match failed")
	}
	if ok := testRegExp(filesRegexp[1], files, 1); !ok {
		t.Fatalf("format \"net/*\" file match failed")
	}
	if ok := testRegExp(filesRegexp[2], files, 1); !ok {
		t.Fatalf("full file name match failed")
	}

	funcs := []string{"tcp_sendmsg", "do_tcp_setsockopt"}
	configFunc := []string{"*tcp*", "tcp*", "do_tcp_setsockopt"}
	funcRegexp := getFuncRegexp(configFunc)
	if ok := testRegExp(funcRegexp[0], funcs, 2); !ok {
		t.Fatalf("format \"*tcp*\" function match failed")
	}
	if ok := testRegExp(funcRegexp[1], funcs, 1); !ok {
		t.Fatalf("format \"tcp*\" function match failed")
	}
	if ok := testRegExp(funcRegexp[2], funcs, 1); !ok {
		t.Fatalf("full function name match failed")
	}
}

func testRegExp(regExp regexp.Regexp, searchArray []string, expectedRet int) bool {
	matched := make([]string, 0)
	for _, e := range searchArray {
		if ok := regExp.MatchString(e); ok {
			matched = append(matched, e)
		}
	}
	return len(matched) == expectedRet
}

func TestCreateBitmap(t *testing.T) {
	target := getTarget(t, "test", "64")
	filter := &CoverFilter{
		enableFilter:       true,
		weightedPCs:        make(map[uint32]float32),
		targetLittleEndian: false,
		targetArch:         target.Arch,
	}
	enablePCStart := uint32(0x81000002)
	enablePCEnd := uint32(0x8120001d)
	filter.weightedPCs[enablePCStart] = 1.0
	filter.weightedPCs[enablePCEnd] = 1.0

	filter.detectRegion()
	if filter.kcovFilterStart != 0x81000000 ||
		filter.kcovFilterEnd != 0x81200020 ||
		filter.kcovFilterSize != 0x200020 {
		t.Fatalf("filte.detectReigion test failed %x %x %x",
			filter.kcovFilterStart, filter.kcovFilterEnd, filter.kcovFilterSize)
	}
	bitmap := filter.bitmapBytes()
	bitmap = bitmap[8:]
	for i, byte := range bitmap {
		if i == 0 {
			if byte != 0x1 {
				t.Fatalf("filter.bitmapByte enable PC failed")
			}
		} else if i == (0x20001 / 0x8) {
			if byte != byte&(1<<(0x20001%0x8)) {
				t.Fatalf("filter.bitmapByte enable PC failed")
			}
		} else {
			if byte != 0x0 {
				t.Fatalf("filter.bitmapByte disable PC failed")
			}
		}
	}
}

func getTarget(t *testing.T, os, arch string) *prog.Target {
	t.Parallel()
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
