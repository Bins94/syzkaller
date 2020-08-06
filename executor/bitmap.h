// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <stdio.h>

#if GOOS_linux || GOOS_freebsd || GOOS_netbsd || GOOS_openbsd || GOOS_akaros
#include <sys/mman.h>
#endif

static byte* bitmap;
static uint32 pcstart;
static uint32 pcsize;
static uint32 pcend;

inline void init_bitmap()
{
#if SYZ_EXECUTOR_USES_SHMEM
	int f = open("/syz-cover-bitmap", O_RDONLY);
	if (f < 0) {
		debug("bitmap is no found, coverage filter disabled\n");
		return;
	}
	// If bitmap is existed, but invalid, executor should exit with error.
	ssize_t ret = read(f, &pcstart, sizeof(uint32));
	if (ret < 0)
		fail("failed to read bitmap start");
	ret = read(f, &pcsize, sizeof(uint32));
	if (ret < 0 || pcsize < 0)
		fail("failed to read bitmap size or bad bitmap size");
	pcend = pcstart + pcsize;
	debug("coverage filter from %x to %x, size %x\n", pcstart, pcend, pcsize);

	uint32 bitmapSize = (pcsize >> 4) / 8 + 1;
	// A random address for bitmap. Don't corrupt output_data.
	void* preferred = (void*)0x110f230000ull;
	bitmap = (byte*)mmap(preferred, bitmapSize + 2 * sizeof(uint32), PROT_READ, MAP_PRIVATE, f, 0);
	if (bitmap != preferred)
		fail("failed to initialize bitmap at %p", preferred);
	bitmap += sizeof(uint32) * 2;
#endif
}

inline bool coverage_filter(uint64 pc)
{
	if (bitmap == NULL)
		fail("filter was enabled but bitmap initialization failed");
	// Prevent overflow while searching bitmap.
	uint32 pc32 = (uint32)(pc & 0xffffffff);
	if (pc32 < pcstart || pc32 > pcend)
		return false;
	// For minimizing the size of bitmap, the lowest 4-bit will be dropped.
	pc32 -= pcstart;
	pc32 = pc32 >> 4;
	uint32 idx = pc32 / 8;
	uint32 shift = pc32 % 8;
	return (bitmap[idx] & (1 << shift)) > 0;
}
