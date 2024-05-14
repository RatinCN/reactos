/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ASLR Implementation
 * COPYRIGHT:   Copyright 2024 Ratin Gao <ratin@knsoft.org>
 */

/*
 * This ASLR implementation is very basic, mainly according to "Windows Internals".
 * 7th "Windows Internals" is referenced but this implementation is more closer to NT6.0,
 * randomized image base address only, without Wow64 support and features
 * on NT6.2 (large address, force ASLR, ...), NT10 (ExGenRandom, CFG, ...)
 *
 * See also:
 * 
 *   "Windows Internals" 7th Part1
 *     -> Chapter 5 Memory management
 *       -> Virtual address space layouts
 *         -> User address space layout
 *           -> Image randomization
 *
 *   https://www.blackhat.com/presentations/bh-usa-08/Sotirov_Dowd/bh08-sotirov-dowd.pdf
 *     -> Part 1. Memory protection mechanisms in Windows
 *       -> ASLR
 *         -> Image randomization
 *         -> Executable randomization
 *         -> DLL randomization
 *
 *   https://bbs.kanxue.com/thread-208278.htm
 *   https://bbs.kanxue.com/thread-206911.htm
 */

#include <ntoskrnl.h>

#define NDEBUG
#include <debug.h>

#include "ARM3/miarm.h"

/* Make sure memory allocation granularity is always 64KB */
_STATIC_ASSERT(MM_ALLOCATION_GRANULARITY == _64K);

/*
 * Reserved address range for system is different on 32-bit and 64-bit:
 *   [0x00007FF7FFFF0000 ... 0x00007FFFFFFF0000], 32GB on 64-bit,
 *   [0x50000000 ... 0x78000000], 640MB on 32-bit.
 *
 * TODO: Both of 32 and 64 are defined to wait for the day we support Wow64...
 */

#define MI_ASLR_BITMAP_SIZE_IN_BYTES_32 0x500
#define MI_ASLR_BITMAP_SIZE_IN_BYTES_64 0x10000
#define MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS_32 0x78000000UL
#define MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS_64 0x00007FFFFFFF0000ULL

#if defined(_WIN64)
#define MI_ASLR_BITMAP_SIZE_IN_BYTES MI_ASLR_BITMAP_SIZE_IN_BYTES_64
#define MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS ((PVOID)MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS_64)
#else
#define MI_ASLR_BITMAP_SIZE_IN_BYTES MI_ASLR_BITMAP_SIZE_IN_BYTES_32
#define MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS ((PVOID)MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS_32)
#endif

/*
 * TODO: Should be read from registry.
 *   Key: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
 *   Value: MoveImages (REG_DWORD)
 *     0: Never randomize images.
 *     0xFFFFFFFF: Force randomize all relocatable image.
 *     Other (default): Randomize images that have IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag.
 */
static ULONG MmMoveImages = 1;

/*
 * ASLR reserved a region for system DLLs,
 * The top of region is MiImageBitMapHighVa,
 * and the size of region depends on the number of
 * units of allocation (64K) MiImageBitMap could track.
 * The first DLL base depends on MiImageBias, see "Windows Internals":
 *   This value corresponds to the TSC of the current CPU
 *   when this function was called during the boot cycle,
 *   shifted and masked into an 8-bit value.
 *   This provides 256 possible values on 32 bit systems;
 *   similar computations are done for 64-bit systems with more possible values
 *   as the address space is vast.
 */
static PVOID MiImageBitMapHighVa;
static RTL_BITMAP MiImageBitMap;
static ULONG MiImageBias;

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeRelocations(VOID)
{
    PVOID Buffer;

    /* Exit if ASLR is disabled */
    if (!MmMoveImages)
    {
        DPRINT1("ASLR: Disabled by configuration.\n");
        return;
    }

    /* Initialize bitmap */
    MiImageBitMapHighVa = MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS;
    Buffer = ExAllocatePoolWithTag(NonPagedPool, MI_ASLR_BITMAP_SIZE_IN_BYTES, TAG_MM);
    if (Buffer == NULL)
    {
        DPRINT1("ASLR: ExAllocatePoolWithTag fail to allocate memory for ASLR bitmap.\n");
        goto Fail;
    }
    RtlInitializeBitMap(&MiImageBitMap, Buffer, MI_ASLR_BITMAP_SIZE_IN_BYTES * CHAR_BIT);
    RtlClearAllBits(&MiImageBitMap);

    /* Initialize random bias */
    MiImageBias = (ReadTimeStampCounter() >> 4) & 0xFF;
    DPRINT1("ASLR: Initialization succeeded, MiImageBitMapHighVa = 0x%p, MiImageBias = %lu.\n",
            MiImageBitMapHighVa,
            MiImageBias);
    return;

Fail:
    MmMoveImages = 0;
    DPRINT1("ASLR: Initialization failed.\n");
}
