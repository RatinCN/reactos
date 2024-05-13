/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ASLR Implementation
 * COPYRIGHT:   Copyright 2024 Ratin Gao <ratin@knsoft.org>
 */

/*
 * This ASLR implementation is very basic, according to "Windows Internals".
 * See "Windows Internals" 7th Part1
 *   -> Chapter 5 Memory management,
 *   -> Virtual address space layouts,
 *   -> User address space layout,
 *   -> Image randomization
 *
 * 7th "Windows Internals" is referenced but this implementation is more closer to NT6.0,
 * which has nothing to do with ExGenRandom, CFG, ...
 *
 * See also:
 *   https://bbs.kanxue.com/thread-208278.htm
 */

#include <ntoskrnl.h>

#define NDEBUG
#include <debug.h>

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
 * TODO: Default is TRUE but should be read from registry,
 *   Key: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
 *   Value: MoveImages (REG_DWORD)
 */
static ULONG MmMoveImages = TRUE;

/*
 * ASLR reserved a region for system DLLs,
 * The top of region is MiImageBitMapHighVa,
 * and the size of region depends on the number of units of allocation MiImageBitMap could track.
 * The first DLL base depends on MiImageBias, see "Windows Internals":
 *   This value corresponds to the TSC of the current CPU
 *   when this function was called during the boot cycle,
 *   shifted and masked into an 8-bit value.
 *   This provides 256 possible values on 32 bit systems;
 *   similar computations are done for 64-bit systems with more possible values
 *   as the address space is vast.
 */
static ULONG MiImageBitMapHighVa;
static RTL_BITMAP MiImageBitMap;
static ULONG MiImageBias;

VOID NTAPI MiInitializeRelocations()
{
    PVOID Buffer;

    /* TODO: ASLR for 64-bit */
#if defined(_WIN64)
    DPRINT1("ASLR: Not support 64-bit yet...\n");
    goto Fail;
#endif

    /* Exit if ASLR is disabled */
    if (!MmMoveImages)
    {
        DPRINT1("ASLR: ASLR is disabled by configuration.\n");
        return;
    }

    /* Initialize bitmap for 32-bit */
    MiImageBitMapHighVa = (ULONG_PTR)MI_ASLR_HIGHEST_SYSTEM_RANGE_ADDRESS;
    Buffer = ExAllocatePoolWithTag(NonPagedPool, MI_ASLR_BITMAP_SIZE_IN_BYTES, TAG_MM);
    if (Buffer == NULL)
    {
        DPRINT1("ASLR: ExAllocatePoolWithTag fail to allocate memory for ASLR bitmap.\n");
        goto Fail;
    }
    RtlInitializeBitMap(&MiImageBitMap, Buffer, MI_ASLR_BITMAP_SIZE_IN_BYTES * CHAR_BIT);
    RtlClearAllBits(&MiImageBitMap);

    /* FIXME: What if CPU has no __rdtsc()? */
#if defined(_M_IX86) || defined(_M_X64)
    MiImageBias = (__rdtsc() >> 4) & 0xFF;
#else
    static ULONG RandSeed = 0;
    MiImageBias = (RtlRandomEx(&RandSeed) >> 4) & 0xFF;
    DPRINT1("ASLR: FIXME: __rdtsc is not supported, use RtlRandomEx instead.\n");
#endif

    DPRINT1("ASLR: Initialization succeeded, MiImageBitMapHighVa = 0x%p, MiImageBias = %lu.\n",
            (PVOID)(ULONG_PTR)MiImageBitMapHighVa,
            MiImageBias);
    return;

Fail:
    MmMoveImages = FALSE;
    DPRINT1("ASLR: ASLR initialization failed.\n");
}
