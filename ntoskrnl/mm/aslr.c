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

static KSPIN_LOCK MiRelocationVaLock;

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
    KeInitializeSpinLock(&MiRelocationVaLock);
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

/*
 * FIXME: a bit hacky.
 * Very similar to MiSelectImageBase, which has PSEGMENT parameter.
 * This implementation has PMM_IMAGE_SECTION_OBJECT parameter instead.
 */
static
PVOID
NTAPI
MiRosSelectImageBase(
    _Inout_ PMM_IMAGE_SECTION_OBJECT ImageSectionObject)
{
    ULONG_PTR ImageSize;
    USHORT NumberOf64kChunks;
    BOOLEAN UseImageBitMap;
    PVOID SelectedBase;
    KIRQL OldIrql;
    ULONG BitIndex, StartBit, EndBit;
    ULONG_PTR Delta, RelocateDelta;

#if defined(_WIN64)
    // if (Segment->BasedAddress < (ULONG_PTR)_4GB)
    if (ImageSectionObject->BasedAddress < (ULONG_PTR)_4GB)
    {
        // TODO
        FIXME("FIXME: Base address < 4GB on 64-bit is not implemented!");
        return NULL;
    }
    else
    {
        // ASLRInfo->BitMap64 = TRUE;
    }
#else
    // ASLRInfo->BitMap64 = FALSE;
#endif

    // ImageSize = ROUND_TO_ALLOCATION_GRANULARITY(Segment->TotalNumberOfPtes * PAGE_SIZE);
    ImageSize = ROUND_TO_ALLOCATION_GRANULARITY(ImageSectionObject->ImageInformation.ImageFileSize);
    NumberOf64kChunks = ImageSize / MM_ALLOCATION_GRANULARITY;

    /* Image bitmap for DLL only, not for EXE */
    UseImageBitMap = TRUE;
    // if (!FlagOn(Segment->u2.ImageInformation->ImageCharacteristics, IMAGE_FILE_DLL))
    if (!FlagOn(ImageSectionObject->ImageInformation.ImageCharacteristics, IMAGE_FILE_DLL))
    {
        UseImageBitMap = FALSE;
    }

    /* And also don't use image bitmap when it's unavailable */
    BitIndex = RtlFindClearBits(&MiImageBitMap, NumberOf64kChunks, MiImageBias);
    if (BitIndex == 0xFFFFFFFF)
    {
        UseImageBitMap = FALSE;
    }
    OldIrql = KeAcquireSpinLockRaiseToSynch(&MiRelocationVaLock);
    StartBit = RtlFindClearBitsAndSet(&MiImageBitMap, NumberOf64kChunks, BitIndex);
    KeReleaseSpinLock(&MiRelocationVaLock, OldIrql);
    if (StartBit == 0xFFFFFFFF)
    {
        UseImageBitMap = FALSE;
    }

    if (UseImageBitMap)
    {
        /* Select image base in image bitmap, typically for DLL */
        EndBit = StartBit + NumberOf64kChunks;
        SelectedBase = (PCHAR)MiImageBitMapHighVa - (EndBit * MM_ALLOCATION_GRANULARITY);
        // if (SelectedBase == Segment->BasedAddress)
        if (SelectedBase == ImageSectionObject->BasedAddress)
        {
            /* Re-select if selected base is the same as image base */
            OldIrql = KeAcquireSpinLockRaiseToSynch(&MiRelocationVaLock);
            BitIndex = RtlFindClearBitsAndSet(&MiImageBitMap, NumberOf64kChunks, EndBit);
            if (BitIndex != 0xFFFFFFFF)
            {
                RtlClearBits(&MiImageBitMap, StartBit, NumberOf64kChunks);
            }
            KeReleaseSpinLock(&MiRelocationVaLock, OldIrql);

            /* Use new base if re-select successfully */
            if (BitIndex != 0xFFFFFFFF)
            {
                StartBit = BitIndex;
                EndBit = StartBit + NumberOf64kChunks;
                SelectedBase = (PCHAR)MiImageBitMapHighVa - (EndBit * MM_ALLOCATION_GRANULARITY);
            }
        }
    }
    else
    {
        /* Select image base not use image bitmap, typically for EXE */

        // RelocateDelta = (ULONG_PTR)Segment->BasedAddress - (ULONG_PTR)ASLRInfo->OriginalBase;
        RelocateDelta = 0; // FIXME
        if (RelocateDelta > (ULONG_PTR)MmHighestUserAddress ||
            ImageSize > (ULONG_PTR)MmHighestUserAddress ||
            RelocateDelta + ImageSize <= RelocateDelta ||
            RelocateDelta + ImageSize > (ULONG_PTR)MmHighestUserAddress)
        {
            return NULL;
        }

        /*
         * See "Windows Internals":
         *   For executables, the load offset is calculated by computing a delta value each time
         *   an executable is loaded. This value is a pseudo-random 8-bit number
         *   from 0x10000 to 0xFE0000, calculated by taking he current processor’s
         *   time stamp counter (TSC), shifting it by four places, and then performing a division
         *   modulo 254 and adding 1. This number is then multiplied by the allocation granularity
         *   of 64 KB discussed earlier.
         */
        Delta = (ULONG_PTR)((ReadTimeStampCounter() >> 4) % 254 + 1) * MM_ALLOCATION_GRANULARITY;
        // if (Add2Ptr(ASLRInfo->OriginalBase, Delta) == NULL)
        if (Add2Ptr(ImageSectionObject->BasedAddress, Delta) == NULL)
        {
            SelectedBase = ImageSectionObject->BasedAddress;
        }
        else if (RelocateDelta > Delta)
        {
            SelectedBase = (PVOID)(RelocateDelta - Delta);
        }
        else
        {
            SelectedBase = (PVOID)(RelocateDelta + Delta);
            if (SelectedBase < (PVOID)RelocateDelta ||
                Add2Ptr(SelectedBase, ImageSize) > MmHighestUserAddress ||
                // Add2Ptr(SelectedBase, ImageSize) < Add2Ptr(Segment->BasedAddress, ImageSize))
                Add2Ptr(SelectedBase, ImageSize) < Add2Ptr(ImageSectionObject->BasedAddress, ImageSize))
            {
                return NULL;
            }
        }
        StartBit = 0xFFFFFFFF;
    }
    // ASLRInfo->ImageRelocationStartBit = StartBit;
    // ASLRInfo->ImageRelocationSizeIn64k = NumberOf64kChunks;
    return SelectedBase;
}

/*
 * FIXME: Totally hacky.
 */
PVOID
NTAPI
MiRosRelocateImage(
    _Inout_ PMM_IMAGE_SECTION_OBJECT ImageSectionObject)
{
    /* Shall we ASLR this image? */
    if (ImageSectionObject->ImageInformation.ImageCharacteristics & IMAGE_FILE_DLL)
    {
        /* Don't ASLR kernel mode modules, that's KASLR */
        if (ImageSectionObject->ImageInformation.SubSystemType != IMAGE_SUBSYSTEM_WINDOWS_GUI &&
            ImageSectionObject->ImageInformation.SubSystemType != IMAGE_SUBSYSTEM_WINDOWS_CUI)
        {
            return NULL;
        }

        /* Hack: Don't ASLR DLLs intend to have a fixed base address (for ntdll, kernel32, user32. WIP) */
        if (ImageSectionObject->BasedAddress != (PVOID)MI_DEFAULT_BASE_DLL)
        {
            return NULL;
        }

        /* FIXME: WIP: How do we recognize system DLLs to ASLR? For Known-DLLs loaded by smss.exe only? */
    }
    else
    {
        /* Don't ASLR EXE, WIP */
        return NULL;
    }

    ImageSectionObject->AslrBaseAddress = MiRosSelectImageBase(ImageSectionObject);
    DPRINT1("ASLR: New section created for %wZ, PE base: 0x%p, ASLR base: 0x%p\n",
            &ImageSectionObject->FileObject->FileName,
            ImageSectionObject->BasedAddress,
            ImageSectionObject->AslrBaseAddress);
    return ImageSectionObject->AslrBaseAddress;
}
