/* Version definitions */
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_VISTA
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_VISTA

#include <ntifs.h>
#include <ndk/ntndk.h>

#define C_ASSERT_FIELD(Type, Offset, MemberType, MemberName) \
    C_ASSERT(FIELD_OFFSET(Type, MemberName) == Offset); \
    C_ASSERT(FIELD_SIZE(Type, MemberName) == sizeof(MemberType));

/* KTHREAD */
C_ASSERT_FIELD(KTHREAD, 0x000, DISPATCHER_HEADER, Header)
C_ASSERT_FIELD(KTHREAD, 0x010, ULONG64, CycleTime)
C_ASSERT_FIELD(KTHREAD, 0x018, ULONG, HighCycleTime)
C_ASSERT_FIELD(KTHREAD, 0x020, ULONG64, QuantumTarget)
C_ASSERT_FIELD(KTHREAD, 0x028, PVOID, InitialStack)
C_ASSERT_FIELD(KTHREAD, 0x02C, PVOID, StackLimit)
C_ASSERT_FIELD(KTHREAD, 0x030, PVOID, KernelStack)
C_ASSERT_FIELD(KTHREAD, 0x034, ULONG, ThreadLock)
C_ASSERT_FIELD(KTHREAD, 0x038, KAPC_STATE, ApcState)
C_ASSERT_FIELD(KTHREAD, 0x038, UCHAR[23], ApcStateFill)
C_ASSERT_FIELD(KTHREAD, 0x04F, CHAR, Priority)
C_ASSERT_FIELD(KTHREAD, 0x050, USHORT, NextProcessor)
C_ASSERT_FIELD(KTHREAD, 0x052, USHORT, DeferredProcessor)
C_ASSERT_FIELD(KTHREAD, 0x054, ULONG, ApcQueueLock)
C_ASSERT_FIELD(KTHREAD, 0x058, ULONG, ContextSwitches)
C_ASSERT_FIELD(KTHREAD, 0x05C, UCHAR, State)
C_ASSERT_FIELD(KTHREAD, 0x05D, UCHAR, NpxState)
C_ASSERT_FIELD(KTHREAD, 0x05E, UCHAR, WaitIrql)
C_ASSERT_FIELD(KTHREAD, 0x05F, CHAR, WaitMode)
C_ASSERT_FIELD(KTHREAD, 0x060, LONG, WaitStatus)
C_ASSERT_FIELD(KTHREAD, 0x064, PKWAIT_BLOCK, WaitBlockList)
C_ASSERT_FIELD(KTHREAD, 0x064, PKGATE, GateObject)
C_ASSERT_FIELD(KTHREAD, 0x068, LONG, MiscFlags)
C_ASSERT_FIELD(KTHREAD, 0x06C, UCHAR, WaitReason)
C_ASSERT_FIELD(KTHREAD, 0x06D, UCHAR, SwapBusy)
C_ASSERT_FIELD(KTHREAD, 0x06E, UCHAR[2], Alerted)
C_ASSERT_FIELD(KTHREAD, 0x070, LIST_ENTRY, WaitListEntry)
C_ASSERT_FIELD(KTHREAD, 0x070, SINGLE_LIST_ENTRY, SwapListEntry)
C_ASSERT_FIELD(KTHREAD, 0x078, PKQUEUE, Queue)
C_ASSERT_FIELD(KTHREAD, 0x07C, ULONG, WaitTime)
C_ASSERT_FIELD(KTHREAD, 0x080, SHORT, KernelApcDisable)
C_ASSERT_FIELD(KTHREAD, 0x082, SHORT, SpecialApcDisable)
C_ASSERT_FIELD(KTHREAD, 0x080, ULONG, CombinedApcDisable)
C_ASSERT_FIELD(KTHREAD, 0x084, PVOID, Teb)
C_ASSERT_FIELD(KTHREAD, 0x088, KTIMER, Timer)
C_ASSERT_FIELD(KTHREAD, 0x088, UCHAR[40], TimerFill)
C_ASSERT_FIELD(KTHREAD, 0x0B0, LONG, ThreadFlags)
C_ASSERT_FIELD(KTHREAD, 0x0B8, KWAIT_BLOCK[4], WaitBlock)
C_ASSERT_FIELD(KTHREAD, 0x0B8, UCHAR[23], WaitBlockFill0)
C_ASSERT_FIELD(KTHREAD, 0x0CF, UCHAR, IdealProcessor)
C_ASSERT_FIELD(KTHREAD, 0x0B8, UCHAR[47], WaitBlockFill1)
C_ASSERT_FIELD(KTHREAD, 0x0E7, CHAR, PreviousMode)
C_ASSERT_FIELD(KTHREAD, 0x0B8, UCHAR[71], WaitBlockFill2)
C_ASSERT_FIELD(KTHREAD, 0x0FF, UCHAR, ResourceIndex)
C_ASSERT_FIELD(KTHREAD, 0x0B8, UCHAR[95], WaitBlockFill3)
C_ASSERT_FIELD(KTHREAD, 0x117, UCHAR, LargeStack)
C_ASSERT_FIELD(KTHREAD, 0x118, LIST_ENTRY, QueueListEntry)
C_ASSERT_FIELD(KTHREAD, 0x120, PKTRAP_FRAME, TrapFrame)
C_ASSERT_FIELD(KTHREAD, 0x124, PVOID, FirstArgument)
C_ASSERT_FIELD(KTHREAD, 0x128, PVOID, CallbackStack)
C_ASSERT_FIELD(KTHREAD, 0x128, ULONG, CallbackDepth)
C_ASSERT_FIELD(KTHREAD, 0x12C, PVOID, ServiceTable)
C_ASSERT_FIELD(KTHREAD, 0x130, UCHAR, ApcStateIndex)
C_ASSERT_FIELD(KTHREAD, 0x131, CHAR, BasePriority)
C_ASSERT_FIELD(KTHREAD, 0x132, CHAR, PriorityDecrement)
C_ASSERT_FIELD(KTHREAD, 0x133, UCHAR, Preempted)
C_ASSERT_FIELD(KTHREAD, 0x134, UCHAR, AdjustReason)
C_ASSERT_FIELD(KTHREAD, 0x135, CHAR, AdjustIncrement)
C_ASSERT_FIELD(KTHREAD, 0x136, UCHAR, Spare01)
C_ASSERT_FIELD(KTHREAD, 0x137, CHAR, Saturation)
C_ASSERT_FIELD(KTHREAD, 0x138, ULONG, SystemCallNumber)
C_ASSERT_FIELD(KTHREAD, 0x13C, ULONG, Spare02)
C_ASSERT_FIELD(KTHREAD, 0x140, ULONG, UserAffinity)
C_ASSERT_FIELD(KTHREAD, 0x144, PKPROCESS, Process)
C_ASSERT_FIELD(KTHREAD, 0x148, ULONG, Affinity)
C_ASSERT_FIELD(KTHREAD, 0x14C, PKAPC_STATE[2], ApcStatePointer)
C_ASSERT_FIELD(KTHREAD, 0x154, KAPC_STATE, SavedApcState)
C_ASSERT_FIELD(KTHREAD, 0x154, UCHAR[23], SavedApcStateFill)
C_ASSERT_FIELD(KTHREAD, 0x16B, CHAR, FreezeCount)
C_ASSERT_FIELD(KTHREAD, 0x16C, CHAR, SuspendCount)
C_ASSERT_FIELD(KTHREAD, 0x16D, UCHAR, UserIdealProcessor)
C_ASSERT_FIELD(KTHREAD, 0x16E, UCHAR, Spare03)
C_ASSERT_FIELD(KTHREAD, 0x16F, UCHAR, OtherPlatformFill)
C_ASSERT_FIELD(KTHREAD, 0x170, PVOID, Win32Thread)
C_ASSERT_FIELD(KTHREAD, 0x174, PVOID, StackBase)
C_ASSERT_FIELD(KTHREAD, 0x178, KAPC, SuspendApc)
C_ASSERT_FIELD(KTHREAD, 0x178, UCHAR, SuspendApcFill0)
C_ASSERT_FIELD(KTHREAD, 0x179, CHAR, Spare04)
C_ASSERT_FIELD(KTHREAD, 0x178, UCHAR[3], SuspendApcFill1)
C_ASSERT_FIELD(KTHREAD, 0x17B, UCHAR, QuantumReset)
C_ASSERT_FIELD(KTHREAD, 0x178, UCHAR[4], SuspendApcFill2)
C_ASSERT_FIELD(KTHREAD, 0x17C, ULONG, KernelTime)
C_ASSERT_FIELD(KTHREAD, 0x178, UCHAR[36], SuspendApcFill3)
C_ASSERT_FIELD(KTHREAD, 0x19C, PKPRCB, WaitPrcb)
C_ASSERT_FIELD(KTHREAD, 0x178, UCHAR[40], SuspendApcFill4)
C_ASSERT_FIELD(KTHREAD, 0x1A0, PVOID, LegoData)
C_ASSERT_FIELD(KTHREAD, 0x178, UCHAR[47], SuspendApcFill5)
C_ASSERT_FIELD(KTHREAD, 0x1A7, UCHAR, PowerState)
C_ASSERT_FIELD(KTHREAD, 0x1A8, ULONG, UserTime)
C_ASSERT_FIELD(KTHREAD, 0x1AC, KSEMAPHORE, SuspendSemaphore)
C_ASSERT_FIELD(KTHREAD, 0x1AC, UCHAR[20], SuspendSemaphorefill)
C_ASSERT_FIELD(KTHREAD, 0x1C0, ULONG, SListFaultCount)
C_ASSERT_FIELD(KTHREAD, 0x1C4, LIST_ENTRY, ThreadListEntry)
C_ASSERT_FIELD(KTHREAD, 0x1CC, LIST_ENTRY, MutantListHead)
C_ASSERT_FIELD(KTHREAD, 0x1D4, PVOID, SListFaultAddress)
C_ASSERT_FIELD(KTHREAD, 0x1D8, PVOID, MdlForLockedTeb)

/* KUSER_SHARED_DATA */
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x000, ULONG, TickCountLowDeprecated)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x004, ULONG, TickCountMultiplier)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x008, KSYSTEM_TIME, InterruptTime)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x014, KSYSTEM_TIME, SystemTime)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x020, KSYSTEM_TIME, TimeZoneBias)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x02C, USHORT, ImageNumberLow)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x02E, USHORT, ImageNumberHigh)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x030, WCHAR[260], NtSystemRoot)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x238, ULONG, MaxStackTraceDepth)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x23C, ULONG, CryptoExponent)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x240, ULONG, TimeZoneId)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x244, ULONG, LargePageMinimum)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x248, ULONG[7], Reserved2)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x264, NT_PRODUCT_TYPE, NtProductType)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x268, BOOLEAN, ProductTypeIsValid)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x26C, ULONG, NtMajorVersion)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x270, ULONG, NtMinorVersion)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x274, BOOLEAN[64], ProcessorFeatures)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2B4, ULONG, Reserved1)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2B8, ULONG, Reserved3)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2BC, ULONG, TimeSlip)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2C0, ALTERNATIVE_ARCHITECTURE_TYPE, AlternativeArchitecture)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2C8, LARGE_INTEGER, SystemExpirationDate)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2D0, ULONG, SuiteMask)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2D4, BOOLEAN, KdDebuggerEnabled)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2D5, UCHAR, MitigationPolicies) // NXSupportPolicy
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2D8, ULONG, ActiveConsoleId)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2DC, ULONG, DismountCount)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2E0, ULONG, ComPlusPackage)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2E4, ULONG, LastSystemRITEventTickCount)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2E8, ULONG, NumberOfPhysicalPages)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2EC, BOOLEAN, SafeBootMode)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2F0, ULONG, SharedDataFlags)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x2F8, ULONGLONG, TestRetInstruction)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x300, ULONG, SystemCall)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x304, ULONG, SystemCallReturn)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x320, KSYSTEM_TIME, TickCount)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x320, ULONGLONG, TickCountQuad)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x330, ULONG, Cookie)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x338, ULONGLONG, ConsoleSessionForegroundProcessId)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x340, ULONG[16], Wow64SharedInformation)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x380, USHORT[8], UserModeGlobalLogger)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x390, ULONG[2], HeapTracingPid)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x398, ULONG[2], CritSecTracingPid)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x3A0, ULONG, ImageFileExecutionOptions)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x3A4, ULONG, LangGenerationCount)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x3A8, ULONGLONG, AffinityPad)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x3A8, KAFFINITY, ActiveProcessorAffinity)
C_ASSERT_FIELD(KUSER_SHARED_DATA, 0x3B0, ULONGLONG, InterruptTimeBias)
