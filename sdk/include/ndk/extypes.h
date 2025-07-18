/*++ NDK Version: 0098

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    extypes.h

Abstract:

    Type definitions for the Executive.

Author:

    Alex Ionescu (alexi@tinykrnl.org) - Updated - 27-Feb-2006

--*/

#ifndef _EXTYPES_H
#define _EXTYPES_H

//
// Dependencies
//
#include <umtypes.h>
#include <cfg.h>
#if !defined(NTOS_MODE_USER)
#include <ntimage.h>
#endif
#include <cmtypes.h>
#include <ketypes.h>
#include <potypes.h>
#include <lpctypes.h>
#ifdef NTOS_MODE_USER
#include <obtypes.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// GCC compatibility
//
#if defined(__GNUC__)
#define __ALIGNED(n)    __attribute__((aligned (n)))
#elif defined(_MSC_VER)
#define __ALIGNED(n)    __declspec(align(n))
#else
#error __ALIGNED not defined for your compiler!
#endif

//
// Rtl Atom
//
typedef USHORT RTL_ATOM, *PRTL_ATOM;

#ifndef NTOS_MODE_USER

//
// Kernel Exported Object Types
//
extern POBJECT_TYPE NTSYSAPI ExDesktopObjectType;
extern POBJECT_TYPE NTSYSAPI ExWindowStationObjectType;
extern POBJECT_TYPE NTSYSAPI ExIoCompletionType;
extern POBJECT_TYPE NTSYSAPI ExMutantObjectType;
extern POBJECT_TYPE NTSYSAPI ExTimerType;

//
// Exported NT Build Number
//
extern ULONG NTSYSAPI NtBuildNumber;

//
// Invalid Handle Value Constant
//
#define INVALID_HANDLE_VALUE                (HANDLE)-1

#endif

//
// Increments
//
#define MUTANT_INCREMENT                    1

//
// Callback Object Access Mask
//
#define CALLBACK_MODIFY_STATE               0x0001
#define CALLBACK_ALL_ACCESS                 (STANDARD_RIGHTS_REQUIRED | \
                                             SYNCHRONIZE | \
                                             CALLBACK_MODIFY_STATE)

//
// Event Object Access Masks
//
#ifdef NTOS_MODE_USER
#define EVENT_QUERY_STATE                   0x0001

//
// Semaphore Object Access Masks
//
#define SEMAPHORE_QUERY_STATE               0x0001
#else

//
// Mutant Object Access Masks
//
#define MUTANT_QUERY_STATE                  0x0001
#define MUTANT_ALL_ACCESS                   (STANDARD_RIGHTS_REQUIRED | \
                                             SYNCHRONIZE | \
                                             MUTANT_QUERY_STATE)

#define TIMER_QUERY_STATE                   0x0001
#define TIMER_MODIFY_STATE                  0x0002
#define TIMER_ALL_ACCESS                    (STANDARD_RIGHTS_REQUIRED | \
                                             SYNCHRONIZE | \
                                             TIMER_QUERY_STATE | \
                                             TIMER_MODIFY_STATE)
#endif

//
// Event Pair Access Masks
//
#define EVENT_PAIR_ALL_ACCESS               0x1F0000L

//
// Profile Object Access Masks
//
#define PROFILE_CONTROL                     0x0001
#define PROFILE_ALL_ACCESS                  (STANDARD_RIGHTS_REQUIRED | PROFILE_CONTROL)

//
// Keyed Event Object Access Masks
//
#define KEYEDEVENT_WAIT                     0x0001
#define KEYEDEVENT_WAKE                     0x0002
#define KEYEDEVENT_ALL_ACCESS               (STANDARD_RIGHTS_REQUIRED | \
                                             KEYEDEVENT_WAIT | \
                                             KEYEDEVENT_WAKE)

//
// NtRaiseHardError-related parameters
//
#define MAXIMUM_HARDERROR_PARAMETERS        5
#define HARDERROR_OVERRIDE_ERRORMODE        0x10000000

//
// Pushlock bits
//
#define EX_PUSH_LOCK_LOCK_V                 ((ULONG_PTR)0x0)
#define EX_PUSH_LOCK_LOCK                   ((ULONG_PTR)0x1)
#define EX_PUSH_LOCK_WAITING                ((ULONG_PTR)0x2)
#define EX_PUSH_LOCK_WAKING                 ((ULONG_PTR)0x4)
#define EX_PUSH_LOCK_MULTIPLE_SHARED        ((ULONG_PTR)0x8)
#define EX_PUSH_LOCK_SHARE_INC              ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS               ((ULONG_PTR)0xf)

//
// Pushlock Wait Block Flags
//
#define EX_PUSH_LOCK_FLAGS_EXCLUSIVE        1
#define EX_PUSH_LOCK_FLAGS_WAIT_V           1
#define EX_PUSH_LOCK_FLAGS_WAIT             2

//
// Resource (ERESOURCE) Flags
//
#define ResourceHasDisabledPriorityBoost    0x08

//
// Shutdown types for NtShutdownSystem
//
typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

//
// Responses for NtRaiseHardError
//
typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes,
    ResponseTryAgain,
    ResponseContinue
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

//
// System Information Classes for NtQuerySystemInformation
//
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation                                = 0, // 0x0
    SystemProcessorInformation                            = 1, // 0x1
    SystemPerformanceInformation                          = 2, // 0x2
    SystemTimeOfDayInformation                            = 3, // 0x3
    SystemPathInformation                                 = 4, // 0x4 - Obsolete: Use KUSER_SHARED_DATA
    SystemProcessInformation                              = 5, // 0x5
    SystemCallCountInformation                            = 6, // 0x6
    SystemDeviceInformation                               = 7, // 0x7
    SystemProcessorPerformanceInformation                 = 8, // 0x8
    SystemFlagsInformation                                = 9, // 0x9
    SystemCallTimeInformation                             = 10, // 0xA
    SystemModuleInformation                               = 11, // 0xB
    SystemLocksInformation                                = 12, // 0xC
    SystemStackTraceInformation                           = 13, // 0xD
    SystemPagedPoolInformation                            = 14, // 0xE
    SystemNonPagedPoolInformation                         = 15, // 0xF
    SystemHandleInformation                               = 16, // 0x10
    SystemObjectInformation                               = 17, // 0x11
    SystemPageFileInformation                             = 18, // 0x12
    SystemVdmInstemulInformation                          = 19, // 0x13
    SystemVdmBopInformation                               = 20, // 0x14
    SystemFileCacheInformation                            = 21, // 0x15
    SystemPoolTagInformation                              = 22, // 0x16
    SystemInterruptInformation                            = 23, // 0x17
    SystemDpcBehaviorInformation                          = 24, // 0x18
    SystemFullMemoryInformation                           = 25, // 0x19
    SystemLoadGdiDriverInformation                        = 26, // 0x1A
    SystemUnloadGdiDriverInformation                      = 27, // 0x1B
    SystemTimeAdjustmentInformation                       = 28, // 0x1C
    SystemSummaryMemoryInformation                        = 29, // 0x1D
    SystemMirrorMemoryInformation                         = 30, // 0x1E
    SystemPerformanceTraceInformation                     = 31, // 0x1F
    SystemObsolete0                                       = 32, // 0x20
    SystemExceptionInformation                            = 33, // 0x21
    SystemCrashDumpStateInformation                       = 34, // 0x22
    SystemKernelDebuggerInformation                       = 35, // 0x23
    SystemContextSwitchInformation                        = 36, // 0x24
    SystemRegistryQuotaInformation                        = 37, // 0x25
    SystemExtendServiceTableInformation                   = 38, // 0x26
    SystemPrioritySeperation                              = 39, // 0x27
    SystemVerifierAddDriverInformation                    = 40, // 0x28
    SystemVerifierRemoveDriverInformation                 = 41, // 0x29
    SystemProcessorIdleInformation                        = 42, // 0x2A
    SystemLegacyDriverInformation                         = 43, // 0x2B
    SystemCurrentTimeZoneInformation                      = 44, // 0x2C
    SystemLookasideInformation                            = 45, // 0x2D
    SystemTimeSlipNotification                            = 46, // 0x2E
    SystemSessionCreate                                   = 47, // 0x2F
    SystemSessionDetach                                   = 48, // 0x30
    SystemSessionInformation                              = 49, // 0x31
    SystemRangeStartInformation                           = 50, // 0x32
    SystemVerifierInformation                             = 51, // 0x33
    SystemVerifierThunkExtend                             = 52, // 0x34 - Win 11: SystemVerifierReserved
    SystemSessionProcessInformation                       = 53, // 0x35
    SystemLoadGdiDriverInSystemSpace                      = 54, // 0x36
    SystemNumaProcessorMap                                = 55, // 0x37
    SystemPrefetcherInformation                           = 56, // 0x38
    SystemExtendedProcessInformation                      = 57, // 0x39
    SystemRecommendedSharedDataAlignment                  = 58, // 0x3A
    SystemComPlusPackage                                  = 59, // 0x3B
    SystemNumaAvailableMemory                             = 60, // 0x3C
    SystemProcessorPowerInformation                       = 61, // 0x3D
    SystemEmulationBasicInformation                       = 62, // 0x3E
    SystemEmulationProcessorInformation                   = 63, // 0x3F
    SystemExtendedHandleInformation                       = 64, // 0x40
    SystemLostDelayedWriteInformation                     = 65, // 0x41
    SystemBigPoolInformation                              = 66, // 0x42
    SystemSessionPoolTagInformation                       = 67, // 0x43
    SystemSessionMappedViewInformation                    = 68, // 0x44
    SystemHotpatchInformation                             = 69, // 0x45
    SystemObjectSecurityMode                              = 70, // 0x46
    SystemWatchdogTimerHandler                            = 71, // 0x47
    SystemWatchdogTimerInformation                        = 72, // 0x48
    SystemLogicalProcessorInformation                     = 73, // 0x49
    SystemWow64SharedInformationObsolete                  = 74, // 0x4A
    SystemRegisterFirmwareTableInformationHandler         = 75, // 0x4B
    SystemFirmwareTableInformation                        = 76, // 0x4C

#if (NTDDI_VERSION >= NTDDI_VISTA) || defined(__REACTOS__)
    SystemModuleInformationEx                             = 77, // 0x4D
    SystemVerifierTriageInformation                       = 78, // 0x4E
    SystemSuperfetchInformation                           = 79, // 0x4F
    SystemMemoryListInformation                           = 80, // 0x50
    SystemFileCacheInformationEx                          = 81, // 0x51
    SystemThreadPriorityClientIdInformation               = 82, // 0x52
    SystemProcessorIdleCycleTimeInformation               = 83, // 0x53
    SystemVerifierCancellationInformation                 = 84, // 0x54
    SystemProcessorPowerInformationEx                     = 85, // 0x55
    SystemRefTraceInformation                             = 86, // 0x56
    SystemSpecialPoolInformation                          = 87, // 0x57
    SystemProcessIdInformation                            = 88, // 0x58
    SystemErrorPortInformation                            = 89, // 0x59
    SystemBootEnvironmentInformation                      = 90, // 0x5A
    SystemHypervisorInformation                           = 91, // 0x5B
    SystemVerifierInformationEx                           = 92, // 0x5C
    SystemTimeZoneInformation                             = 93, // 0x5D
    SystemImageFileExecutionOptionsInformation            = 94, // 0x5E
    SystemCoverageInformation                             = 95, // 0x5F
    SystemPrefetchPatchInformation                        = 96, // 0x60
    SystemVerifierFaultsInformation                       = 97, // 0x61
    SystemSystemPartitionInformation                      = 98, // 0x62
    SystemSystemDiskInformation                           = 99, // 0x63
    SystemProcessorPerformanceDistribution                = 100, // 0x64
    SystemNumaProximityNodeInformation                    = 101, // 0x65
    SystemDynamicTimeZoneInformation                      = 102, // 0x66
    SystemCodeIntegrityInformation                        = 103, // 0x67
    SystemProcessorMicrocodeUpdateInformation             = 104, // 0x68
    SystemProcessorBrandString                            = 105, // 0x69
    SystemVirtualAddressInformation                       = 106, // 0x6A
#endif // (NTDDI_VERSION >= NTDDI_VISTA)

#if (NTDDI_VERSION >= NTDDI_WIN7) || defined(__REACTOS__)
    SystemLogicalProcessorAndGroupInformation             = 107, // 0x6B
    SystemProcessorCycleTimeInformation                   = 108, // 0x6C
    SystemStoreInformation                                = 109, // 0x6D
    SystemRegistryAppendString                            = 110, // 0x6E
    SystemAitSamplingValue                                = 111, // 0x6F
    SystemVhdBootInformation                              = 112, // 0x70
    SystemCpuQuotaInformation                             = 113, // 0x71
    SystemNativeBasicInformation                          = 114, // 0x72
    SystemErrorPortTimeouts                               = 115, // 0x73
    SystemLowPriorityIoInformation                        = 116, // 0x74
    SystemBootEntropyInformation                          = 117, // 0x75
    SystemVerifierCountersInformation                     = 118, // 0x76
    SystemPagedPoolInformationEx                          = 119, // 0x77
    SystemSystemPtesInformationEx                         = 120, // 0x78
    SystemNodeDistanceInformation                         = 121, // 0x79
    SystemAcpiAuditInformation                            = 122, // 0x7A
    SystemBasicPerformanceInformation                     = 123, // 0x7B
    SystemQueryPerformanceCounterInformation              = 124, // 0x7C
#endif // (NTDDI_VERSION >= NTDDI_WIN7)

#if (NTDDI_VERSION >= NTDDI_WIN8)
    SystemSessionBigPoolInformation                       = 125, // 0x7D
    SystemBootGraphicsInformation                         = 126, // 0x7E
    SystemScrubPhysicalMemoryInformation                  = 127, // 0x7F
    SystemBadPageInformation                              = 128, // 0x80
    SystemProcessorProfileControlArea                     = 129, // 0x81
    SystemCombinePhysicalMemoryInformation                = 130, // 0x82
    SystemEntropyInterruptTimingInformation               = 131, // 0x83
    SystemConsoleInformation                              = 132, // 0x84
    SystemPlatformBinaryInformation                       = 133, // 0x85
    SystemThrottleNotificationInformation                 = 134, // 0x86 - 6.2 only
    SystemPolicyInformation                               = 134, // 0x86 - 6.3 and higher
    SystemHypervisorProcessorCountInformation             = 135, // 0x87
    SystemDeviceDataInformation                           = 136, // 0x88
    SystemDeviceDataEnumerationInformation                = 137, // 0x89
    SystemMemoryTopologyInformation                       = 138, // 0x8A
    SystemMemoryChannelInformation                        = 139, // 0x8B
    SystemBootLogoInformation                             = 140, // 0x8C
    SystemProcessorPerformanceInformationEx               = 141, // 0x8D
    SystemSpare0                                          = 142, // 0x8E - 6.2 to 1511
    SystemCriticalProcessErrorLogInformation              = 142, // 0x8E - 1607 and higher
    SystemSecureBootPolicyInformation                     = 143, // 0x8F
    SystemPageFileInformationEx                           = 144, // 0x90
    SystemSecureBootInformation                           = 145, // 0x91
    SystemEntropyInterruptTimingRawInformation            = 146, // 0x92
    SystemPortableWorkspaceEfiLauncherInformation         = 147, // 0x93
    SystemFullProcessInformation                          = 148, // 0x94
#endif // (NTDDI_VERSION >= NTDDI_WIN8)

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
    SystemKernelDebuggerInformationEx                     = 149, // 0x95
    SystemBootMetadataInformation                         = 150, // 0x96
    SystemSoftRebootInformation                           = 151, // 0x97
    SystemElamCertificateInformation                      = 152, // 0x98
    SystemOfflineDumpConfigInformation                    = 153, // 0x99
    SystemProcessorFeaturesInformation                    = 154, // 0x9A
    SystemRegistryReconciliationInformation               = 155, // 0x9B
    SystemEdidInformation                                 = 156, // 0x9C
#endif // (NTDDI_VERSION >= NTDDI_WINBLUE)

#if (NTDDI_VERSION >= NTDDI_WIN10)
    SystemManufacturingInformation                        = 157, // 0x9D
    SystemEnergyEstimationConfigInformation               = 158, // 0x9E
    SystemHypervisorDetailInformation                     = 159, // 0x9F
    SystemProcessorCycleStatsInformation                  = 160, // 0xA0
    SystemVmGenerationCountInformation                    = 161, // 0xA1
    SystemTrustedPlatformModuleInformation                = 162, // 0xA2
    SystemKernelDebuggerFlags                             = 163, // 0xA3
    SystemCodeIntegrityPolicyInformation                  = 164, // 0xA4
    SystemIsolatedUserModeInformation                     = 165, // 0xA5
    SystemHardwareSecurityTestInterfaceResultsInformation = 166, // 0xA6
    SystemSingleModuleInformation                         = 167, // 0xA7
    SystemAllowedCpuSetsInformation                       = 168, // 0xA8
    SystemVsmProtectionInformation                        = 169, // 0xA9 - aka SystemDmaProtectionInformation
    SystemInterruptCpuSetsInformation                     = 170, // 0xAA
    SystemSecureBootPolicyFullInformation                 = 171, // 0xAB
    SystemCodeIntegrityPolicyFullInformation              = 172, // 0xAC
    SystemAffinitizedInterruptProcessorInformation        = 173, // 0xAD
    SystemRootSiloInformation                             = 174, // 0xAE
    SystemCpuSetInformation                               = 175, // 0xAF
    SystemCpuSetTagInformation                            = 176, // 0xB0
    SystemWin32WerStartCallout                            = 177, // 0xB1
    SystemSecureKernelProfileInformation                  = 178, // 0xB2
    SystemCodeIntegrityPlatformManifestInformation        = 179, // 0xB3
    SystemInterruptSteeringInformation                    = 180, // 0xB4
    SystemSupportedProcessorArchitectures                 = 181, // 0xB5
    SystemMemoryUsageInformation                          = 182, // 0xB6
    SystemCodeIntegrityCertificateInformation             = 183, // 0xB7
    SystemPhysicalMemoryInformation                       = 184, // 0xB8
    SystemControlFlowTransition                           = 185, // 0xB9
    SystemKernelDebuggingAllowed                          = 186, // 0xBA
    SystemActivityModerationExeState                      = 187, // 0xBB
    SystemActivityModerationUserSettings                  = 188, // 0xBC
    SystemCodeIntegrityPoliciesFullInformation            = 189, // 0xBD
    SystemCodeIntegrityUnlockInformation                  = 190, // 0xBE
    SystemIntegrityQuotaInformation                       = 191, // 0xBF
    SystemFlushInformation                                = 192, // 0xC0
    SystemProcessorIdleMaskInformation                    = 193, // 0xC1
    SystemSecureDumpEncryptionInformation                 = 194, // 0xC2
    SystemWriteConstraintInformation                      = 195, // 0xC3
    SystemKernelVaShadowInformation                       = 196, // 0xC4
    SystemHypervisorSharedPageInformation                 = 197, // 0xC5
    SystemFirmwareBootPerformanceInformation              = 198, // 0xC6
    SystemCodeIntegrityVerificationInformation            = 199, // 0xC7
    SystemFirmwarePartitionInformation                    = 200, // 0xC8
    SystemSpeculationControlInformation                   = 201, // 0xC9
    SystemDmaGuardPolicyInformation                       = 202, // 0xCA
    SystemEnclaveLaunchControlInformation                 = 203, // 0xCB
    SystemWorkloadAllowedCpuSetsInformation               = 204, // 0xCC
    SystemCodeIntegrityUnlockModeInformation              = 205, // 0xCD
    SystemLeapSecondInformation                           = 206, // 0xCE
    SystemFlags2Information                               = 207, // 0xCF
    SystemSecurityModelInformation                        = 208, // 0xD0
    SystemCodeIntegritySyntheticCacheInformation          = 209, // 0xD1
    SystemFeatureConfigurationInformation                 = 210, // 0xD2
    SystemFeatureConfigurationSectionInformation          = 211, // 0xD3
    SystemFeatureUsageSubscriptionInformation             = 212, // 0xD4
    SystemSecureSpeculationControlInformation             = 213, // 0xD5
    SystemSpacesBootInformation                           = 214, // 0xD6
    SystemFwRamdiskInformation                            = 215, // 0xD7
    SystemWheaIpmiHardwareInformation                     = 216, // 0xD8
    SystemDifSetRuleClassInformation                      = 217, // 0xD9
    SystemDifClearRuleClassInformation                    = 218, // 0xDA
    SystemDifApplyPluginVerificationOnDriver              = 219, // 0xDB
    SystemDifRemovePluginVerificationOnDriver             = 220, // 0xDC
    SystemShadowStackInformation                          = 221, // 0xDD
    SystemBuildVersionInformation                         = 222, // 0xDE
    SystemPoolLimitInformation                            = 223, // 0xDF
    SystemCodeIntegrityAddDynamicStore                    = 224, // 0xE0
    SystemCodeIntegrityClearDynamicStores                 = 225, // 0xE1
    SystemDifPoolTrackingInformation                      = 226, // 0xE2 - Win 11
    SystemPoolZeroingInformation                          = 227, // 0xE3
#endif // (NTDDI_VERSION >= NTDDI_WIN10)

#if (NTDDI_VERSION >= NTDDI_WIN11)
    SystemDpcWatchdogInformation                          = 228, // 0xE4
    SystemDpcWatchdogInformation2                         = 229, // 0xE5
    SystemSupportedProcessorArchitectures2                = 230, // 0xE6
    SystemSingleProcessorRelationshipInformation          = 231, // 0xE7
    SystemXfgCheckFailureInformation                      = 232, // 0xE8
    SystemIommuStateInformation                           = 233, // 0xE9
    SystemHypervisorMinrootInformation                    = 234, // 0xEA
    SystemHypervisorBootPagesInformation                  = 235, // 0xEB
    SystemPointerAuthInformation                          = 236, // 0xEC
    SystemSecureKernelDebuggerInformation                 = 237, // 0xED
    SystemOriginalImageFeatureInformation                 = 238, // 0xEE
    SystemMemoryNumaInformation                           = 239, // 0xEF
    SystemMemoryNumaPerformanceInformation                = 240, // 0xF0
    SystemCodeIntegritySignedPoliciesFullInformation      = 241, // 0xF1
    SystemSecureSecretsInformation                        = 242, // 0xF2
    SystemTrustedAppsRuntimeInformation                   = 243, // 0xF3
    SystemBadPageInformationEx                            = 244, // 0xF4
    SystemResourceDeadlockTimeout                         = 245, // 0xF5
    SystemBreakOnContextUnwindFailureInformation          = 246, // 0xF6
    SystemOslRamdiskInformation                           = 247, // 0xF7
#endif // (NTDDI_VERSION >= NTDDI_WIN11)

    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

//
// System Information Classes for NtQueryMutant
//
typedef enum _MUTANT_INFORMATION_CLASS
{
    MutantBasicInformation,
    MutantOwnerInformation
} MUTANT_INFORMATION_CLASS;

//
// System Information Classes for NtQueryAtom
//
typedef enum _ATOM_INFORMATION_CLASS
{
    AtomBasicInformation,
    AtomTableInformation,
} ATOM_INFORMATION_CLASS;

//
// System Information Classes for NtQueryTimer
//
typedef enum _TIMER_INFORMATION_CLASS
{
    TimerBasicInformation
} TIMER_INFORMATION_CLASS;

//
// System Information Classes for NtQuerySemaphore
//
typedef enum _SEMAPHORE_INFORMATION_CLASS
{
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

//
// System Information Classes for NtQueryEvent
//
typedef enum _EVENT_INFORMATION_CLASS
{
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

#ifdef NTOS_MODE_USER

//
// Firmware Table Actions for SystemFirmwareTableInformation
//
typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
    SystemFirmwareTable_Enumerate = 0,
    SystemFirmwareTable_Get = 1,
} SYSTEM_FIRMWARE_TABLE_ACTION, *PSYSTEM_FIRMWARE_TABLE_ACTION;

//
// Firmware Handler Callback
//
struct _SYSTEM_FIRMWARE_TABLE_INFORMATION;
typedef
NTSTATUS
(__cdecl *PFNFTH)(
    _In_ struct _SYSTEM_FIRMWARE_TABLE_INFORMATION *FirmwareTableInformation
);

#else

//
// Handle Enumeration Callback
//
struct _HANDLE_TABLE_ENTRY;
typedef BOOLEAN
(NTAPI *PEX_ENUM_HANDLE_CALLBACK)(
    _In_ struct _HANDLE_TABLE_ENTRY *HandleTableEntry,
    _In_ HANDLE Handle,
    _In_ PVOID Context
);

//
// Executive Work Queue Structures
//
typedef struct _EX_QUEUE_WORKER_INFO
{
    ULONG QueueDisabled:1;
    ULONG MakeThreadsAsNecessary:1;
    ULONG WaitMode:1;
    ULONG WorkerCount:29;
} EX_QUEUE_WORKER_INFO, *PEX_QUEUE_WORKER_INFO;

typedef struct _EX_WORK_QUEUE
{
    KQUEUE WorkerQueue;
    LONG DynamicThreadCount;
    ULONG WorkItemsProcessed;
    ULONG WorkItemsProcessedLastPass;
    ULONG QueueDepthLastPass;
    EX_QUEUE_WORKER_INFO Info;
} EX_WORK_QUEUE, *PEX_WORK_QUEUE;

//
// Executive Fast Reference Structure
//
typedef struct _EX_FAST_REF
{
    union
    {
        PVOID Object;
        ULONG_PTR RefCnt:3;
        ULONG_PTR Value;
    };
} EX_FAST_REF, *PEX_FAST_REF;

//
// Executive Cache-Aware Rundown Reference Descriptor
//
typedef struct _EX_RUNDOWN_REF_CACHE_AWARE
{
    PEX_RUNDOWN_REF RunRefs;
    PVOID PoolToFree;
    ULONG RunRefSize;
    ULONG Number;
} EX_RUNDOWN_REF_CACHE_AWARE;

//
// Executive Rundown Wait Block
//
typedef struct _EX_RUNDOWN_WAIT_BLOCK
{
    ULONG_PTR Count;
    KEVENT WakeEvent;
} EX_RUNDOWN_WAIT_BLOCK, *PEX_RUNDOWN_WAIT_BLOCK;

//
// Executive Pushlock
//
#undef EX_PUSH_LOCK
#undef PEX_PUSH_LOCK
typedef struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONG_PTR Locked:1;
            ULONG_PTR Waiting:1;
            ULONG_PTR Waking:1;
            ULONG_PTR MultipleShared:1;
            ULONG_PTR Shared:sizeof (ULONG_PTR) * 8 - 4;
        };
        ULONG_PTR Value;
        PVOID Ptr;
    };
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

//
// Executive Pushlock Wait Block
//

//
// The wait block has to be properly aligned
// on a non-checked build even if the debug data isn't there.
//
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4324)
#endif

typedef __ALIGNED(16) struct _EX_PUSH_LOCK_WAIT_BLOCK
{
    union
    {
        KGATE WakeGate;
        KEVENT WakeEvent;
    };
    struct _EX_PUSH_LOCK_WAIT_BLOCK *Next;
    struct _EX_PUSH_LOCK_WAIT_BLOCK *Last;
    struct _EX_PUSH_LOCK_WAIT_BLOCK *Previous;
    LONG ShareCount;
    LONG Flags;
#if DBG
    BOOLEAN Signaled;
    EX_PUSH_LOCK NewValue;
    EX_PUSH_LOCK OldValue;
    PEX_PUSH_LOCK PushLock;
#endif
} EX_PUSH_LOCK_WAIT_BLOCK, *PEX_PUSH_LOCK_WAIT_BLOCK;

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

//
// Callback Object
//
typedef struct _CALLBACK_OBJECT
{
    ULONG Signature;
    KSPIN_LOCK Lock;
    LIST_ENTRY RegisteredCallbacks;
    BOOLEAN AllowMultipleCallbacks;
    UCHAR reserved[3];
} CALLBACK_OBJECT;

//
// Callback Handle
//
typedef struct _CALLBACK_REGISTRATION
{
    LIST_ENTRY Link;
    PCALLBACK_OBJECT CallbackObject;
    PCALLBACK_FUNCTION CallbackFunction;
    PVOID CallbackContext;
    ULONG Busy;
    BOOLEAN UnregisterWaiting;
} CALLBACK_REGISTRATION, *PCALLBACK_REGISTRATION;

//
// Internal Callback Object
//
typedef struct _EX_CALLBACK_ROUTINE_BLOCK
{
    EX_RUNDOWN_REF RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

//
// Internal Callback Handle
//
typedef struct _EX_CALLBACK
{
    EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

//
// Profile Object
//
typedef struct _EPROFILE
{
    PEPROCESS Process;
    PVOID RangeBase;
    SIZE_T RangeSize;
    PVOID Buffer;
    ULONG BufferSize;
    ULONG BucketSize;
    PKPROFILE ProfileObject;
    PVOID LockedBufferAddress;
    PMDL Mdl;
    ULONG_PTR Segment;
    KPROFILE_SOURCE ProfileSource;
    KAFFINITY Affinity;
} EPROFILE, *PEPROFILE;

//
// Handle Table Structures
//
typedef struct _HANDLE_TRACE_DB_ENTRY
{
    CLIENT_ID ClientId;
    HANDLE Handle;
    ULONG Type;
    PVOID StackTrace[16];
} HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;

typedef struct _HANDLE_TRACE_DEBUG_INFO
{
    LONG RefCount;
    ULONG TableSize;
    ULONG BitMaskFlags;
    FAST_MUTEX CloseCompactionLock;
    ULONG CurrentStackIndex;
    HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
    ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY
{
    union
    {
        PVOID Object;
        ULONG_PTR ObAttributes;
        PHANDLE_TABLE_ENTRY_INFO InfoTable;
        ULONG_PTR Value;
    };
    union
    {
        ULONG GrantedAccess;
        struct
        {
            USHORT GrantedAccessIndex;
            USHORT CreatorBackTraceIndex;
        };
        LONG NextFreeTableEntry;
    };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
#if (NTDDI_VERSION >= NTDDI_WINXP)
    ULONG_PTR TableCode;
#else
    PHANDLE_TABLE_ENTRY **Table;
#endif
    PEPROCESS QuotaProcess;
    PVOID UniqueProcessId;
#if (NTDDI_VERSION >= NTDDI_WINXP)
    EX_PUSH_LOCK HandleTableLock[4];
    LIST_ENTRY HandleTableList;
    EX_PUSH_LOCK HandleContentionEvent;
#else
    ERESOURCE HandleLock;
    LIST_ENTRY HandleTableList;
    KEVENT HandleContentionEvent;
#endif
    PHANDLE_TRACE_DEBUG_INFO DebugInfo;
    LONG ExtraInfoPages;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    union
    {
        ULONG Flags;
        UCHAR StrictFIFO:1;
    };
    LONG FirstFreeHandle;
    PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
    LONG HandleCount;
    ULONG NextHandleNeedingPool;
#else
    ULONG FirstFree;
    ULONG LastFree;
    ULONG NextHandleNeedingPool;
    LONG HandleCount;
    union
    {
        ULONG Flags;
        UCHAR StrictFIFO:1;
    };
#endif
} HANDLE_TABLE, *PHANDLE_TABLE;

#endif

//
// Hard Error LPC Message
//
typedef struct _HARDERROR_MSG
{
    PORT_MESSAGE h;
    NTSTATUS Status;
    LARGE_INTEGER ErrorTime;
    ULONG ValidResponseOptions;
    ULONG Response;
    ULONG NumberOfParameters;
    ULONG UnicodeStringParameterMask;
    ULONG_PTR Parameters[MAXIMUM_HARDERROR_PARAMETERS];
} HARDERROR_MSG, *PHARDERROR_MSG;

//
// Information Structures for NtQueryMutant
//
typedef struct _MUTANT_BASIC_INFORMATION
{
    LONG CurrentCount;
    BOOLEAN OwnedByCaller;
    BOOLEAN AbandonedState;
} MUTANT_BASIC_INFORMATION, *PMUTANT_BASIC_INFORMATION;

typedef struct _MUTANT_OWNER_INFORMATION
{
    CLIENT_ID ClientId;
} MUTANT_OWNER_INFORMATION, *PMUTANT_OWNER_INFORMATION;

//
// Information Structures for NtQueryAtom
//
typedef struct _ATOM_BASIC_INFORMATION
{
    USHORT UsageCount;
    USHORT Flags;
    USHORT NameLength;
    WCHAR Name[1];
} ATOM_BASIC_INFORMATION, *PATOM_BASIC_INFORMATION;

typedef struct _ATOM_TABLE_INFORMATION
{
    ULONG NumberOfAtoms;
    USHORT Atoms[1];
} ATOM_TABLE_INFORMATION, *PATOM_TABLE_INFORMATION;

//
// Information Structures for NtQueryTimer
//
typedef struct _TIMER_BASIC_INFORMATION
{
    LARGE_INTEGER TimeRemaining;
    BOOLEAN SignalState;
} TIMER_BASIC_INFORMATION, *PTIMER_BASIC_INFORMATION;

//
// Information Structures for NtQuerySemaphore
//
typedef struct _SEMAPHORE_BASIC_INFORMATION
{
    LONG CurrentCount;
    LONG MaximumCount;
} SEMAPHORE_BASIC_INFORMATION, *PSEMAPHORE_BASIC_INFORMATION;

//
// Information Structures for NtQueryEvent
//
typedef struct _EVENT_BASIC_INFORMATION
{
    EVENT_TYPE EventType;
    LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

//
// Information Structures for NtQuerySystemInformation
//
typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

// Class 1
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
#if (NTDDI_VERSION < NTDDI_WIN8)
    USHORT Reserved;
#else
    USHORT MaximumProcessors;
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10) || ((NTDDI_VERSION >= NTDDI_WINBLUE) && defined(_WIN64))
    ULONG64 ProcessorFeatureBits;
#else
    ULONG ProcessorFeatureBits;
#endif
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

// Class 2
typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG Spare3Count;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    ULONGLONG CcTotalDirtyPages;
    ULONGLONG CcDirtyPageThreshold;
#endif
#if (NTDDI_VERSION >= NTDDI_WIN8)
    LONGLONG ResidentAvailablePages;
    ULONGLONG SharedCommittedPages;
#endif
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

// Class 3
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
#if (NTDDI_VERSION >= NTDDI_WIN2K)
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
#endif
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

// Class 4
// This class is obsolete, please use KUSER_SHARED_DATA instead

// Class 5
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
    ULONG PadPadAlignment;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
#ifndef _WIN64
C_ASSERT(sizeof(SYSTEM_THREAD_INFORMATION) == 0x40); // Must be 8-byte aligned
#endif

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; //VISTA
    ULONG HardFaultCount; //WIN7
    ULONG NumberOfThreadsHighWatermark; //WIN7
    ULONGLONG CycleTime; //WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;

    //
    // This part corresponds to VM_COUNTERS_EX.
    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
    //
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;

    //
    // This part corresponds to IO_COUNTERS
    //
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
//    SYSTEM_THREAD_INFORMATION TH[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
#ifndef _WIN64
C_ASSERT(sizeof(SYSTEM_PROCESS_INFORMATION) == 0xB8); // Must be 8-byte aligned
#endif

//
// Class 6
typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
    ULONG Length;
    ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

// Class 7
typedef struct _SYSTEM_DEVICE_INFORMATION
{
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

// Class 8
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

// Class 9
typedef struct _SYSTEM_FLAGS_INFORMATION
{
    ULONG Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

// Class 10
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
    ULONG Length;
    ULONG TotalCalls;
    LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

// Class 11 - See RTL_PROCESS_MODULES

// Class 12 - See RTL_PROCESS_LOCKS

// Class 13 - See RTL_PROCESS_BACKTRACES

// Class 14 - 15
typedef struct _SYSTEM_POOL_ENTRY
{
    BOOLEAN Allocated;
    BOOLEAN Spare0;
    USHORT AllocatorBackTraceIndex;
    ULONG Size;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
        PVOID ProcessChargedQuota;
    };
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION
{
    SIZE_T TotalSize;
    PVOID FirstEntry;
    USHORT EntryOverhead;
    BOOLEAN PoolTagPresent;
    BOOLEAN Spare0;
    ULONG NumberOfEntries;
    SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

// Class 16
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// Class 17
typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfObjects;
    ULONG NumberOfHandles;
    ULONG TypeIndex;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG PoolType;
    BOOLEAN SecurityRequired;
    BOOLEAN WaitableObject;
    UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION
{
    ULONG NextEntryOffset;
    PVOID Object;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Flags;
    LONG PointerCount;
    LONG HandleCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    HANDLE ExclusiveProcessId;
    PVOID SecurityDescriptor;
    OBJECT_NAME_INFORMATION NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

// Class 18
typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

// Class 19
typedef struct _SYSTEM_VDM_INSTEMUL_INFO
{
    ULONG SegmentNotPresent;
    ULONG VdmOpcode0F;
    ULONG OpcodeESPrefix;
    ULONG OpcodeCSPrefix;
    ULONG OpcodeSSPrefix;
    ULONG OpcodeDSPrefix;
    ULONG OpcodeFSPrefix;
    ULONG OpcodeGSPrefix;
    ULONG OpcodeOPER32Prefix;
    ULONG OpcodeADDR32Prefix;
    ULONG OpcodeINSB;
    ULONG OpcodeINSW;
    ULONG OpcodeOUTSB;
    ULONG OpcodeOUTSW;
    ULONG OpcodePUSHF;
    ULONG OpcodePOPF;
    ULONG OpcodeINTnn;
    ULONG OpcodeINTO;
    ULONG OpcodeIRET;
    ULONG OpcodeINBimm;
    ULONG OpcodeINWimm;
    ULONG OpcodeOUTBimm;
    ULONG OpcodeOUTWimm ;
    ULONG OpcodeINB;
    ULONG OpcodeINW;
    ULONG OpcodeOUTB;
    ULONG OpcodeOUTW;
    ULONG OpcodeLOCKPrefix;
    ULONG OpcodeREPNEPrefix;
    ULONG OpcodeREPPrefix;
    ULONG OpcodeHLT;
    ULONG OpcodeCLI;
    ULONG OpcodeSTI;
    ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;

// Class 20 - ULONG VDMBOPINFO

// Class 21
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

// Class 22
typedef struct _SYSTEM_POOLTAG
{
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

// Class 23
typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

// Class 24
typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
    ULONG Spare;
    ULONG DpcQueueDepth;
    ULONG MinimumDpcRate;
    ULONG AdjustDpcThreshold;
    ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

// Class 25
typedef struct _SYSTEM_MEMORY_INFO
{
    PUCHAR StringOffset;
    USHORT ValidCount;
    USHORT TransitionCount;
    USHORT ModifiedCount;
    USHORT PageTableCount;
} SYSTEM_MEMORY_INFO, *PSYSTEM_MEMORY_INFO;

typedef struct _SYSTEM_MEMORY_INFORMATION
{
    ULONG InfoSize;
    ULONG StringStart;
    SYSTEM_MEMORY_INFO Memory[1];
} SYSTEM_MEMORY_INFORMATION, *PSYSTEM_MEMORY_INFORMATION;

// Class 26
// See https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/gdi_driver.htm.
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

// Class 27
// Not an actually class, simply a PVOID to the ImageAddress

// Class 28
typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    ULONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

// Class 29 - Same as 25

// FIXME: Class 30

// Class 31
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
   UCHAR TraceEnable;
   UCHAR TracePermanent;
   UNICODE_STRING TraceProcessName;
   UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

// Class 32 - OBSOLETE

// Class 33
typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
    ULONG AlignmentFixupCount;
    ULONG ExceptionDispatchCount;
    ULONG FloatingEmulationCount;
    ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

// Class 34
typedef struct _SYSTEM_CRASH_STATE_INFORMATION
{
    ULONG ValidCrashDump;
} SYSTEM_CRASH_STATE_INFORMATION, *PSYSTEM_CRASH_STATE_INFORMATION;

// Class 35
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// Class 36
typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
    ULONG ContextSwitches;
    ULONG FindAny;
    ULONG FindLast;
    ULONG FindIdeal;
    ULONG IdleAny;
    ULONG IdleCurrent;
    ULONG IdleLast;
    ULONG IdleIdeal;
    ULONG PreemptAny;
    ULONG PreemptCurrent;
    ULONG PreemptLast;
    ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

// Class 37
typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
    ULONG RegistryQuotaAllowed;
    ULONG RegistryQuotaUsed;
    SIZE_T PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

// Class 38
// Not a structure, simply send the UNICODE_STRING

// Class 39
// Not a structure, simply send a ULONG containing the new separation

// Class 40
typedef struct _SYSTEM_PLUGPLAY_BUS_INFORMATION
{
    ULONG BusCount;
    PLUGPLAY_BUS_INSTANCE BusInstance[1];
} SYSTEM_PLUGPLAY_BUS_INFORMATION, *PSYSTEM_PLUGPLAY_BUS_INFORMATION;

// Class 41
typedef struct _SYSTEM_DOCK_INFORMATION
{
    SYSTEM_DOCK_STATE DockState;
    INTERFACE_TYPE DeviceBusType;
    ULONG DeviceBusNumber;
    ULONG SlotNumber;
} SYSTEM_DOCK_INFORMATION, *PSYSTEM_DOCK_INFORMATION;

// Class 42
typedef struct _SYSTEM_POWER_INFORMATION_NATIVE
{
    BOOLEAN SystemSuspendSupported;
    BOOLEAN SystemHibernateSupported;
    BOOLEAN ResumeTimerSupportsSuspend;
    BOOLEAN ResumeTimerSupportsHibernate;
    BOOLEAN LidSupported;
    BOOLEAN TurboSettingSupported;
    BOOLEAN TurboMode;
    BOOLEAN SystemAcOrDc;
    BOOLEAN PowerDownDisabled;
    LARGE_INTEGER SpindownDrives;
} SYSTEM_POWER_INFORMATION_NATIVE, *PSYSTEM_POWER_INFORMATION_NATIVE;

// Class 43
typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
    PNP_VETO_TYPE VetoType;
    UNICODE_STRING VetoDriver;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

// Class 44
//typedef struct _TIME_ZONE_INFORMATION RTL_TIME_ZONE_INFORMATION;

// Class 45
typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
    USHORT CurrentDepth;
    USHORT MaximumDepth;
    ULONG TotalAllocates;
    ULONG AllocateMisses;
    ULONG TotalFrees;
    ULONG FreeMisses;
    ULONG Type;
    ULONG Tag;
    ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

// Class 46
// Not a structure. Only a HANDLE for the SlipEvent;

// Class 47
// Not a structure. Only a ULONG for the SessionId;

// Class 48
// Not a structure. Only a ULONG for the SessionId;

// FIXME: Class 49

// Class 50
// Not a structure. Only a ULONG_PTR for the SystemRangeStart

// Class 51
typedef struct _SYSTEM_VERIFIER_INFORMATION
{
   ULONG NextEntryOffset;
   ULONG Level;
   UNICODE_STRING DriverName;
   ULONG RaiseIrqls;
   ULONG AcquireSpinLocks;
   ULONG SynchronizeExecutions;
   ULONG AllocationsAttempted;
   ULONG AllocationsSucceeded;
   ULONG AllocationsSucceededSpecialPool;
   ULONG AllocationsWithNoTag;
   ULONG TrimRequests;
   ULONG Trims;
   ULONG AllocationsFailed;
   ULONG AllocationsFailedDeliberately;
   ULONG Loads;
   ULONG Unloads;
   ULONG UnTrackedPool;
   ULONG CurrentPagedPoolAllocations;
   ULONG CurrentNonPagedPoolAllocations;
   ULONG PeakPagedPoolAllocations;
   ULONG PeakNonPagedPoolAllocations;
   SIZE_T PagedPoolUsageInBytes;
   SIZE_T NonPagedPoolUsageInBytes;
   SIZE_T PeakPagedPoolUsageInBytes;
   SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

// FIXME: Class 52

// Class 53
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer; // Same format as in SystemProcessInformation
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

// FIXME: Class 54

// Class 55
#define MAXIMUM_NUMA_NODES 16
typedef struct _SYSTEM_NUMA_INFORMATION
{
    ULONG HighestNodeNumber;
    ULONG Reserved;
    union
    {
        ULONGLONG ActiveProcessorsAffinityMask[MAXIMUM_NUMA_NODES];
        ULONGLONG AvailableMemory[MAXIMUM_NUMA_NODES];
    };
} SYSTEM_NUMA_INFORMATION, *PSYSTEM_NUMA_INFORMATION;

// FIXME: Class 56-63

// Class 64
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// FIXME: Class 65-89

// Class 90
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
#if (NTDDI_VERSION >= NTDDI_WIN8)
    ULONGLONG BootFlags;
#endif
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
typedef struct _SYSTEM_BOOT_ENVIRONMENT_V1
{
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_V1, *PSYSTEM_BOOT_ENVIRONMENT_V1;
#endif

// FIXME: Class 91-97

#if (NTDDI_VERSION >= NTDDI_VISTA)
// Class 98
typedef struct _SYSTEM_SYSTEM_PARTITION_INFORMATION
{
    UNICODE_STRING SystemPartition;
} SYSTEM_SYSTEM_PARTITION_INFORMATION, *PSYSTEM_SYSTEM_PARTITION_INFORMATION;

// Class 99
typedef struct _SYSTEM_SYSTEM_DISK_INFORMATION
{
    UNICODE_STRING SystemDisk;
} SYSTEM_SYSTEM_DISK_INFORMATION, *PSYSTEM_SYSTEM_DISK_INFORMATION;
#endif

//
// Hotpatch flags
//
#define RTL_HOTPATCH_SUPPORTED_FLAG         0x01
#define RTL_HOTPATCH_SWAP_OBJECT_NAMES      0x08 << 24
#define RTL_HOTPATCH_SYNC_RENAME_FILES      0x10 << 24
#define RTL_HOTPATCH_PATCH_USER_MODE        0x20 << 24
#define RTL_HOTPATCH_REMAP_SYSTEM_DLL       0x40 << 24
#define RTL_HOTPATCH_PATCH_KERNEL_MODE      0x80 << 24


// Class 69
typedef struct _SYSTEM_HOTPATCH_CODE_INFORMATION
{
    ULONG Flags;
    ULONG InfoSize;
    union
    {
        struct
        {
            ULONG Foo;
        } CodeInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
        } KernelInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
            USHORT TargetNameOffset;
            USHORT TargetNameLength;
            UCHAR PatchingFinished;
        } UserModeInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
            USHORT TargetNameOffset;
            USHORT TargetNameLength;
            UCHAR PatchingFinished;
            NTSTATUS ReturnCode;
            HANDLE TargetProcess;
        } InjectionInfo;
        struct
        {
            HANDLE FileHandle1;
            PIO_STATUS_BLOCK IoStatusBlock1;
            PVOID RenameInformation1;
            PVOID RenameInformationLength1;
            HANDLE FileHandle2;
            PIO_STATUS_BLOCK IoStatusBlock2;
            PVOID RenameInformation2;
            PVOID RenameInformationLength2;
        } RenameInfo;
        struct
        {
            HANDLE ParentDirectory;
            HANDLE ObjectHandle1;
            HANDLE ObjectHandle2;
        } AtomicSwap;
    };
} SYSTEM_HOTPATCH_CODE_INFORMATION, *PSYSTEM_HOTPATCH_CODE_INFORMATION;

//
// Class 75
//
#ifdef NTOS_MODE_USER
typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
    ULONG ProviderSignature;
    BOOLEAN Register;
    PFNFTH FirmwareTableHandler;
    PVOID DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER, *PSYSTEM_FIRMWARE_TABLE_HANDLER;

//
// Class 76
//
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

#endif // !NTOS_MODE_USER

//
// Class 80
//
typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
    SIZE_T ZeroPageCount;
    SIZE_T FreePageCount;
    SIZE_T ModifiedPageCount;
    SIZE_T ModifiedNoWritePageCount;
    SIZE_T BadPageCount;
    SIZE_T PageCountByPriority[8];
    SIZE_T RepurposedPagesByPriority[8];
    SIZE_T ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION, *PSYSTEM_MEMORY_LIST_INFORMATION;

//
// Firmware variable attributes
//
#define VARIABLE_ATTRIBUTE_NON_VOLATILE                             0x00000001
#define VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS                       0x00000002
#define VARIABLE_ATTRIBUTE_RUNTIME_ACCESS                           0x00000004
#define VARIABLE_ATTRIBUTE_HARDWARE_ERROR_RECORD                    0x00000008
#define VARIABLE_ATTRIBUTE_AUTHENTICATED_WRITE_ACCESS               0x00000010
#define VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS    0x00000020
#define VARIABLE_ATTRIBUTE_APPEND_WRITE                             0x00000040

#ifdef __cplusplus
}; // extern "C"
#endif

#endif // !_EXTYPES_H
