#pragma once

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include "../shared/protocol.h"

// Undocumented structures

typedef struct _PEB_LDR_DATA {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY      InLoadOrderLinks;
    LIST_ENTRY      InMemoryOrderLinks;
    LIST_ENTRY      InInitializationOrderLinks;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
    ULONG           Flags;
    USHORT          LoadCount;
    USHORT          TlsIndex;
    LIST_ENTRY      HashLinks;
    ULONG           TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN       InheritedAddressSpace;
    BOOLEAN       ReadImageFileExecOptions;
    BOOLEAN       BeingDebugged;
    BOOLEAN       BitField;
    PVOID         Mutant;
    PVOID         ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID         ProcessParameters;
} PEB, *PPEB;

// NT exports not in standard headers

NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(
    _Out_    PHANDLE            ProcessHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID         ClientId
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_  HANDLE    ProcessId,
    _Out_ PEPROCESS *Process
);

NTKERNELAPI VOID KeAttachProcess(_In_ PEPROCESS Process);
NTKERNELAPI VOID KeDetachProcess(VOID);

NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
    _In_    HANDLE    ProcessHandle,
    _Inout_ PVOID    *BaseAddress,
    _In_    ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T   RegionSize,
    _In_    ULONG     AllocationType,
    _In_    ULONG     Protect
);

NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID  *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   FreeType
);

NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_     HANDLE         Handle,
    _In_     BOOLEAN        Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSYSAPI BOOLEAN NTAPI RtlAddFunctionTable(
    _In_ PRUNTIME_FUNCTION FunctionTable,
    _In_ ULONG             EntryCount,
    _In_ ULONG64           BaseAddress
);

// Dynamically resolved function pointers

typedef NTSTATUS (NTAPI *fn_MmCopyVirtualMemory)(
    PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T
);

typedef PPEB (NTAPI *fn_PsGetProcessPeb)(PEPROCESS);

typedef NTSTATUS (NTAPI *fn_ZwProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG
);

typedef NTSTATUS (NTAPI *fn_RtlCreateUserThread)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
    SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID
);

extern fn_MmCopyVirtualMemory    pfnMmCopyVirtualMemory;
extern fn_PsGetProcessPeb        pfnPsGetProcessPeb;
extern fn_ZwProtectVirtualMemory pfnZwProtectVirtualMemory;
extern fn_RtlCreateUserThread    pfnRtlCreateUserThread;

NTSTATUS ResolveDynamicImports(VOID);

// PE helpers

static __forceinline PIMAGE_NT_HEADERS64 RtlImageNtHeader(PVOID Base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)Base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return nt;
}

static __forceinline PIMAGE_SECTION_HEADER RtlFirstSection(PIMAGE_NT_HEADERS64 Nt) {
    return (PIMAGE_SECTION_HEADER)((ULONG_PTR)&Nt->OptionalHeader + Nt->FileHeader.SizeOfOptionalHeader);
}

// Injection flags — stored in SHARED_HEADER.Flags

#define INJ_FLAG_ERASE_HEADERS   0x01
#define INJ_FLAG_STOMP_HEADERS   0x02
#define INJ_FLAG_SKIP_TLS        0x04
#define INJ_FLAG_SKIP_EXCEPTIONS 0x08

// Internal API

NTSTATUS CreateSharedSection(VOID);
VOID     DestroySharedSection(VOID);

NTSTATUS PerformManualMap(
    _In_ ULONG  TargetPid,
    _In_ PVOID  RawDll,
    _In_ ULONG  DllSize,
    _In_ ULONG  Flags
);

NTSTATUS ValidatePeImage(_In_ PVOID RawDll, _In_ ULONG DllSize);

NTSTATUS MapSections(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PVOID               RawDll,
    _In_ PIMAGE_NT_HEADERS64 Nt
);

NTSTATUS ProcessRelocations(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt,
    _In_ ULONG_PTR           Delta
);

NTSTATUS ResolveImports(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt
);

NTSTATUS ResolveDelayImports(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt
);

NTSTATUS SetSectionProtections(
    _In_ HANDLE              ProcHandle,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt
);

NTSTATUS ExecuteTlsCallbacks(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt
);

NTSTATUS CallEntryPoint(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt
);

PVOID FindModuleBase(_In_ PEPROCESS Process, _In_ PCWSTR ModName);
PVOID FindExportSafe(_In_ PVOID ModBase, _In_ PCCH FuncName);
PVOID FindExportByOrdinal(_In_ PVOID ModBase, _In_ USHORT Ordinal);
PVOID ResolveForwardedExport(_In_ PEPROCESS Process, _In_ const char* ForwardStr);
