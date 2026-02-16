#pragma once

//=============================================================================
// Kernel Driver — Internal Header
//=============================================================================

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

// Pull in shared protocol
#include "../shared/protocol.h"

//-----------------------------------------------------------------------------
// Undocumented NT structures for PEB walking
//-----------------------------------------------------------------------------

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
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 BitField;
    PVOID                   Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LDR_DATA           Ldr;
    PVOID                   ProcessParameters;
    // ... remaining fields not needed for our purposes
} PEB, *PPEB;

//-----------------------------------------------------------------------------
// NT kernel function declarations (not in standard headers)
//-----------------------------------------------------------------------------

// KeStackAttachProcess, KeUnstackDetachProcess
// are provided by ntifs.h

// ZwOpenProcess
NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(
    _Out_    PHANDLE            ProcessHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID         ClientId
);

// PsLookupProcessByProcessId
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_  HANDLE    ProcessId,
    _Out_ PEPROCESS *Process
);

// KeAttachProcess / KeDetachProcess — for direct VA access
NTKERNELAPI VOID KeAttachProcess(_In_ PEPROCESS Process);
NTKERNELAPI VOID KeDetachProcess(VOID);

// ZwAllocateVirtualMemory — allocate in target process context
NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
    _In_    HANDLE   ProcessHandle,
    _Inout_ PVOID    *BaseAddress,
    _In_    ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T  RegionSize,
    _In_    ULONG    AllocationType,
    _In_    ULONG    Protect
);

// ZwFreeVirtualMemory
NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID   *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   FreeType
);

// ZwWaitForSingleObject
NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_     HANDLE         Handle,
    _In_     BOOLEAN        Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

//-----------------------------------------------------------------------------
// Dynamically resolved undocumented functions
// (not in ntoskrnl.lib — resolved via MmGetSystemRoutineAddress)
//-----------------------------------------------------------------------------

// Function pointer typedefs
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

// Global function pointers (set in DriverEntry)
extern fn_MmCopyVirtualMemory     pfnMmCopyVirtualMemory;
extern fn_PsGetProcessPeb         pfnPsGetProcessPeb;
extern fn_ZwProtectVirtualMemory  pfnZwProtectVirtualMemory;
extern fn_RtlCreateUserThread     pfnRtlCreateUserThread;

// Initialize all dynamic imports — call from DriverEntry
NTSTATUS ResolveDynamicImports(VOID);

//-----------------------------------------------------------------------------
// PE Parsing helpers
//-----------------------------------------------------------------------------

// Get the NT headers from a PE base
static __forceinline PIMAGE_NT_HEADERS64 RtlImageNtHeader(PVOID Base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)Base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return nt;
}

// Get first section header
static __forceinline PIMAGE_SECTION_HEADER RtlFirstSection(PIMAGE_NT_HEADERS64 Nt) {
    return (PIMAGE_SECTION_HEADER)((ULONG_PTR)&Nt->OptionalHeader + Nt->FileHeader.SizeOfOptionalHeader);
}

//-----------------------------------------------------------------------------
// Driver internal functions (implemented in driver.cpp)
//-----------------------------------------------------------------------------

// Shared memory section management
NTSTATUS CreateSharedSection(VOID);
VOID     DestroySharedSection(VOID);

// Main injection worker
NTSTATUS PerformManualMap(
    _In_ ULONG   TargetPid,
    _In_ PVOID   RawDll,
    _In_ ULONG   DllSize
);

// PE operations (all execute in kernel context, targeting remote process)
NTSTATUS ValidatePeImage(_In_ PVOID RawDll, _In_ ULONG DllSize);
NTSTATUS MapSections(_In_ PEPROCESS Process, _In_ PVOID AllocBase, _In_ PVOID RawDll, _In_ PIMAGE_NT_HEADERS64 Nt);
NTSTATUS ProcessRelocations(_In_ PEPROCESS Process, _In_ PVOID AllocBase, _In_ PIMAGE_NT_HEADERS64 Nt, _In_ ULONG_PTR Delta);
NTSTATUS ResolveImports(_In_ PEPROCESS Process, _In_ PVOID AllocBase, _In_ PIMAGE_NT_HEADERS64 Nt);
NTSTATUS SetSectionProtections(_In_ HANDLE ProcHandle, _In_ PVOID AllocBase, _In_ PIMAGE_NT_HEADERS64 Nt);
NTSTATUS CallEntryPoint(_In_ PEPROCESS Process, _In_ PVOID AllocBase, _In_ PIMAGE_NT_HEADERS64 Nt);

// Utility
PVOID GetModuleBaseInProcess(_In_ PEPROCESS Process, _In_ PUNICODE_STRING ModuleName);
PVOID GetExportAddress(_In_ PVOID ModuleBase, _In_ PCCH ExportName);
