/*
 * nanahira — Kernel Manual Map Injector
 * Driver: Ring-0 Manual Map Injection Engine
 *
 * Source: https://github.com/Kiy0w0/kernel-mmi
 *
 * All PE operations (parsing, section mapping, relocations, import
 * resolution, memory protection, DllMain call) happen in kernel space.
 * The usermode component only reads the DLL file and writes it to
 * shared memory — zero injection APIs from Ring 3.
 */

#include "driver.h"

//=============================================================================
// Globals
//=============================================================================

static HANDLE           g_SectionHandle  = NULL;
static PVOID            g_MappedView     = NULL;
static SIZE_T           g_ViewSize       = 0;
static HANDLE           g_WorkerThread   = NULL;
static volatile BOOLEAN g_Shutdown       = FALSE;
static SHARED_HEADER*   g_Header         = NULL;

// Dynamically resolved function pointers
fn_MmCopyVirtualMemory     pfnMmCopyVirtualMemory    = NULL;
fn_PsGetProcessPeb         pfnPsGetProcessPeb        = NULL;
fn_ZwProtectVirtualMemory  pfnZwProtectVirtualMemory = NULL;
fn_RtlCreateUserThread     pfnRtlCreateUserThread    = NULL;

NTSTATUS ResolveDynamicImports(VOID)
{
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, L"MmCopyVirtualMemory");
    pfnMmCopyVirtualMemory = (fn_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"PsGetProcessPeb");
    pfnPsGetProcessPeb = (fn_PsGetProcessPeb)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"ZwProtectVirtualMemory");
    pfnZwProtectVirtualMemory = (fn_ZwProtectVirtualMemory)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"RtlCreateUserThread");
    pfnRtlCreateUserThread = (fn_RtlCreateUserThread)MmGetSystemRoutineAddress(&name);

    if (!pfnMmCopyVirtualMemory || !pfnPsGetProcessPeb) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Critical dynamic imports failed!\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Dynamic imports resolved: MmCopy=%p PsGetPeb=%p ZwProtect=%p RtlCreate=%p\n",
        pfnMmCopyVirtualMemory, pfnPsGetProcessPeb,
        pfnZwProtectVirtualMemory, pfnRtlCreateUserThread);

    return STATUS_SUCCESS;
}

//=============================================================================
// Forward Declarations
//=============================================================================

static VOID   WorkerRoutine(_In_ PVOID Context);
static VOID   UpdateProgress(_In_ LONG Pct, _In_ const char* Msg);
static PVOID  FindModuleBase(_In_ PEPROCESS Process, _In_ PCWSTR ModName);
static PVOID  FindExport(_In_ PVOID ModBase, _In_ PCCH FuncName);
static NTSTATUS WriteToProcess(_In_ PEPROCESS Target, _In_ PVOID Dest, _In_ PVOID Src, _In_ SIZE_T Size);
static NTSTATUS ReadFromProcess(_In_ PEPROCESS Target, _In_ PVOID Src, _Out_ PVOID Dest, _In_ SIZE_T Size);

//=============================================================================
// Shared Section Management
//=============================================================================

NTSTATUS CreateSharedSection(VOID)
{
    NTSTATUS            status;
    UNICODE_STRING      sectionName;
    OBJECT_ATTRIBUTES   objAttr;
    LARGE_INTEGER       maxSize;

    // Create a security descriptor with NULL DACL (allows usermode access)
    SECURITY_DESCRIPTOR sd;
    status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] RtlCreateSecurityDescriptor failed: 0x%08X\n", status);
        return status;
    }

    // Set NULL DACL = everyone has full access
    status = RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] RtlSetDaclSecurityDescriptor failed: 0x%08X\n", status);
        return status;
    }

    RtlInitUnicodeString(&sectionName, KM_SECTION_PATH);
    InitializeObjectAttributes(&objAttr, &sectionName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sd);

    maxSize.QuadPart = SHM_TOTAL_SIZE;

    status = ZwCreateSection(
        &g_SectionHandle,
        SECTION_ALL_ACCESS,
        &objAttr,
        &maxSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] ZwCreateSection failed: 0x%08X\n", status);
        return status;
    }

    g_ViewSize = SHM_TOTAL_SIZE;
    status = ZwMapViewOfSection(
        g_SectionHandle,
        ZwCurrentProcess(),
        &g_MappedView,
        0, 0, NULL,
        &g_ViewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] ZwMapViewOfSection failed: 0x%08X\n", status);
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    // Initialize header
    RtlZeroMemory(g_MappedView, SHM_TOTAL_SIZE);
    g_Header = (SHARED_HEADER*)g_MappedView;
    g_Header->Magic   = PROTO_MAGIC;
    g_Header->Version = (PROTO_VER_MAJOR << 16) | PROTO_VER_MINOR;
    InterlockedExchange(&g_Header->Status, IPC_READY);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Shared section created at %p, size=%llu\n",
        g_MappedView, (ULONGLONG)g_ViewSize);

    return STATUS_SUCCESS;
}

VOID DestroySharedSection(VOID)
{
    if (g_MappedView) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), g_MappedView);
        g_MappedView = NULL;
    }
    if (g_SectionHandle) {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
    }
    g_Header = NULL;
}

//=============================================================================
// Progress Reporting
//=============================================================================

static VOID UpdateProgress(_In_ LONG Pct, _In_ const char* Msg)
{
    if (!g_Header) return;
    InterlockedExchange(&g_Header->Progress, Pct);

    // Safe string copy
    SIZE_T len = 0;
    const char* p = Msg;
    while (*p && len < sizeof(g_Header->Message) - 1) {
        g_Header->Message[len++] = *p++;
    }
    g_Header->Message[len] = '\0';

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] [%3ld%%] %s\n", Pct, Msg);
}

//=============================================================================
// Process Memory R/W via MmCopyVirtualMemory
//=============================================================================

static NTSTATUS WriteToProcess(
    _In_ PEPROCESS Target,
    _In_ PVOID     Dest,
    _In_ PVOID     Src,
    _In_ SIZE_T    Size)
{
    SIZE_T bytes = 0;
    if (!pfnMmCopyVirtualMemory) return STATUS_PROCEDURE_NOT_FOUND;
    return pfnMmCopyVirtualMemory(
        PsGetCurrentProcess(), Src,
        Target,                Dest,
        Size,
        KernelMode,
        &bytes
    );
}

static NTSTATUS ReadFromProcess(
    _In_  PEPROCESS Target,
    _In_  PVOID     Src,
    _Out_ PVOID     Dest,
    _In_  SIZE_T    Size)
{
    SIZE_T bytes = 0;
    if (!pfnMmCopyVirtualMemory) return STATUS_PROCEDURE_NOT_FOUND;
    return pfnMmCopyVirtualMemory(
        Target,                Src,
        PsGetCurrentProcess(), Dest,
        Size,
        KernelMode,
        &bytes
    );
}

//=============================================================================
// PE Validation
//=============================================================================

NTSTATUS ValidatePeImage(_In_ PVOID RawDll, _In_ ULONG DllSize)
{
    if (DllSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] PE too small: %u bytes\n", DllSize);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)RawDll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Invalid DOS signature: 0x%04X\n", dos->e_magic);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > DllSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)RawDll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Invalid NT signature: 0x%08X\n", nt->Signature);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Not x64 PE: machine=0x%04X\n", nt->FileHeader.Machine);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] PE is not a DLL\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// Section Mapping — Copy PE sections to allocated memory in target process
//=============================================================================

NTSTATUS MapSections(
    _In_ PEPROCESS          Process,
    _In_ PVOID              AllocBase,
    _In_ PVOID              RawDll,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    NTSTATUS status;

    // 1. Copy PE headers
    status = WriteToProcess(Process, AllocBase, RawDll,
        Nt->OptionalHeader.SizeOfHeaders);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to write headers: 0x%08X\n", status);
        return status;
    }

    // 2. Copy each section
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(Nt);
    for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; i++, sec++) {

        if (sec->SizeOfRawData == 0)
            continue;  // BSS or uninitialized — will be zeroed by allocation

        PVOID dst = (PVOID)((ULONG_PTR)AllocBase + sec->VirtualAddress);
        PVOID src = (PVOID)((ULONG_PTR)RawDll + sec->PointerToRawData);

        status = WriteToProcess(Process, dst, src, sec->SizeOfRawData);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[drv] Failed to map section[%u] '%.8s': 0x%08X\n",
                i, sec->Name, status);
            return status;
        }

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
            "[drv] Mapped section '%.8s' -> %p (size=0x%X)\n",
            sec->Name, dst, sec->SizeOfRawData);
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// Base Relocations
//=============================================================================

NTSTATUS ProcessRelocations(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt,
    _In_ ULONG_PTR           Delta)
{
    if (Delta == 0)
        return STATUS_SUCCESS;  // Loaded at preferred base, no relocs needed

    ULONG relocRva  = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    ULONG relocSize = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRva == 0 || relocSize == 0) {
        // No relocations — if delta != 0, this is a problem
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[drv] No relocation table but delta=0x%llX\n", (ULONGLONG)Delta);
        return STATUS_SUCCESS;
    }

    // We need to read the relocation data from the target process
    // since we already mapped sections there. Alternatively, we can
    // process from the raw DLL before mapping.
    // Here we allocate a kernel buffer and read back from target.

    PVOID relocBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, relocSize, DRV_POOL_TAG);
    if (!relocBuf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ReadFromProcess(
        Process,
        (PVOID)((ULONG_PTR)AllocBase + relocRva),
        relocBuf,
        relocSize
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(relocBuf, DRV_POOL_TAG);
        return status;
    }

    // Walk relocation blocks
    PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)relocBuf;
    ULONG processed = 0;

    while (processed < relocSize && block->SizeOfBlock > 0) {
        ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PUSHORT entries = (PUSHORT)((ULONG_PTR)block + sizeof(IMAGE_BASE_RELOCATION));

        for (ULONG i = 0; i < count; i++) {
            USHORT type   = entries[i] >> 12;
            USHORT offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                // Read the 8-byte value, add delta, write back
                ULONG_PTR patchAddr = (ULONG_PTR)AllocBase + block->VirtualAddress + offset;
                ULONG_PTR value = 0;

                status = ReadFromProcess(Process, (PVOID)patchAddr, &value, sizeof(value));
                if (!NT_SUCCESS(status)) continue;

                value += Delta;

                status = WriteToProcess(Process, (PVOID)patchAddr, &value, sizeof(value));
                if (!NT_SUCCESS(status)) continue;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW) {
                ULONG_PTR patchAddr = (ULONG_PTR)AllocBase + block->VirtualAddress + offset;
                ULONG value = 0;

                status = ReadFromProcess(Process, (PVOID)patchAddr, &value, sizeof(value));
                if (!NT_SUCCESS(status)) continue;

                value += (ULONG)Delta;

                status = WriteToProcess(Process, (PVOID)patchAddr, &value, sizeof(value));
                if (!NT_SUCCESS(status)) continue;
            }
            else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // Padding, skip
            }
        }

        processed += block->SizeOfBlock;
        block = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)block + block->SizeOfBlock);
    }

    ExFreePoolWithTag(relocBuf, DRV_POOL_TAG);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Relocations applied, delta=0x%llX\n", (ULONGLONG)Delta);

    return STATUS_SUCCESS;
}

//=============================================================================
// Module & Export Lookup (PEB walking)
//=============================================================================

// Walk the target process PEB to find a loaded module
static PVOID FindModuleBase(_In_ PEPROCESS Process, _In_ PCWSTR ModName)
{
    PVOID result = NULL;
    KAPC_STATE apcState;

    KeStackAttachProcess(Process, &apcState);

    __try {
        // Access PEB
        PPEB peb = pfnPsGetProcessPeb ? pfnPsGetProcessPeb(Process) : NULL;
        if (!peb) __leave;

        PPEB_LDR_DATA ldr = peb->Ldr;
        if (!ldr) __leave;

        // Walk InLoadOrderModuleList
        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY entry = head->Flink;

        while (entry != head) {
            PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (mod->BaseDllName.Buffer) {
                // Case-insensitive compare
                UNICODE_STRING target;
                RtlInitUnicodeString(&target, ModName);

                if (RtlCompareUnicodeString(&mod->BaseDllName, &target, TRUE) == 0) {
                    result = mod->DllBase;
                    __leave;
                }
            }

            entry = entry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = NULL;
    }

    KeUnstackDetachProcess(&apcState);
    return result;
}

PVOID FindExportSafe(_In_ PVOID ModBase, _In_ PCCH FuncName)
{
    PVOID result = NULL;
    __try {
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS64 nt;

        RtlCopyMemory(&dos, ModBase, sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) __leave;

        RtlCopyMemory(&nt, (PVOID)((ULONG_PTR)ModBase + dos.e_lfanew), sizeof(nt));
        if (nt.Signature != IMAGE_NT_SIGNATURE) __leave;

        ULONG exportRva  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exportRva) __leave;

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ModBase + exportRva);
        PULONG  nameRvas = (PULONG) ((ULONG_PTR)ModBase + exp->AddressOfNames);
        PUSHORT ordinals = (PUSHORT)((ULONG_PTR)ModBase + exp->AddressOfNameOrdinals);
        PULONG  funcRvas = (PULONG) ((ULONG_PTR)ModBase + exp->AddressOfFunctions);

        for (ULONG i = 0; i < exp->NumberOfNames; i++) {
            char* name = (char*)((ULONG_PTR)ModBase + nameRvas[i]);
            const char* a = name, *b = FuncName;
            BOOLEAN match = TRUE;
            while (*a && *b) { if (*a++ != *b++) { match = FALSE; break; } }
            if (!match || *a != *b) continue;

            ULONG fRva = funcRvas[ordinals[i]];
            if (fRva >= exportRva && fRva < exportRva + exportSize) continue;
            result = (PVOID)((ULONG_PTR)ModBase + fRva);
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { result = NULL; }
    return result;
}

PVOID FindExportByOrdinal(_In_ PVOID ModBase, _In_ USHORT Ordinal)
{
    PVOID result = NULL;
    __try {
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS64 nt;

        RtlCopyMemory(&dos, ModBase, sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) __leave;

        RtlCopyMemory(&nt, (PVOID)((ULONG_PTR)ModBase + dos.e_lfanew), sizeof(nt));
        if (nt.Signature != IMAGE_NT_SIGNATURE) __leave;

        ULONG exportRva  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exportRva) __leave;

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ModBase + exportRva);
        ULONG idx = (ULONG)(Ordinal - (USHORT)exp->Base);
        if (idx >= exp->NumberOfFunctions) __leave;

        PULONG funcRvas = (PULONG)((ULONG_PTR)ModBase + exp->AddressOfFunctions);
        ULONG fRva = funcRvas[idx];
        if (!fRva || (fRva >= exportRva && fRva < exportRva + exportSize)) __leave;
        result = (PVOID)((ULONG_PTR)ModBase + fRva);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { result = NULL; }
    return result;
}

PVOID ResolveForwardedExport(_In_ PEPROCESS Process, _In_ const char* ForwardStr)
{
    char modName[128] = { 0 };
    const char* dot = NULL;
    for (const char* p = ForwardStr; *p; p++) {
        if (*p == '.') { dot = p; break; }
    }
    if (!dot) return NULL;

    SIZE_T modLen = (SIZE_T)(dot - ForwardStr);
    if (modLen >= 120) return NULL;

    RtlCopyMemory(modName, ForwardStr, modLen);
    RtlCopyMemory(modName + modLen, ".dll", 5);

    WCHAR wMod[128] = { 0 };
    for (SIZE_T i = 0; i < modLen + 4 && modName[i]; i++)
        wMod[i] = (WCHAR)modName[i];

    PVOID modBase = FindModuleBase(Process, wMod);
    if (!modBase) return NULL;

    const char* funcName = dot + 1;
    if (funcName[0] == '#') {
        ULONG ord = 0;
        RtlCharToInteger(funcName + 1, 10, &ord);
        return FindExportByOrdinal(modBase, (USHORT)ord);
    }
    return FindExportSafe(modBase, funcName);
}

NTSTATUS ResolveImports(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    ULONG importRva  = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ULONG importSize = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (!importRva || !importSize) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[drv] No imports\n");
        return STATUS_SUCCESS;
    }

    ULONG bufSize = importSize + 4096;
    PVOID importBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, DRV_POOL_TAG);
    if (!importBuf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ReadFromProcess(
        Process,
        (PVOID)((ULONG_PTR)AllocBase + importRva),
        importBuf,
        importSize
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(importBuf, DRV_POOL_TAG);
        return status;
    }

    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)importBuf;

    while (desc->Name) {
        char modNameBuf[256] = { 0 };
        ReadFromProcess(Process, (PVOID)((ULONG_PTR)AllocBase + desc->Name), modNameBuf, 255);

        WCHAR wModName[256] = { 0 };
        for (int j = 0; j < 255 && modNameBuf[j]; j++)
            wModName[j] = (WCHAR)modNameBuf[j];

        // FindModuleBase does its own attach/detach — safe to call outside any attach context
        PVOID modBase = FindModuleBase(Process, wModName);

        if (!modBase) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[drv] Import module not found: %ls\n", wModName);
            desc++;
            continue;
        }

        // Attach once, walk all thunks for this module, then detach
        KAPC_STATE apc;
        KeStackAttachProcess(Process, &apc);
        __try {
            ULONG_PTR thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            PIMAGE_THUNK_DATA64 orig  = (PIMAGE_THUNK_DATA64)((ULONG_PTR)AllocBase + thunkRva);
            PIMAGE_THUNK_DATA64 first = (PIMAGE_THUNK_DATA64)((ULONG_PTR)AllocBase + desc->FirstThunk);

            while (orig->u1.AddressOfData) {
                PVOID funcAddr = NULL;

                if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal)) {
                    USHORT ordinal = IMAGE_ORDINAL64(orig->u1.Ordinal);
                    funcAddr = FindExportByOrdinal(modBase, ordinal);
                } else {
                    PIMAGE_IMPORT_BY_NAME hint =
                        (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)AllocBase + orig->u1.AddressOfData);
                    funcAddr = FindExportSafe(modBase, (PCCH)hint->Name);
                }

                if (funcAddr)
                    first->u1.Function = (ULONG_PTR)funcAddr;
                else
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                        "[drv] Unresolved import in %ls\n", wModName);

                orig++;
                first++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[drv] Exception in thunk walk for %ls\n", wModName);
        }
        KeUnstackDetachProcess(&apc);

        desc++;
    }

    ExFreePoolWithTag(importBuf, DRV_POOL_TAG);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[drv] Imports resolved\n");
    return STATUS_SUCCESS;
}

//=============================================================================
// Import Resolution
//=============================================================================

NTSTATUS ResolveImports(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    ULONG importRva  = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ULONG importSize = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (importRva == 0 || importSize == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[drv] No imports to resolve\n");
        return STATUS_SUCCESS;
    }

    // Read the import directory from target
    ULONG bufSize = importSize + 4096;  // Extra for safety
    PVOID importBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, DRV_POOL_TAG);
    if (!importBuf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ReadFromProcess(
        Process,
        (PVOID)((ULONG_PTR)AllocBase + importRva),
        importBuf,
        importSize
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(importBuf, DRV_POOL_TAG);
        return status;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)importBuf;

    KAPC_STATE apcState;
    KeStackAttachProcess(Process, &apcState);

    __try {
        while (importDesc->Name) {
            // Read module name from target process memory
            char* modName = (char*)((ULONG_PTR)AllocBase + importDesc->Name);

            // Convert to wide string for FindModuleBase
            WCHAR wModName[256] = { 0 };
            for (int j = 0; j < 255 && modName[j]; j++) {
                wModName[j] = (WCHAR)modName[j];
            }

            // Temporarily detach to call FindModuleBase (it does its own attach)
            KeUnstackDetachProcess(&apcState);

            PVOID modBase = FindModuleBase(Process, wModName);
            if (!modBase) {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                    "[drv] Module not found: %ls\n", wModName);
                
                // Re-attach and continue
                KeStackAttachProcess(Process, &apcState);
                importDesc++;
                continue;
            }

            // Re-attach
            KeStackAttachProcess(Process, &apcState);

            // Walk the thunk array
            ULONG_PTR thunkRva = importDesc->OriginalFirstThunk ?
                importDesc->OriginalFirstThunk : importDesc->FirstThunk;

            PIMAGE_THUNK_DATA64 origThunk = (PIMAGE_THUNK_DATA64)((ULONG_PTR)AllocBase + thunkRva);
            PIMAGE_THUNK_DATA64 firstThunk = (PIMAGE_THUNK_DATA64)((ULONG_PTR)AllocBase + importDesc->FirstThunk);

            while (origThunk->u1.AddressOfData) {
                PVOID funcAddr = NULL;

                if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) {
                    // Import by ordinal — not commonly used, skip for safety
                    origThunk++;
                    firstThunk++;
                    continue;
                }
                else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME hint =
                        (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)AllocBase + origThunk->u1.AddressOfData);

                    funcAddr = FindExport(modBase, (PCCH)hint->Name);
                }

                if (funcAddr) {
                    firstThunk->u1.Function = (ULONG_PTR)funcAddr;
                }

                origThunk++;
                firstThunk++;
            }

            importDesc++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&apcState);
        ExFreePoolWithTag(importBuf, DRV_POOL_TAG);
        return STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&apcState);
    ExFreePoolWithTag(importBuf, DRV_POOL_TAG);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Imports resolved\n");

    return STATUS_SUCCESS;
}

//=============================================================================
// Set Section Memory Protections
//=============================================================================

NTSTATUS SetSectionProtections(
    _In_ HANDLE              ProcHandle,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(Nt);
    NTSTATUS status;

    for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; i++, sec++) {
        ULONG protect = PAGE_NOACCESS;
        ULONG chars = sec->Characteristics;

        BOOLEAN exec  = !!(chars & IMAGE_SCN_MEM_EXECUTE);
        BOOLEAN read  = !!(chars & IMAGE_SCN_MEM_READ);
        BOOLEAN write = !!(chars & IMAGE_SCN_MEM_WRITE);

        if (exec && write)      protect = PAGE_EXECUTE_READWRITE;
        else if (exec && read)  protect = PAGE_EXECUTE_READ;
        else if (exec)          protect = PAGE_EXECUTE;
        else if (write)         protect = PAGE_READWRITE;
        else if (read)          protect = PAGE_READONLY;

        PVOID base = (PVOID)((ULONG_PTR)AllocBase + sec->VirtualAddress);
        SIZE_T size = sec->Misc.VirtualSize;
        ULONG oldProtect;

        if (size == 0) continue;

        if (!pfnZwProtectVirtualMemory) continue;
        status = pfnZwProtectVirtualMemory(ProcHandle, &base, &size, protect, &oldProtect);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[drv] ZwProtectVirtualMemory for '%.8s' failed: 0x%08X\n",
                sec->Name, status);
            // Non-fatal, continue
        }
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// Call DllMain via shellcode
//
// We inject a small stub that calls DllMain(hModule, DLL_PROCESS_ATTACH, 0)
// and then returns. We create a thread in the target process to execute it.
//=============================================================================

// x64 shellcode template for calling DllMain
// Registers: RCX = hModule, RDX = DLL_PROCESS_ATTACH (1), R8 = 0
// sub rsp, 28h          ; shadow space
// mov rcx, <hModule>    ; 10 bytes
// mov rdx, 1            ; DLL_PROCESS_ATTACH
// xor r8, r8            ; lpvReserved = NULL
// mov rax, <EntryPoint> ; 10 bytes
// call rax
// add rsp, 28h
// ret

static const UCHAR g_ShellcodeTemplate[] = {
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, <hModule>
    0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,       // mov rdx, 1
    0x4D, 0x31, 0xC0,                                // xor r8, r8
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <EntryPoint>
    0xFF, 0xD0,                                       // call rax
    0x48, 0x83, 0xC4, 0x28,                          // add rsp, 0x28
    0xC3                                              // ret
};

#define SHELLCODE_HMODULE_OFFSET  6
#define SHELLCODE_ENTRY_OFFSET    25
#define SHELLCODE_SIZE            sizeof(g_ShellcodeTemplate)

NTSTATUS CallEntryPoint(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    NTSTATUS status;

    ULONG_PTR entryRva = Nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRva == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[drv] No entry point, skipping DllMain call\n");
        return STATUS_SUCCESS;
    }

    ULONG_PTR entryPoint = (ULONG_PTR)AllocBase + entryRva;
    ULONG_PTR hModule    = (ULONG_PTR)AllocBase;

    // Build shellcode
    UCHAR shellcode[SHELLCODE_SIZE];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate, SHELLCODE_SIZE);

    // Patch in hModule
    *(ULONG_PTR*)(shellcode + SHELLCODE_HMODULE_OFFSET) = hModule;
    // Patch in entry point
    *(ULONG_PTR*)(shellcode + SHELLCODE_ENTRY_OFFSET) = entryPoint;

    // Allocate executable memory in target for shellcode
    HANDLE procHandle = NULL;
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    clientId.UniqueProcess = PsGetProcessId(Process);

    status = ZwOpenProcess(&procHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] ZwOpenProcess for thread creation failed: 0x%08X\n", status);
        return status;
    }

    PVOID scBase = NULL;
    SIZE_T scSize = SHELLCODE_SIZE;

    status = ZwAllocateVirtualMemory(procHandle, &scBase, 0, &scSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status)) {
        ZwClose(procHandle);
        return status;
    }

    // Write shellcode
    status = WriteToProcess(Process, scBase, shellcode, SHELLCODE_SIZE);
    if (!NT_SUCCESS(status)) {
        ZwFreeVirtualMemory(procHandle, &scBase, &scSize, MEM_RELEASE);
        ZwClose(procHandle);
        return status;
    }

    // Create thread to execute shellcode
    HANDLE threadHandle = NULL;
    if (!pfnRtlCreateUserThread) {
        ZwFreeVirtualMemory(procHandle, &scBase, &scSize, MEM_RELEASE);
        ZwClose(procHandle);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = pfnRtlCreateUserThread(
        procHandle,
        NULL,       // SecurityDescriptor
        FALSE,      // CreateSuspended
        0,          // StackZeroBits
        0,          // StackReserve
        0,          // StackCommit
        scBase,     // StartAddress
        NULL,       // Parameter
        &threadHandle,
        NULL
    );

    if (NT_SUCCESS(status) && threadHandle) {
        // Wait for thread to finish (max 5 seconds)
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;  // 5 seconds relative
        ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
        ZwClose(threadHandle);
    }
    else {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] RtlCreateUserThread failed: 0x%08X\n", status);
    }

    // Free shellcode memory
    ZwFreeVirtualMemory(procHandle, &scBase, &scSize, MEM_RELEASE);
    ZwClose(procHandle);

    return status;
}

// TLS callback typedef as used by the OS
typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, ULONG Reason, PVOID Reserved);

NTSTATUS ExecuteTlsCallbacks(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    ULONG tlsRva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (!tlsRva) return STATUS_SUCCESS;

    IMAGE_TLS_DIRECTORY64 tlsDir = { 0 };
    NTSTATUS status = ReadFromProcess(
        Process,
        (PVOID)((ULONG_PTR)AllocBase + tlsRva),
        &tlsDir,
        sizeof(tlsDir)
    );
    if (!NT_SUCCESS(status)) return status;

    // AddressOfCallBacks is a VA in the loaded image pointing to a null-terminated array
    if (!tlsDir.AddressOfCallBacks) return STATUS_SUCCESS;

    // Read up to 64 callback pointers
    ULONG_PTR callbacks[64] = { 0 };
    ReadFromProcess(
        Process,
        (PVOID)tlsDir.AddressOfCallBacks,
        callbacks,
        sizeof(callbacks)
    );

    for (int i = 0; i < 64 && callbacks[i]; i++) {
        ULONG_PTR cbVa = callbacks[i];

        // Build a tiny shellcode to call: callback(AllocBase, DLL_PROCESS_ATTACH, 0)
        UCHAR sc[40];
        RtlCopyMemory(sc, g_ShellcodeTemplate, sizeof(sc) < SHELLCODE_SIZE ? sizeof(sc) : SHELLCODE_SIZE);
        *(ULONG_PTR*)(sc + SHELLCODE_HMODULE_OFFSET) = (ULONG_PTR)AllocBase;
        *(ULONG_PTR*)(sc + SHELLCODE_ENTRY_OFFSET)   = cbVa;

        HANDLE procHandle = NULL;
        CLIENT_ID cid = { 0 };
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = PsGetProcessId(Process);

        if (!NT_SUCCESS(ZwOpenProcess(&procHandle, PROCESS_ALL_ACCESS, &oa, &cid)))
            continue;

        PVOID scBase = NULL;
        SIZE_T scSize = SHELLCODE_SIZE;
        if (NT_SUCCESS(ZwAllocateVirtualMemory(procHandle, &scBase, 0, &scSize,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
            WriteToProcess(Process, scBase, sc, SHELLCODE_SIZE);

            if (pfnRtlCreateUserThread) {
                HANDLE thr = NULL;
                if (NT_SUCCESS(pfnRtlCreateUserThread(procHandle, NULL, FALSE, 0, 0, 0,
                                                       scBase, NULL, &thr, NULL))) {
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -30000000LL; // 3s
                    ZwWaitForSingleObject(thr, FALSE, &timeout);
                    ZwClose(thr);
                }
            }
            ZwFreeVirtualMemory(procHandle, &scBase, &scSize, MEM_RELEASE);
        }
        ZwClose(procHandle);

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[drv] TLS callback[%d] at %p executed\n", i, (PVOID)cbVa);
    }

    return STATUS_SUCCESS;
}

NTSTATUS ResolveDelayImports(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    ULONG delayRva  = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    ULONG delaySize = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;

    if (!delayRva || !delaySize) return STATUS_SUCCESS;

    // IMAGE_DELAYLOAD_DESCRIPTOR layout
    typedef struct _DELAY_IMPORT_DESC {
        ULONG  Attributes;
        ULONG  DllNameRVA;
        ULONG  ModuleHandleRVA;
        ULONG  ImportAddressTableRVA;
        ULONG  ImportNameTableRVA;
        ULONG  BoundImportAddressTableRVA;
        ULONG  UnloadInformationTableRVA;
        ULONG  TimeDateStamp;
    } DELAY_IMPORT_DESC;

    ULONG bufSize = delaySize + sizeof(DELAY_IMPORT_DESC);
    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, DRV_POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ReadFromProcess(
        Process,
        (PVOID)((ULONG_PTR)AllocBase + delayRva),
        buf,
        delaySize
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, DRV_POOL_TAG);
        return status;
    }

    DELAY_IMPORT_DESC* desc = (DELAY_IMPORT_DESC*)buf;

    while (desc->DllNameRVA) {
        char modNameBuf[256] = { 0 };
        ReadFromProcess(Process, (PVOID)((ULONG_PTR)AllocBase + desc->DllNameRVA), modNameBuf, 255);

        WCHAR wMod[256] = { 0 };
        for (int j = 0; j < 255 && modNameBuf[j]; j++)
            wMod[j] = (WCHAR)modNameBuf[j];

        PVOID modBase = FindModuleBase(Process, wMod);

        if (modBase && desc->ImportAddressTableRVA && desc->ImportNameTableRVA) {
            KAPC_STATE apc;
            KeStackAttachProcess(Process, &apc);
            __try {
                PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)((ULONG_PTR)AllocBase + desc->ImportAddressTableRVA);
                PIMAGE_THUNK_DATA64 int_ = (PIMAGE_THUNK_DATA64)((ULONG_PTR)AllocBase + desc->ImportNameTableRVA);

                while (int_->u1.AddressOfData) {
                    PVOID fn = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL64(int_->u1.Ordinal))
                        fn = FindExportByOrdinal(modBase, IMAGE_ORDINAL64(int_->u1.Ordinal));
                    else {
                        PIMAGE_IMPORT_BY_NAME hint =
                            (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)AllocBase + int_->u1.AddressOfData);
                        fn = FindExportSafe(modBase, (PCCH)hint->Name);
                    }
                    if (fn) iat->u1.Function = (ULONG_PTR)fn;
                    iat++;
                    int_++;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            KeUnstackDetachProcess(&apc);
        }

        desc++;
    }

    ExFreePoolWithTag(buf, DRV_POOL_TAG);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[drv] Delay imports resolved\n");
    return STATUS_SUCCESS;
}

NTSTATUS PerformManualMap(
    _In_ ULONG TargetPid,
    _In_ PVOID RawDll,
    _In_ ULONG DllSize,
    _In_ ULONG Flags)
{

    NTSTATUS    status;
    PEPROCESS   process     = NULL;
    HANDLE      procHandle  = NULL;
    PVOID       allocBase   = NULL;
    SIZE_T      allocSize   = 0;

    UpdateProgress(5, "Validating PE image...");

    status = ValidatePeImage(RawDll, DllSize);
    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Invalid PE format");
        return status;
    }

    PIMAGE_NT_HEADERS64 nt = RtlImageNtHeader(RawDll);
    if (!nt) {
        UpdateProgress(0, "Failed to parse PE headers");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    allocSize = nt->OptionalHeader.SizeOfImage;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] PE validated: ImageSize=0x%llX, Entry=0x%X, Sections=%u Flags=0x%X\n",
        (ULONGLONG)allocSize, nt->OptionalHeader.AddressOfEntryPoint,
        nt->FileHeader.NumberOfSections, Flags);

    UpdateProgress(10, "Attaching to target process...");

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Target process not found");
        return status;
    }

    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)TargetPid;

    status = ZwOpenProcess(&procHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Failed to open process");
        ObDereferenceObject(process);
        return status;
    }

    UpdateProgress(20, "Allocating memory in target...");

    status = ZwAllocateVirtualMemory(
        procHandle,
        &allocBase,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Memory allocation failed");
        ZwClose(procHandle);
        ObDereferenceObject(process);
        return status;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Allocated 0x%llX bytes at %p in PID %u\n",
        (ULONGLONG)allocSize, allocBase, TargetPid);

    UpdateProgress(35, "Mapping PE sections...");

    status = MapSections(process, allocBase, RawDll, nt);
    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Section mapping failed");
        goto Cleanup;
    }

    UpdateProgress(50, "Processing relocations...");

    ULONG_PTR delta = (ULONG_PTR)allocBase - nt->OptionalHeader.ImageBase;
    status = ProcessRelocations(process, allocBase, nt, delta);
    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Relocation processing failed");
        goto Cleanup;
    }

    UpdateProgress(60, "Resolving imports...");

    status = ResolveImports(process, allocBase, nt);
    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Import resolution failed");
        goto Cleanup;
    }

    UpdateProgress(68, "Resolving delay imports...");

    ResolveDelayImports(process, allocBase, nt);

    UpdateProgress(75, "Setting memory protections...");

    SetSectionProtections(procHandle, allocBase, nt);

    if (!(Flags & INJ_FLAG_SKIP_EXCEPTIONS)) {
        UpdateProgress(80, "Registering exception handlers...");
        ULONG pdataRva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        ULONG pdataSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        if (pdataRva && pdataSize) {
            PRUNTIME_FUNCTION pdata = (PRUNTIME_FUNCTION)((ULONG_PTR)allocBase + pdataRva);
            ULONG count = pdataSize / sizeof(RUNTIME_FUNCTION);
            RtlAddFunctionTable(pdata, count, (ULONG64)allocBase);
        }
    }

    if (!(Flags & INJ_FLAG_SKIP_TLS)) {
        UpdateProgress(83, "Executing TLS callbacks...");
        ExecuteTlsCallbacks(process, allocBase, nt);
    }

    UpdateProgress(87, "Cleaning up PE headers...");
    {
        SIZE_T headerSize = nt->OptionalHeader.SizeOfHeaders;

        if (Flags & INJ_FLAG_STOMP_HEADERS) {
            PVOID stompBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, headerSize, DRV_POOL_TAG);
            if (stompBuf) {
                // Fill with pseudo-random junk using a simple LFSR
                ULONG lfsr = 0xDEADBEEF;
                PULONG p = (PULONG)stompBuf;
                for (SIZE_T i = 0; i < headerSize / sizeof(ULONG); i++) {
                    lfsr ^= lfsr << 13;
                    lfsr ^= lfsr >> 17;
                    lfsr ^= lfsr << 5;
                    p[i] = lfsr;
                }
                WriteToProcess(process, allocBase, stompBuf, headerSize);
                ExFreePoolWithTag(stompBuf, DRV_POOL_TAG);
            }
        } else if (Flags & INJ_FLAG_ERASE_HEADERS) {
            PVOID zeros = ExAllocatePool2(POOL_FLAG_NON_PAGED, headerSize, DRV_POOL_TAG);
            if (zeros) {
                RtlZeroMemory(zeros, headerSize);
                WriteToProcess(process, allocBase, zeros, headerSize);
                ExFreePoolWithTag(zeros, DRV_POOL_TAG);
            }
        }
    }

    UpdateProgress(92, "Calling entry point...");

    status = CallEntryPoint(process, allocBase, nt);
    if (!NT_SUCCESS(status)) {
        UpdateProgress(0, "Entry point execution failed");
        goto Cleanup;
    }

    UpdateProgress(100, "Injection complete");

    if (g_Header)
        g_Header->BaseAddr = (ULONGLONG)(ULONG_PTR)allocBase;

    ZwClose(procHandle);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;

Cleanup:
    if (allocBase && procHandle) {
        allocSize = 0;
        ZwFreeVirtualMemory(procHandle, &allocBase, &allocSize, MEM_RELEASE);
    }
    if (procHandle) ZwClose(procHandle);
    if (process) ObDereferenceObject(process);
    return status;
}

static VOID WorkerRoutine(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[drv] Worker thread started\n");

    while (!g_Shutdown) {
        if (!g_Header) break;

        LONG cmd = InterlockedExchange(&g_Header->Command, IPC_CMD_NONE);

        switch (cmd) {
        case IPC_CMD_INJECT:
        {
            InterlockedExchange(&g_Header->Status, IPC_BUSY);

            ULONG pid   = g_Header->TargetPid;
            ULONG size  = g_Header->PayloadSize;
            ULONG flags = g_Header->Flags;

            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[drv] Inject: PID=%u size=%u flags=0x%X\n", pid, size, flags);

            if (size == 0 || size > MAX_PAYLOAD_SIZE) {
                UpdateProgress(0, "Invalid payload size");
                InterlockedExchange(&g_Header->Status, IPC_ERR_PE);
                break;
            }

            PVOID dllData = (PVOID)((ULONG_PTR)g_MappedView + PAYLOAD_DATA_OFFSET);
            NTSTATUS result = PerformManualMap(pid, dllData, size, flags);

            if (NT_SUCCESS(result)) {
                InterlockedExchange(&g_Header->Status, IPC_DONE);
            } else {
                LONG errCode = IPC_ERR_UNKNOWN;
                if (result == STATUS_INVALID_IMAGE_FORMAT) errCode = IPC_ERR_PE;
                else if (result == STATUS_INSUFFICIENT_RESOURCES) errCode = IPC_ERR_ALLOC;
                else if (result == STATUS_ACCESS_VIOLATION)       errCode = IPC_ERR_IMPORTS;
                InterlockedExchange(&g_Header->Status, errCode);
            }
            break;
        }

        case IPC_CMD_PING:
            InterlockedExchange(&g_Header->Status, IPC_READY);
            break;

        case IPC_CMD_STATUS:
            // Usermode queries current driver state — re-affirm READY if idle
            if (InterlockedCompareExchange(&g_Header->Status, IPC_READY, IPC_IDLE) == IPC_IDLE)
                InterlockedExchange(&g_Header->Status, IPC_READY);
            break;

        case IPC_CMD_CLEANUP:
            g_Shutdown = TRUE;
            break;

        case IPC_CMD_NONE:
        default:
            break;
        }

        LARGE_INTEGER interval;
        interval.QuadPart = -100000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[drv] Worker thread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

//=============================================================================
// Driver Entry / Unload
//=============================================================================

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Unloading...\n");

    // Signal worker to stop
    g_Shutdown = TRUE;

    // Wait for worker thread
    if (g_WorkerThread) {
        ZwWaitForSingleObject(g_WorkerThread, FALSE, NULL);
        ZwClose(g_WorkerThread);
        g_WorkerThread = NULL;
    }

    // Clean up shared memory
    DestroySharedSection();

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Unloaded successfully\n");
}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] DriverEntry — initializing\n");

    DriverObject->DriverUnload = DriverUnload;

    // Resolve undocumented API function pointers
    NTSTATUS status = ResolveDynamicImports();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to resolve dynamic imports: 0x%08X\n", status);
        return status;
    }

    // Create shared memory section
    status = CreateSharedSection();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to create shared section: 0x%08X\n", status);
        return status;
    }

    // Create worker thread
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objAttr,
        NULL,
        NULL,
        WorkerRoutine,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to create worker thread: 0x%08X\n", status);
        DestroySharedSection();
        return status;
    }

    g_WorkerThread = threadHandle;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Initialization complete — waiting for commands\n");

    return STATUS_SUCCESS;
}
