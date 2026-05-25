
#include "driver.h"

static PVOID            g_SharedBuffer   = NULL;
static PMDL             g_SharedMdl      = NULL;
static PVOID            g_UserMappedVa   = NULL;
static PEPROCESS        g_InjectorProc   = NULL;
static HANDLE           g_WorkerThread   = NULL;
static volatile BOOLEAN g_Shutdown       = FALSE;
static SHARED_HEADER*   g_Header         = NULL;

fn_MmCopyVirtualMemory     pfnMmCopyVirtualMemory    = NULL;
fn_PsGetProcessPeb         pfnPsGetProcessPeb        = NULL;
fn_ZwProtectVirtualMemory  pfnZwProtectVirtualMemory = NULL;
fn_RtlCreateUserThread     pfnRtlCreateUserThread    = NULL;
fn_ZwSuspendThread         pfnZwSuspendThread        = NULL;
fn_ZwResumeThread          pfnZwResumeThread         = NULL;
fn_ZwGetThreadContext      pfnZwGetThreadContext     = NULL;
fn_ZwSetThreadContext      pfnZwSetThreadContext     = NULL;

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

    RtlInitUnicodeString(&name, L"ZwSuspendThread");
    pfnZwSuspendThread = (fn_ZwSuspendThread)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"ZwResumeThread");
    pfnZwResumeThread = (fn_ZwResumeThread)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"ZwGetThreadContext");
    pfnZwGetThreadContext = (fn_ZwGetThreadContext)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"ZwSetThreadContext");
    pfnZwSetThreadContext = (fn_ZwSetThreadContext)MmGetSystemRoutineAddress(&name);

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

static VOID   WorkerRoutine(_In_ PVOID Context);
static VOID   UpdateProgress(_In_ LONG Pct, _In_ const char* Msg);
static PVOID  FindModuleBase(_In_ PEPROCESS Process, _In_ PCWSTR ModName);
static PVOID  FindExport(_In_ PVOID ModBase, _In_ PCCH FuncName);
static NTSTATUS WriteToProcess(_In_ PEPROCESS Target, _In_ PVOID Dest, _In_ PVOID Src, _In_ SIZE_T Size);
static NTSTATUS ReadFromProcess(_In_ PEPROCESS Target, _In_ PVOID Src, _Out_ PVOID Dest, _In_ SIZE_T Size);

NTSTATUS CreateSharedMemory(VOID)
{

    g_SharedBuffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        SHM_TOTAL_SIZE, DRV_POOL_TAG
    );
    if (!g_SharedBuffer) return STATUS_INSUFFICIENT_RESOURCES;

    g_SharedMdl = IoAllocateMdl(g_SharedBuffer, (ULONG)SHM_TOTAL_SIZE, FALSE, FALSE, NULL);
    if (!g_SharedMdl) {
        ExFreePoolWithTag(g_SharedBuffer, DRV_POOL_TAG);
        g_SharedBuffer = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(g_SharedMdl);

    g_Header            = (SHARED_HEADER*)g_SharedBuffer;
    g_Header->Magic     = PROTO_MAGIC;
    g_Header->Version   = (PROTO_VER_MAJOR << 16) | PROTO_VER_MINOR;
    InterlockedExchange(&g_Header->Status, IPC_READY);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Shared buffer at %p (%llu bytes), MDL built — no named object\n",
        g_SharedBuffer, (ULONGLONG)SHM_TOTAL_SIZE);

    return STATUS_SUCCESS;
}

VOID DestroySharedMemory(VOID)
{
    if (g_UserMappedVa && g_InjectorProc) {
        KAPC_STATE apc;
        KeStackAttachProcess(g_InjectorProc, &apc);
        __try { MmUnmapLockedPages(g_UserMappedVa, g_SharedMdl); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        KeUnstackDetachProcess(&apc);
        g_UserMappedVa = NULL;
    }
    if (g_SharedMdl) {
        IoFreeMdl(g_SharedMdl);
        g_SharedMdl = NULL;
    }
    if (g_SharedBuffer) {
        ExFreePoolWithTag(g_SharedBuffer, DRV_POOL_TAG);
        g_SharedBuffer = NULL;
    }
    if (g_InjectorProc) {
        ObDereferenceObject(g_InjectorProc);
        g_InjectorProc = NULL;
    }
    g_Header = NULL;
}

static VOID ProcessNotifyCallback(
    _In_     PEPROCESS            Process,
    _In_     HANDLE               ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);

    if (!CreateInfo) {

        if (Process == g_InjectorProc && g_UserMappedVa && g_SharedMdl) {
            KAPC_STATE apc;
            KeStackAttachProcess(Process, &apc);
            __try { MmUnmapLockedPages(g_UserMappedVa, g_SharedMdl); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            KeUnstackDetachProcess(&apc);
            g_UserMappedVa = NULL;
            ObDereferenceObject(g_InjectorProc);
            g_InjectorProc = NULL;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[drv] Injector exited, shared buffer unmapped\n");
        }
        return;
    }

    if (!CreateInfo->ImageFileName || !g_SharedMdl) return;

    PCUNICODE_STRING full = CreateInfo->ImageFileName;
    USHORT          slash = 0;
    for (USHORT i = 0; i < full->Length / sizeof(WCHAR); i++)
        if (full->Buffer[i] == L'\\') slash = (USHORT)(i + 1);

    UNICODE_STRING baseName = {
        (USHORT)(full->Length - slash * sizeof(WCHAR)),
        (USHORT)(full->Length - slash * sizeof(WCHAR)),
        full->Buffer + slash
    };
    UNICODE_STRING injName;
    RtlInitUnicodeString(&injName, INJECTOR_PROCESS_NAME);

    if (RtlCompareUnicodeString(&baseName, &injName, TRUE) != 0) return;
    if (g_InjectorProc) return;

    PVOID mapped = NULL;
    KAPC_STATE apc;
    KeStackAttachProcess(Process, &apc);
    __try {
        mapped = MmMapLockedPagesSpecifyCache(
            g_SharedMdl, UserMode, MmCached, NULL, FALSE,
            (MM_PAGE_PRIORITY)(NormalPagePriority | MdlMappingNoExecute)
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { mapped = NULL; }
    KeUnstackDetachProcess(&apc);

    if (!mapped) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to map shared buffer into injector\n");
        return;
    }

    ObReferenceObject(Process);
    g_InjectorProc = Process;
    g_UserMappedVa = mapped;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Shared buffer mapped into injector at user VA %p\n", mapped);
}

static VOID UpdateProgress(_In_ LONG Pct, _In_ const char* Msg)
{
    if (!g_Header) return;
    InterlockedExchange(&g_Header->Progress, Pct);

    SIZE_T len = 0;
    const char* p = Msg;
    while (*p && len < sizeof(g_Header->Message) - 1) {
        g_Header->Message[len++] = *p++;
    }
    g_Header->Message[len] = '\0';

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] [%3ld%%] %s\n", Pct, Msg);
}

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

NTSTATUS MapSections(
    _In_ PEPROCESS          Process,
    _In_ PVOID              AllocBase,
    _In_ PVOID              RawDll,
    _In_ PIMAGE_NT_HEADERS64 Nt)
{
    NTSTATUS status;

    status = WriteToProcess(Process, AllocBase, RawDll,
        Nt->OptionalHeader.SizeOfHeaders);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to write headers: 0x%08X\n", status);
        return status;
    }

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(Nt);
    for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; i++, sec++) {

        if (sec->SizeOfRawData == 0)
            continue;

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

NTSTATUS ProcessRelocations(
    _In_ PEPROCESS           Process,
    _In_ PVOID               AllocBase,
    _In_ PIMAGE_NT_HEADERS64 Nt,
    _In_ ULONG_PTR           Delta)
{
    if (Delta == 0)
        return STATUS_SUCCESS;

    ULONG relocRva  = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    ULONG relocSize = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRva == 0 || relocSize == 0) {

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[drv] No relocation table but delta=0x%llX\n", (ULONGLONG)Delta);
        return STATUS_SUCCESS;
    }

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

    PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)relocBuf;
    ULONG processed = 0;

    while (processed < relocSize && block->SizeOfBlock > 0) {
        ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PUSHORT entries = (PUSHORT)((ULONG_PTR)block + sizeof(IMAGE_BASE_RELOCATION));

        for (ULONG i = 0; i < count; i++) {
            USHORT type   = entries[i] >> 12;
            USHORT offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {

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

static PVOID FindModuleBase(_In_ PEPROCESS Process, _In_ PCWSTR ModName)
{
    PVOID result = NULL;
    KAPC_STATE apcState;

    KeStackAttachProcess(Process, &apcState);

    __try {

        PPEB peb = pfnPsGetProcessPeb ? pfnPsGetProcessPeb(Process) : NULL;
        if (!peb) __leave;

        PPEB_LDR_DATA ldr = peb->Ldr;
        if (!ldr) __leave;

        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY entry = head->Flink;

        while (entry != head) {
            PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (mod->BaseDllName.Buffer) {

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

        PVOID modBase = FindModuleBase(Process, wModName);

        if (!modBase) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[drv] Import module not found: %ls\n", wModName);
            desc++;
            continue;
        }

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

        }
    }

    return STATUS_SUCCESS;
}

static const UCHAR g_ShellcodeTemplate[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
    0x4D, 0x31, 0xC0,
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3
};

#define SHELLCODE_HMODULE_OFFSET  6
#define SHELLCODE_ENTRY_OFFSET    25
#define SHELLCODE_SIZE            sizeof(g_ShellcodeTemplate)

#pragma pack(push, 8)
typedef struct _SYS_THREAD_INFO {
    LARGE_INTEGER KernelTime, UserTime, CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    LONG          Priority, BasePriority;
    ULONG         ContextSwitchCount, ThreadState, WaitReason;
} SYS_THREAD_INFO;

typedef struct _SYS_PROC_INFO {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Spare[3];
    LARGE_INTEGER  CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount, SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize, VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize, WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount, WriteOperationCount, OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount, WriteTransferCount, OtherTransferCount;
    SYS_THREAD_INFO Threads[1];
} SYS_PROC_INFO;
#pragma pack(pop)

static NTSTATUS FindSuitableThread(_In_ ULONG TargetPid, _Out_ PHANDLE OutHandle)
{
    *OutHandle = NULL;

    ULONG bufSize = 0;
    ZwQuerySystemInformation(5, NULL, 0, &bufSize);
    bufSize += 0x10000;

    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, DRV_POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ZwQuerySystemInformation(5, buf, bufSize, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, DRV_POOL_TAG);
        return status;
    }

    HANDLE target    = (HANDLE)(ULONG_PTR)TargetPid;
    HANDLE hFallback = NULL;
    SYS_PROC_INFO* entry = (SYS_PROC_INFO*)buf;

    for (;;) {
        if (entry->UniqueProcessId == target && entry->NumberOfThreads > 1) {

            for (ULONG i = 1; i < entry->NumberOfThreads; i++) {
                SYS_THREAD_INFO* ti = &entry->Threads[i];

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                HANDLE hThr = NULL;
                NTSTATUS os = ZwOpenThread(&hThr,
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                    THREAD_QUERY_INFORMATION,
                    &oa, &ti->ClientId);

                if (!NT_SUCCESS(os))
                    continue;

                if (ti->ThreadState == 5 && ti->WaitReason == 6) {
                    if (hFallback) ZwClose(hFallback);
                    ExFreePoolWithTag(buf, DRV_POOL_TAG);
                    *OutHandle = hThr;
                    return STATUS_SUCCESS;
                }

                if (ti->ThreadState == 5 && !hFallback) {
                    hFallback = hThr;
                } else {
                    ZwClose(hThr);
                }
            }
            break;
        }
        if (!entry->NextEntryOffset) break;
        entry = (SYS_PROC_INFO*)((UCHAR*)entry + entry->NextEntryOffset);
    }

    ExFreePoolWithTag(buf, DRV_POOL_TAG);

    if (hFallback) {
        *OutHandle = hFallback;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS RunShellcodeInTarget(
    _In_ PEPROCESS Process,
    _In_ ULONG     TargetPid,
    _In_ HANDLE    ProcHandle,
    _In_ PVOID     Sc,
    _In_ SIZE_T    ScSize)
{
    if (ScSize > 0xF00) return STATUS_INVALID_PARAMETER;

    SIZE_T totalSize = 0x2000;
    PVOID  allocBase = NULL;
    NTSTATUS status = ZwAllocateVirtualMemory(ProcHandle, &allocBase, 0, &totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) return status;

    ULONG_PTR scVA        = (ULONG_PTR)allocBase;
    ULONG_PTR trampolineVA = scVA + 0x1000;
    ULONG_PTR stackVA      = scVA + 0x1100;
    ULONG_PTR flagVA       = scVA + 0x1FF0;

    WriteToProcess(Process, (PVOID)scVA, Sc, ScSize);

    BOOLEAN executed = FALSE;
    HANDLE  hThread  = NULL;

    if (NT_SUCCESS(FindSuitableThread(TargetPid, &hThread))) {
        if (pfnZwSuspendThread) pfnZwSuspendThread(hThread, NULL);
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        if (pfnZwGetThreadContext && NT_SUCCESS(pfnZwGetThreadContext(hThread, &ctx))) {
            static const UCHAR kCallTpl[] = {
                0x48, 0x83, 0xEC, 0x28,
                0x48, 0xB8, 0,0,0,0, 0,0,0,0,
                0xFF, 0xD0,
                0x48, 0xB8, 0,0,0,0, 0,0,0,0,
                0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x48, 0x83, 0xC4, 0x28,
                0x48, 0xB8, 0,0,0,0, 0,0,0,0,
                0xFF, 0xE0
            };
            UCHAR tpl[sizeof(kCallTpl)];
            RtlCopyMemory(tpl, kCallTpl, sizeof(tpl));
            *(ULONG_PTR*)(tpl + 6)  = scVA;
            *(ULONG_PTR*)(tpl + 18) = flagVA;
            *(ULONG_PTR*)(tpl + 38) = ctx.Rip;
            WriteToProcess(Process, (PVOID)trampolineVA, tpl, sizeof(tpl));

            CONTEXT newCtx     = ctx;
            newCtx.Rip         = trampolineVA;
            newCtx.Rsp         = stackVA + 0xF8;

            if (pfnZwSetThreadContext && NT_SUCCESS(pfnZwSetThreadContext(hThread, &newCtx))) {
                if (pfnZwResumeThread) pfnZwResumeThread(hThread, NULL);
                for (int i = 0; i < 500; i++) {
                    ULONG done = 0;
                    ReadFromProcess(Process, (PVOID)flagVA, &done, sizeof(done));
                    if (done) { executed = TRUE; break; }
                    LARGE_INTEGER d; d.QuadPart = -100000LL;
                    KeDelayExecutionThread(KernelMode, FALSE, &d);
                }
            } else {
                if (pfnZwResumeThread) pfnZwResumeThread(hThread, NULL);
            }
        } else {
            if (pfnZwResumeThread) pfnZwResumeThread(hThread, NULL);
        }
        ZwClose(hThread);
    }

    if (!executed && pfnRtlCreateUserThread) {
        HANDLE thr = NULL;
        if (NT_SUCCESS(pfnRtlCreateUserThread(ProcHandle, NULL, FALSE, 0, 0, 0,
                                               (PVOID)scVA, NULL, &thr, NULL))) {
            LARGE_INTEGER timeout; timeout.QuadPart = -30000000LL;
            ZwWaitForSingleObject(thr, FALSE, &timeout);
            ZwClose(thr);
            executed = TRUE;
        }
    }

    ZwFreeVirtualMemory(ProcHandle, &allocBase, &totalSize, MEM_RELEASE);
    return executed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static const UCHAR kHijackTemplate[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0xB9, 0,0,0,0, 0,0,0,0,
    0xBA, 0x01, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xC0,
    0x48, 0xB8, 0,0,0,0, 0,0,0,0,
    0xFF, 0xD0,
    0x48, 0xB8, 0,0,0,0, 0,0,0,0,
    0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x28,
    0x48, 0xB8, 0,0,0,0, 0,0,0,0,
    0xFF, 0xE0
};
enum { HJ_HMOD=6, HJ_ENTRY=24, HJ_FLAG=36, HJ_ORIP=56 };

static NTSTATUS ExecuteViaHijack(
    _In_ PEPROCESS Process,
    _In_ ULONG     TargetPid,
    _In_ PVOID     AllocBase,
    _In_ ULONG_PTR EntryPoint,
    _In_ HANDLE    ProcHandle)
{
    HANDLE hThread = NULL;
    if (!NT_SUCCESS(FindSuitableThread(TargetPid, &hThread)))
        return STATUS_NOT_FOUND;

    if (pfnZwSuspendThread) pfnZwSuspendThread(hThread, NULL);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    NTSTATUS status = pfnZwGetThreadContext ? pfnZwGetThreadContext(hThread, &ctx) : STATUS_PROCEDURE_NOT_FOUND;
    if (!NT_SUCCESS(status)) {
        if (pfnZwResumeThread) pfnZwResumeThread(hThread, NULL);
        ZwClose(hThread);
        return status;
    }

    PVOID mem = NULL;
    SIZE_T memSz = 0x3000;
    status = ZwAllocateVirtualMemory(ProcHandle, &mem, 0, &memSz,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        if (pfnZwResumeThread) pfnZwResumeThread(hThread, NULL);
        ZwClose(hThread);
        return status;
    }

    ULONG_PTR scBase    = (ULONG_PTR)mem;
    ULONG_PTR stackBase = scBase + 0x100;
    ULONG_PTR flagAddr  = scBase + 0x2FF0;

    UCHAR sc[sizeof(kHijackTemplate)];
    RtlCopyMemory(sc, kHijackTemplate, sizeof(sc));
    *(ULONG_PTR*)(sc + HJ_HMOD)  = (ULONG_PTR)AllocBase;
    *(ULONG_PTR*)(sc + HJ_ENTRY) = EntryPoint;
    *(ULONG_PTR*)(sc + HJ_FLAG)  = flagAddr;
    *(ULONG_PTR*)(sc + HJ_ORIP)  = ctx.Rip;

    WriteToProcess(Process, (PVOID)scBase, sc, sizeof(sc));

    CONTEXT newCtx = ctx;
    newCtx.Rip = scBase;
    newCtx.Rsp = stackBase + 0xFF8;

    status = pfnZwSetThreadContext ? pfnZwSetThreadContext(hThread, &newCtx) : STATUS_PROCEDURE_NOT_FOUND;
    if (!NT_SUCCESS(status)) {
        ZwFreeVirtualMemory(ProcHandle, &mem, &memSz, MEM_RELEASE);
        if (pfnZwResumeThread) pfnZwResumeThread(hThread, NULL);
        ZwClose(hThread);
        return status;
    }

    if (pfnZwResumeThread) pfnZwResumeThread(hThread, NULL);
    ZwClose(hThread);

    ULONG done = 0;
    for (int i = 0; i < 500 && !done; i++) {
        ReadFromProcess(Process, (PVOID)flagAddr, &done, sizeof(ULONG));
        if (done) break;
        LARGE_INTEGER d; d.QuadPart = -100000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &d);
    }

    ZwFreeVirtualMemory(ProcHandle, &mem, &memSz, MEM_RELEASE);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Thread hijack execution %s\n", done ? "complete" : "timed out");

    return done ? STATUS_SUCCESS : STATUS_TIMEOUT;
}

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
    ULONG     pid        = (ULONG)(ULONG_PTR)PsGetProcessId(Process);

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

    ULONG flags = g_Header ? g_Header->Flags : 0;

    if (flags & INJ_FLAG_THREAD_HIJACK) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[drv] Using thread hijack execution\n");
        status = ExecuteViaHijack(Process, pid, AllocBase, entryPoint, procHandle);

        if (NT_SUCCESS(status)) {
            ZwClose(procHandle);
            return STATUS_SUCCESS;
        }

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[drv] Hijack failed (0x%08X), falling back to RtlCreateUserThread\n", status);
    }

    UCHAR shellcode[SHELLCODE_SIZE];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate, SHELLCODE_SIZE);

    *(ULONG_PTR*)(shellcode + SHELLCODE_HMODULE_OFFSET) = hModule;

    *(ULONG_PTR*)(shellcode + SHELLCODE_ENTRY_OFFSET) = entryPoint;

    PVOID scBase = NULL;
    SIZE_T scSize = SHELLCODE_SIZE;

    status = ZwAllocateVirtualMemory(procHandle, &scBase, 0, &scSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status)) {
        ZwClose(procHandle);
        return status;
    }

    status = WriteToProcess(Process, scBase, shellcode, SHELLCODE_SIZE);
    if (!NT_SUCCESS(status)) {
        ZwFreeVirtualMemory(procHandle, &scBase, &scSize, MEM_RELEASE);
        ZwClose(procHandle);
        return status;
    }

    HANDLE threadHandle = NULL;
    if (!pfnRtlCreateUserThread) {
        ZwFreeVirtualMemory(procHandle, &scBase, &scSize, MEM_RELEASE);
        ZwClose(procHandle);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = pfnRtlCreateUserThread(
        procHandle,
        NULL,
        FALSE,
        0,
        0,
        0,
        scBase,
        NULL,
        &threadHandle,
        NULL
    );

    if (NT_SUCCESS(status) && threadHandle) {

        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;
        ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
        ZwClose(threadHandle);
    }
    else {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] RtlCreateUserThread failed: 0x%08X\n", status);
    }

    ZwFreeVirtualMemory(procHandle, &scBase, &scSize, MEM_RELEASE);
    ZwClose(procHandle);

    return status;
}

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

    if (!tlsDir.AddressOfCallBacks) return STATUS_SUCCESS;

    ULONG_PTR callbacks[64] = { 0 };
    ReadFromProcess(
        Process,
        (PVOID)tlsDir.AddressOfCallBacks,
        callbacks,
        sizeof(callbacks)
    );

    ULONG pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);

    for (int i = 0; i < 64 && callbacks[i]; i++) {
        ULONG_PTR cbVa = callbacks[i];

        UCHAR sc[SHELLCODE_SIZE];
        RtlCopyMemory(sc, g_ShellcodeTemplate, SHELLCODE_SIZE);
        *(ULONG_PTR*)(sc + SHELLCODE_HMODULE_OFFSET) = (ULONG_PTR)AllocBase;
        *(ULONG_PTR*)(sc + SHELLCODE_ENTRY_OFFSET)   = cbVa;

        HANDLE procHandle = NULL;
        CLIENT_ID cid = { 0 };
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = PsGetProcessId(Process);

        if (!NT_SUCCESS(ZwOpenProcess(&procHandle, PROCESS_ALL_ACCESS, &oa, &cid)))
            continue;

        RunShellcodeInTarget(Process, pid, procHandle, sc, SHELLCODE_SIZE);
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

            static const UCHAR kRaftTemplate[] = {
                0x48, 0x83, 0xEC, 0x28,
                0x48, 0xB9, 0,0,0,0, 0,0,0,0,
                0xBA, 0,0,0,0,
                0x49, 0xB8, 0,0,0,0, 0,0,0,0,
                0x48, 0xB8, 0,0,0,0, 0,0,0,0,
                0xFF, 0xD0,
                0x48, 0x83, 0xC4, 0x28,
                0xC3
            };

            enum { OFF_PDATA = 6, OFF_COUNT = 16, OFF_BASE = 21, OFF_FN = 31 };

            PVOID ntdllBase = FindModuleBase(process, L"ntdll.dll");
            PVOID fnRaft    = ntdllBase ? FindExportSafe(ntdllBase, "RtlAddFunctionTable") : NULL;

            if (fnRaft) {
                ULONG_PTR pdataVa   = (ULONG_PTR)allocBase + pdataRva;
                ULONG     entryCount = pdataSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

                UCHAR sc[sizeof(kRaftTemplate)];
                RtlCopyMemory(sc, kRaftTemplate, sizeof(sc));
                *(ULONG_PTR*)(sc + OFF_PDATA) = pdataVa;
                *(ULONG*)    (sc + OFF_COUNT)  = entryCount;
                *(ULONG_PTR*)(sc + OFF_BASE)   = (ULONG_PTR)allocBase;
                *(ULONG_PTR*)(sc + OFF_FN)     = (ULONG_PTR)fnRaft;

                CLIENT_ID cid = { (HANDLE)(ULONG_PTR)TargetPid, NULL };
                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                HANDLE ph = NULL;

                if (NT_SUCCESS(ZwOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid))) {
                    RunShellcodeInTarget(process, TargetPid, ph, sc, sizeof(sc));
                    ZwClose(ph);
                }
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                    "[drv] RtlAddFunctionTable invoked in target (count=%u)\n", entryCount);
            } else {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                    "[drv] ntdll!RtlAddFunctionTable not found — SEH may not work\n");
            }
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

            PVOID dllData = (PVOID)((ULONG_PTR)g_SharedBuffer + PAYLOAD_DATA_OFFSET);
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

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Unloading...\n");

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);

    g_Shutdown = TRUE;

    if (g_WorkerThread) {
        ZwWaitForSingleObject(g_WorkerThread, FALSE, NULL);
        ZwClose(g_WorkerThread);
        g_WorkerThread = NULL;
    }

    DestroySharedMemory();

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

    NTSTATUS status = ResolveDynamicImports();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to resolve dynamic imports: 0x%08X\n", status);
        return status;
    }

    status = CreateSharedMemory();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] Failed to create shared buffer: 0x%08X\n", status);
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[drv] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        DestroySharedMemory();
        return status;
    }

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
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        DestroySharedMemory();
        return status;
    }

    g_WorkerThread = threadHandle;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[drv] Initialization complete — waiting for nanahira.exe to start\n");

    return STATUS_SUCCESS;
}

