#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>

#pragma runtime_checks("", off)
#pragma optimize("", off)

struct UserModeMapParams {
    uintptr_t base;
    uintptr_t flag_addr;
    uintptr_t fnLoadLibraryA;
    uintptr_t fnGetProcAddress;
    uintptr_t fnRtlAddFunctionTable;
};

static void __stdcall UserModeShellcode(UserModeMapParams* p)
{
    using fn_LoadLibraryA    = HMODULE(WINAPI*)(const char*);
    using fn_GetProcAddress  = FARPROC(WINAPI*)(HMODULE, const char*);
    using fn_RtlAddFuncTable = BOOL(WINAPI*)(void*, DWORD, DWORD64);
    using fn_DllMain         = BOOL(WINAPI*)(void*, DWORD, void*);

    BYTE* pBase = (BYTE*)p->base;
    auto* pDos  = (IMAGE_DOS_HEADER*)pBase;
    auto* pNt   = (IMAGE_NT_HEADERS64*)(pBase + pDos->e_lfanew);
    auto* pOpt  = &pNt->OptionalHeader;

    auto _LoadLibraryA    = (fn_LoadLibraryA)   p->fnLoadLibraryA;
    auto _GetProcAddress  = (fn_GetProcAddress)  p->fnGetProcAddress;
    auto _RtlAddFuncTable = (fn_RtlAddFuncTable) p->fnRtlAddFunctionTable;

    ptrdiff_t Delta = (ptrdiff_t)((uintptr_t)pBase - pOpt->ImageBase);
    if (Delta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc    = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* relocEnd = (IMAGE_BASE_RELOCATION*)((uintptr_t)reloc + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        while (reloc < relocEnd && reloc->SizeOfBlock) {
            UINT  count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entry = (WORD*)(reloc + 1);
            for (UINT i = 0; i < count; i++, entry++) {
                if ((*entry >> 0xC) == IMAGE_REL_BASED_DIR64)
                    *(uintptr_t*)(pBase + reloc->VirtualAddress + (*entry & 0xFFF)) += (uintptr_t)Delta;
            }
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    if (_LoadLibraryA && _GetProcAddress && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE hMod = _LoadLibraryA((char*)(pBase + imp->Name));
            auto* orig   = (uintptr_t*)(pBase + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto* iat    = (uintptr_t*)(pBase + imp->FirstThunk);
            for (; *orig; orig++, iat++) {
                if (IMAGE_SNAP_BY_ORDINAL(*orig))
                    *iat = (uintptr_t)_GetProcAddress(hMod, (char*)(*orig & 0xFFFF));
                else
                    *iat = (uintptr_t)_GetProcAddress(hMod, ((IMAGE_IMPORT_BY_NAME*)(pBase + *orig))->Name);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = (IMAGE_TLS_DIRECTORY64*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* cb  = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; cb && *cb; cb++)
            (*cb)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    if (_RtlAddFuncTable && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size)
        _RtlAddFuncTable(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (DWORD64)pBase
        );

    auto _DllMain = (fn_DllMain)(pBase + pOpt->AddressOfEntryPoint);
    _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

    *(volatile BYTE*)p->flag_addr = 0x69;
}

#pragma optimize("", off)
#pragma runtime_checks("", off)
static void UserModeShellcode_End() { __nop(); }
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#pragma runtime_checks("", restore)

typedef LONG (NTAPI* fn_NtCreateThreadEx)(
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    PVOID              ObjectAttributes,
    HANDLE             ProcessHandle,
    PVOID              StartRoutine,
    PVOID              Argument,
    ULONG              CreateFlags,
    SIZE_T             ZeroBits,
    SIZE_T             StackSize,
    SIZE_T             MaximumStackSize,
    PVOID              AttributeList
);

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x4

static inline void ApplyUmSectionProtections(HANDLE hProc, BYTE* remoteBase, IMAGE_NT_HEADERS64* nt)
{
    auto* secs = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto* s = secs + i;
        DWORD chars   = s->Characteristics;
        BOOL  isExec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL  isRead  = (chars & IMAGE_SCN_MEM_READ)    != 0;
        BOOL  isWrite = (chars & IMAGE_SCN_MEM_WRITE)   != 0;

        DWORD prot = PAGE_NOACCESS;
        if      (isExec && isRead && isWrite) prot = PAGE_EXECUTE_READWRITE;
        else if (isExec && isRead)            prot = PAGE_EXECUTE_READ;
        else if (isExec)                      prot = PAGE_EXECUTE;
        else if (isRead && isWrite)           prot = PAGE_READWRITE;
        else if (isRead)                      prot = PAGE_READONLY;

        SIZE_T secSize = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (!secSize) continue;

        DWORD old;
        VirtualProtectEx(hProc, remoteBase + s->VirtualAddress, secSize, prot, &old);
    }
}

struct UmInjector {
    static bool inject(DWORD pid, const wchar_t* dllPath)
    {
        fn_NtCreateThreadEx NtCreateThreadEx = (fn_NtCreateThreadEx)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        if (!NtCreateThreadEx) return false;

        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) return false;

        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return false; }

        DWORD fileSize = GetFileSize(hFile, NULL);
        BYTE* fileData = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        DWORD read = 0;
        ReadFile(hFile, fileData, fileSize, &read, NULL);
        CloseHandle(hFile);

        auto* dos = (IMAGE_DOS_HEADER*)fileData;
        auto* nt  = (IMAGE_NT_HEADERS64*)(fileData + dos->e_lfanew);

        BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProc, NULL, nt->OptionalHeader.SizeOfImage,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBase) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        WriteProcessMemory(hProc, remoteBase, fileData, nt->OptionalHeader.SizeOfHeaders, NULL);

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (sec->SizeOfRawData)
                WriteProcessMemory(hProc, remoteBase + sec->VirtualAddress,
                                   fileData + sec->PointerToRawData, sec->SizeOfRawData, NULL);
        }

        SIZE_T scSize  = 0x2000;
        BYTE*  scBase  = (BYTE*)VirtualAllocEx(hProc, NULL, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        BYTE*  flagBase = (BYTE*)VirtualAllocEx(hProc, NULL, sizeof(BYTE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!scBase || !flagBase) {
            if (scBase)   VirtualFreeEx(hProc, scBase,   0, MEM_RELEASE);
            if (flagBase) VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        UserModeMapParams params = {
            (uintptr_t)remoteBase,
            (uintptr_t)flagBase,
            (uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
            (uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"),
            (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),    "RtlAddFunctionTable")
        };

        SIZE_T scFnSize = (SIZE_T)((BYTE*)UserModeShellcode_End - (BYTE*)UserModeShellcode);
        if (sizeof(params) + scFnSize > scSize) {
            VirtualFreeEx(hProc, scBase,    0, MEM_RELEASE);
            VirtualFreeEx(hProc, flagBase,  0, MEM_RELEASE);
            VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        WriteProcessMemory(hProc, scBase, &params, sizeof(params), NULL);
        WriteProcessMemory(hProc, scBase + sizeof(params), (BYTE*)UserModeShellcode, scFnSize, NULL);

        DWORD old;
        VirtualProtectEx(hProc, scBase, scSize, PAGE_EXECUTE_READ, &old);

        HANDLE hThread = NULL;
        LONG st = NtCreateThreadEx(
            &hThread, GENERIC_ALL, NULL, hProc,
            (PVOID)(scBase + sizeof(params)), scBase,
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
            0, 0, 0, NULL
        );

        if (st < 0 || !hThread) {
            VirtualFreeEx(hProc, scBase,    0, MEM_RELEASE);
            VirtualFreeEx(hProc, flagBase,  0, MEM_RELEASE);
            VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        BYTE  flag    = 0;
        DWORD timeout = 5000;
        while (flag != 0x69 && timeout > 0) {
            ReadProcessMemory(hProc, flagBase, &flag, 1, NULL);
            Sleep(10);
            timeout -= 10;
        }

        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);

        if (flag == 0x69)
            ApplyUmSectionProtections(hProc, remoteBase, nt);

        VirtualFreeEx(hProc, scBase,   0, MEM_RELEASE);
        VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
        VirtualFree(fileData, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (flag == 0x69);
    }
};
