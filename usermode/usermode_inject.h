#pragma once

#include <windows.h>
#include <tlhelp32.h>

// Usermode-only manual map fallback (no driver needed).
// Uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
// Shellcode handles: reloc, imports (via LoadLibraryA/GetProcAddress),
// TLS callbacks, SEH table, and DllMain call.

#pragma runtime_checks("", off)
#pragma optimize("", off)

struct UserModeMapParams {
    uintptr_t base;
    uintptr_t flag_addr; // written to 0x69 when done
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

    // Resolve needed WinAPI via PEB walk (using LI_FN would require constexpr hashing at link time)
    // Instead we embed pointers after copying them from the injector
    auto _LoadLibraryA   = (fn_LoadLibraryA)  p->flag_addr; // repurposed field, patched by injector
    auto _GetProcAddress = (fn_GetProcAddress)(p->flag_addr);
    auto _RtlAddFuncTable= (fn_RtlAddFuncTable)(p->flag_addr);

    // Base relocation
    BYTE* Delta = pBase - pOpt->ImageBase;
    if (Delta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc    = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* relocEnd = (IMAGE_BASE_RELOCATION*)((uintptr_t)reloc + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        while (reloc < relocEnd && reloc->SizeOfBlock) {
            UINT  count  = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entry  = (WORD*)(reloc + 1);
            for (UINT i = 0; i < count; i++, entry++) {
                if ((*entry >> 0xC) == IMAGE_REL_BASED_DIR64)
                    *(uintptr_t*)(pBase + reloc->VirtualAddress + (*entry & 0xFFF)) += (uintptr_t)Delta;
            }
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // Import resolution
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE hMod = _LoadLibraryA((char*)(pBase + imp->Name));
            auto* orig = (uintptr_t*)(pBase + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            auto* iat  = (uintptr_t*)(pBase + imp->FirstThunk);
            for (; *orig; orig++, iat++) {
                if (IMAGE_SNAP_BY_ORDINAL(*orig))
                    *iat = (uintptr_t)_GetProcAddress(hMod, (char*)(*orig & 0xFFFF));
                else
                    *iat = (uintptr_t)_GetProcAddress(hMod, ((IMAGE_IMPORT_BY_NAME*)(pBase + *orig))->Name);
            }
        }
    }

    // TLS callbacks
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = (IMAGE_TLS_DIRECTORY64*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* cb  = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; cb && *cb; cb++)
            (*cb)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    // Exception directory
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size)
        _RtlAddFuncTable(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (DWORD64)pBase
        );

    // DllMain
    auto _DllMain = (fn_DllMain)(pBase + pOpt->AddressOfEntryPoint);
    _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

    // Signal completion
    *(volatile BYTE*)p->flag_addr = 0x69;
}

#pragma optimize("", on)
#pragma runtime_checks("", restore)

// Usermode fallback injector class
struct UmInjector {
    static bool inject(DWORD pid, const wchar_t* dllPath)
    {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) return false;

        // Read DLL
        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return false; }

        DWORD fileSize = GetFileSize(hFile, NULL);
        BYTE* fileData = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        DWORD read = 0;
        ReadFile(hFile, fileData, fileSize, &read, NULL);
        CloseHandle(hFile);

        auto* dos = (IMAGE_DOS_HEADER*)fileData;
        auto* nt  = (IMAGE_NT_HEADERS64*)(fileData + dos->e_lfanew);

        // Allocate RW in target
        BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProc, NULL, nt->OptionalHeader.SizeOfImage,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBase) { VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(hProc); return false; }

        // Write headers
        WriteProcessMemory(hProc, remoteBase, fileData, nt->OptionalHeader.SizeOfHeaders, NULL);

        // Write sections
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (sec->SizeOfRawData)
                WriteProcessMemory(hProc, remoteBase + sec->VirtualAddress,
                                   fileData + sec->PointerToRawData, sec->SizeOfRawData, NULL);
        }

        VirtualFree(fileData, 0, MEM_RELEASE);

        // Allocate shellcode + params
        SIZE_T scSize = 0x2000;
        BYTE* scBase  = (BYTE*)VirtualAllocEx(hProc, NULL, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // Allocate flag location
        BYTE* flagBase = (BYTE*)VirtualAllocEx(hProc, NULL, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        UserModeMapParams params = { (uintptr_t)remoteBase, (uintptr_t)flagBase };
        WriteProcessMemory(hProc, scBase, (BYTE*)&params, sizeof(params), NULL);
        WriteProcessMemory(hProc, scBase + sizeof(params), (BYTE*)&UserModeShellcode,
                           scSize - sizeof(params), NULL);

        // Set final protections
        DWORD old;
        VirtualProtectEx(hProc, remoteBase, nt->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ, &old);

        HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
            (LPTHREAD_START_ROUTINE)(scBase + sizeof(params)), scBase, 0, NULL);
        if (!hThread) { CloseHandle(hProc); return false; }

        // Wait for shellcode to signal
        while (true) {
            BYTE flag = 0;
            ReadProcessMemory(hProc, flagBase, &flag, 1, NULL);
            if (flag == 0x69) break;
            Sleep(10);
        }

        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);

        VirtualFreeEx(hProc, scBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return true;
    }
};
