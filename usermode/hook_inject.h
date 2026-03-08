#pragma once

#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// Inject via SetWinEventHook — shellcode runs inside target process thread context.
// Technique from: Kernel-Manual-Map-Injector / Inject.cpp
// The shellcode processes reloc+imports+TLS+SEH+DllMain itself (no kernel involvement needed).

#pragma runtime_checks("", off)
#pragma optimize("", off)

static void __stdcall HookShellcode()
{
    uintptr_t base      = 0x15846254168;
    uintptr_t flag_addr = 0x24856841253;

    *(volatile BYTE*)flag_addr = 0x69;

    BYTE* pBase = (BYTE*)base;
    auto* pDos  = (IMAGE_DOS_HEADER*)pBase;
    auto* pNt   = (IMAGE_NT_HEADERS64*)(pBase + pDos->e_lfanew);
    auto* pOpt  = &pNt->OptionalHeader;

    using fn_LoadLibraryA    = HMODULE(WINAPI*)(const char*);
    using fn_GetProcAddress  = FARPROC(WINAPI*)(HMODULE, const char*);
    using fn_RtlAddFuncTable = BOOL(WINAPI*)(void*, DWORD, DWORD64);

    // Resolve kernel32 base via PEB walk (runs inside target process)
    auto getPEB = []() -> BYTE* {
#ifdef _WIN64
        return (BYTE*)__readgsqword(0x60);
#else
        return (BYTE*)__readfsdword(0x30);
#endif
    };

    auto hashStr = [](const wchar_t* s) -> ULONG {
        ULONG h = 0;
        for (; *s; s++) h = h * 31 + (*s | 0x20);
        return h;
    };

    auto findModule = [&](ULONG nameHash) -> BYTE* {
        BYTE* peb = getPEB();
        BYTE* ldr = *(BYTE**)(peb + 0x18);
        LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x10);
        for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
            BYTE* entry = (BYTE*)e;
            UNICODE_STRING* name = (UNICODE_STRING*)(entry + 0x58);
            if (!name->Buffer) continue;
            if (hashStr(name->Buffer) == nameHash)
                return *(BYTE**)(entry + 0x30);
        }
        return nullptr;
    };

    auto findExport = [](BYTE* modBase, const char* funcName) -> void* {
        auto* dos = (IMAGE_DOS_HEADER*)modBase;
        auto* nt  = (IMAGE_NT_HEADERS64*)(modBase + dos->e_lfanew);
        ULONG expRva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!expRva) return nullptr;
        auto* exp     = (IMAGE_EXPORT_DIRECTORY*)(modBase + expRva);
        auto* names   = (ULONG*)(modBase + exp->AddressOfNames);
        auto* ords    = (USHORT*)(modBase + exp->AddressOfNameOrdinals);
        auto* funcs   = (ULONG*)(modBase + exp->AddressOfFunctions);
        for (ULONG i = 0; i < exp->NumberOfNames; i++) {
            const char* n = (const char*)(modBase + names[i]);
            const char* a = n, *b = funcName;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a != *b) continue;
            ULONG rva = funcs[ords[i]];
            if (rva >= expRva && rva < expRva + expSize) continue;
            return modBase + rva;
        }
        return nullptr;
    };

    // kernel32 hash of "kernel32.dll" lowercased: k=0x6b,e,r,n,e,l,3,2,...
    BYTE* k32  = findModule(0x6A4ABC5B); // precomputed hash for "kernel32.dll"
    BYTE* ntdl = findModule(0x1EDE3681); // precomputed hash for "ntdll.dll"

    auto _LoadLibraryA    = (fn_LoadLibraryA)   findExport(k32,  "LoadLibraryA");
    auto _GetProcAddress  = (fn_GetProcAddress)  findExport(k32,  "GetProcAddress");
    auto _RtlAddFuncTable = (fn_RtlAddFuncTable) findExport(ntdl, "RtlAddFunctionTable");

    if (!_LoadLibraryA || !_GetProcAddress) return;

    // Relocations
    BYTE* Delta = pBase - (BYTE*)pOpt->ImageBase;
    if (Delta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc    = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* relocEnd = (IMAGE_BASE_RELOCATION*)((uintptr_t)reloc + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        while (reloc < relocEnd && reloc->SizeOfBlock) {
            WORD* entry = (WORD*)(reloc + 1);
            UINT  count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (UINT i = 0; i < count; i++, entry++)
                if ((*entry >> 0xC) == IMAGE_REL_BASED_DIR64)
                    *(uintptr_t*)(pBase + reloc->VirtualAddress + (*entry & 0xFFF)) += (uintptr_t)Delta;
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // Imports
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
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

    // TLS callbacks
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = (IMAGE_TLS_DIRECTORY64*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* cb  = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; cb && *cb; cb++)
            (*cb)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    // Exception directory
    if (_RtlAddFuncTable && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size)
        _RtlAddFuncTable(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (DWORD64)pBase
        );

    // DllMain
    auto _DllMain = (BOOL(WINAPI*)(void*, DWORD, void*))(pBase + pOpt->AddressOfEntryPoint);
    _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
}

#pragma optimize("", on)
#pragma runtime_checks("", restore)

// Byte-scan helper
static inline PBYTE ScanPattern(PVOID imageBase, SIZE_T imageSize, const char* pat, const char* mask)
{
    SIZE_T mlen = strlen(mask);
    for (SIZE_T i = 0; i < imageSize - mlen; i++) {
        PBYTE addr = (PBYTE)imageBase + i;
        bool match = true;
        for (SIZE_T j = 0; j < mlen; j++) {
            if (mask[j] == 'x' && addr[j] != (BYTE)pat[j]) { match = false; break; }
        }
        if (match) return addr;
    }
    return nullptr;
}

// Measure function length (scan for 0xCCCCCCCC int3 padding)
static inline int ScFunctionLength(void* fn)
{
    int len = 0;
    while (*(UINT32*)((BYTE*)fn + len) != 0xCCCCCCCC) len++;
    return len;
}

struct HookInjector {
    static bool inject(DWORD pid, const wchar_t* dllPath)
    {
        // Get target window handle and thread id for hook
        HWND targetHwnd = NULL;
        EnumWindows([](HWND h, LPARAM lp) -> BOOL {
            DWORD owner;
            GetWindowThreadProcessId(h, &owner);
            if (owner == (DWORD)lp) { *(HWND*)(lp + sizeof(DWORD)) = h; return FALSE; }
            return TRUE;
        }, (LPARAM)&pid); // pack pid+hwnd into struct would be cleaner, simplified here

        // Simplified: just use pid to get thread id via snapshot
        DWORD threadId = 0;
        {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            THREADENTRY32 te = { sizeof(te) };
            if (Thread32First(snap, &te)) do {
                if (te.th32OwnerProcessID == pid) { threadId = te.th32ThreadID; break; }
            } while (Thread32Next(snap, &te));
            CloseHandle(snap);
        }
        if (!threadId) return false;

        // Open target process
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) return false;

        // Read DLL file
        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return false; }
        DWORD fileSize = GetFileSize(hFile, NULL);
        BYTE* fileData = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        DWORD read = 0;
        ReadFile(hFile, fileData, fileSize, &read, NULL);
        CloseHandle(hFile);

        auto* dos = (IMAGE_DOS_HEADER*)fileData;
        auto* nt  = (IMAGE_NT_HEADERS64*)(fileData + dos->e_lfanew);

        // Allocate memory in target (RW first, shellcode will set RX)
        BYTE* remoteBase = (BYTE*)VirtualAllocEx(hProc, NULL, nt->OptionalHeader.SizeOfImage,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBase) { VirtualFree(fileData, 0, MEM_RELEASE); CloseHandle(hProc); return false; }

        // Protect and write target memory RWX (needed for shellcode to patch)
        DWORD old;
        VirtualProtectEx(hProc, remoteBase, nt->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &old);

        // Write headers + sections
        WriteProcessMemory(hProc, remoteBase, fileData, nt->OptionalHeader.SizeOfHeaders, NULL);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (sec->SizeOfRawData)
                WriteProcessMemory(hProc, remoteBase + sec->VirtualAddress,
                                   fileData + sec->PointerToRawData, sec->SizeOfRawData, NULL);
        }
        VirtualFree(fileData, 0, MEM_RELEASE);

        // Allocate flag + shellcode region
        BYTE* flagBase  = (BYTE*)VirtualAllocEx(hProc, NULL, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        BYTE* scRemote  = (BYTE*)VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // Copy shellcode locally and patch sentinels
        MODULEINFO mi = {};
        GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi));

        int scLen = ScFunctionLength(&HookShellcode);
        BYTE* scLocal = (BYTE*)VirtualAlloc(NULL, scLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(scLocal, &HookShellcode, scLen);

        // Patch base sentinel (0x15846254168)
        PBYTE pBase  = ScanPattern(scLocal, scLen, "\x68\x41\x25\x46\x58\x01\x00\x00", "xxxxxx??");
        // Patch flag sentinel (0x24856841253)
        PBYTE pFlag  = ScanPattern(scLocal, scLen, "\x53\x12\x84\x56\x48\x02\x00\x00", "xxxxxx??");

        if (!pBase || !pFlag) {
            VirtualFree(scLocal, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, scRemote, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        *(uintptr_t*)pBase = (uintptr_t)remoteBase;
        *(uintptr_t*)pFlag = (uintptr_t)flagBase;

        WriteProcessMemory(hProc, scRemote, scLocal, scLen, NULL);
        VirtualFree(scLocal, 0, MEM_RELEASE);

        // Hook via WinEvent (requires ntdll loaded in target)
        HMODULE ntdll = LoadLibraryA("ntdll.dll");
        HWINEVENTHOOK hook = SetWinEventHook(
            EVENT_MIN, EVENT_MAX,
            ntdll,
            (WINEVENTPROC)scRemote,
            pid, threadId,
            WINEVENT_INCONTEXT
        );

        if (!hook) {
            VirtualFreeEx(hProc, scRemote, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        // Poll flag until shellcode signals
        BYTE flag = 0;
        DWORD timeout = 10000;
        while (flag != 0x69 && timeout > 0) {
            ReadProcessMemory(hProc, flagBase, &flag, 1, NULL);
            Sleep(10);
            timeout -= 10;
        }

        UnhookWinEvent(hook);
        VirtualFreeEx(hProc, scRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, flagBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return (flag == 0x69);
    }
};
