#pragma once

//=============================================================================
// Usermode Injector — Header
// Source: https://github.com/Kiy0w0/kernel-mmi
//=============================================================================

#ifndef INJECTOR_H
#define INJECTOR_H

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../shared/protocol.h"

//-----------------------------------------------------------------------------
// Console colors & UI
//-----------------------------------------------------------------------------

// Enable virtual terminal (ANSI) processing
static inline BOOL EnableAnsiConsole() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return FALSE;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    return SetConsoleMode(hOut, mode);
}

// ANSI color codes
#define CLR_RESET       "\033[0m"
#define CLR_BOLD        "\033[1m"
#define CLR_DIM         "\033[2m"

#define CLR_RED         "\033[38;2;255;80;80m"
#define CLR_GREEN       "\033[38;2;80;255;120m"
#define CLR_BLUE        "\033[38;2;80;160;255m"
#define CLR_CYAN        "\033[38;2;80;220;255m"
#define CLR_PURPLE      "\033[38;2;180;100;255m"
#define CLR_PINK        "\033[38;2;255;120;200m"
#define CLR_YELLOW      "\033[38;2;255;220;80m"
#define CLR_ORANGE      "\033[38;2;255;160;60m"
#define CLR_WHITE       "\033[38;2;240;240;250m"
#define CLR_GRAY        "\033[38;2;140;140;160m"

// Background
#define BG_DARK         "\033[48;2;15;15;25m"

//-----------------------------------------------------------------------------
// Process utilities
//-----------------------------------------------------------------------------

// Find process ID by name (case-insensitive)
static inline DWORD FindProcessId(const char* procName)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

// Check if process is still running
static inline BOOL IsProcessRunning(DWORD pid)
{
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return FALSE;

    DWORD exitCode = 0;
    GetExitCodeProcess(proc, &exitCode);
    CloseHandle(proc);

    return (exitCode == STILL_ACTIVE);
}

//-----------------------------------------------------------------------------
// File utilities
//-----------------------------------------------------------------------------

// Read entire file into heap buffer
static inline BYTE* ReadFileToBuffer(const char* path, DWORD* outSize)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        *outSize = 0;
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        *outSize = 0;
        return NULL;
    }

    BYTE* buf = (BYTE*)malloc(fileSize);
    if (!buf) {
        CloseHandle(hFile);
        *outSize = 0;
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(buf);
        CloseHandle(hFile);
        *outSize = 0;
        return NULL;
    }

    CloseHandle(hFile);
    *outSize = fileSize;
    return buf;
}

// Quick PE validation (check DOS + NT signature + DLL flag)
static inline BOOL QuickValidatePE(BYTE* data, DWORD size)
{
    if (size < sizeof(IMAGE_DOS_HEADER)) return FALSE;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) return FALSE;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return FALSE;
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) return FALSE;

    return TRUE;
}

#endif // INJECTOR_H
