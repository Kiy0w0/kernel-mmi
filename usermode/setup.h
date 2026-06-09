#pragma once

#include <windows.h>
#include <shellapi.h>
#include <conio.h>
#include <stdio.h>
#include "nanahira.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

static bool SetupCheckTestSigning() {
    typedef LONG (NTAPI *fn_t)(ULONG, PVOID, ULONG, PULONG);
    struct { ULONG Length; ULONG Options; } ci = { 8, 0 };
    auto fn = (fn_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (fn) fn(103, &ci, sizeof(ci), nullptr);
    return (ci.Options & 0x0002) != 0;
}

static bool SetupCheckSecureBootDisabled() {
    DWORD val = 1, sz = sizeof(val);
    RegGetValueA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        "UEFISecureBootEnabled", RRF_RT_DWORD, nullptr, &val, &sz);
    return val == 0;
}

static bool SetupCheckHvciDisabled() {
    DWORD val = 0, sz = sizeof(val);
    LONG r = RegGetValueA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        "Enabled", RRF_RT_DWORD, nullptr, &val, &sz);
    return r != ERROR_SUCCESS || val == 0;
}

static bool SetupCheckCargoInstalled() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    char cmd[] = "cargo --version";
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 3000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static bool SetupGetDriverPath(char* out, DWORD sz) {
    GetModuleFileNameA(nullptr, out, sz);
    char* last = strrchr(out, '\\');
    if (last) *(last + 1) = '\0';
    strcat_s(out, sz, "driver.sys");
    return GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES;
}

static bool SetupValidateDriverPE(const char* path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    IMAGE_DOS_HEADER dos = {};
    DWORD read = 0;
    ReadFile(hFile, &dos, sizeof(dos), &read, nullptr);

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return false;
    }

    SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN);

    IMAGE_NT_HEADERS64 nt = {};
    ReadFile(hFile, &nt, sizeof(nt), &read, nullptr);
    CloseHandle(hFile);

    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    return true;
}

static bool SetupRunSilentCmd(const char* cmd) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    char buf[512];
    strncpy_s(buf, cmd, sizeof(buf) - 1);
    if (!CreateProcessA(nullptr, buf, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static bool SetupEnableTestSigning() {
    return SetupRunSilentCmd("bcdedit /set testsigning on");
}

static bool SetupDisableHvci() {
    HKEY hKey;
    LONG r = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (r != ERROR_SUCCESS) return false;
    DWORD val = 0;
    r = RegSetValueExA(hKey, "Enabled", 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
    RegCloseKey(hKey);
    return r == ERROR_SUCCESS;
}

static bool SetupIsDriverSigned(const char* sysPath) {
    HANDLE hFile = CreateFileA(sysPath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    IMAGE_DOS_HEADER dos = {};
    DWORD read = 0;
    ReadFile(hFile, &dos, sizeof(dos), &read, nullptr);
    SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN);

    IMAGE_NT_HEADERS64 nt = {};
    ReadFile(hFile, &nt, sizeof(nt), &read, nullptr);
    CloseHandle(hFile);

    ULONG secDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    ULONG secSz  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    return secDir != 0 && secSz != 0;
}

static bool SetupSignDriver(const char* sysPath) {
    char tmpPs[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpPs);
    strcat_s(tmpPs, "nanahira_sign.ps1");

    FILE* f = nullptr;
    if (fopen_s(&f, tmpPs, "w") != 0) return false;

    fprintf(f,
        "$cert = New-SelfSignedCertificate "
        "-Subject 'CN=NanahiraTestCert' "
        "-CertStoreLocation 'Cert:\\LocalMachine\\My' "
        "-KeyUsage DigitalSignature "
        "-Type CodeSigningCert "
        "-HashAlgorithm SHA256\n"
        "$cer = [System.IO.Path]::GetTempFileName() + '.cer'\n"
        "Export-Certificate -Cert $cert -FilePath $cer | Out-Null\n"
        "Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\\LocalMachine\\Root' | Out-Null\n"
        "Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\\LocalMachine\\TrustedPublisher' | Out-Null\n"
        "Remove-Item $cer -Force\n"
        "Set-AuthenticodeSignature -FilePath \"%s\" -Certificate $cert | Out-Null\n",
        sysPath
    );
    fclose(f);

    char cmd[MAX_PATH + 128];
    snprintf(cmd, sizeof(cmd),
        "powershell -NoProfile -ExecutionPolicy Bypass -File \"%s\"", tmpPs);

    bool ok = SetupRunSilentCmd(cmd);
    DeleteFileA(tmpPs);
    return ok;
}

static void SetupDeleteDriverService() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceA(scm, "nanahira", SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss = {};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static bool SetupLoadDriver() {
    char sysPath[MAX_PATH];
    if (!SetupGetDriverPath(sysPath, MAX_PATH)) return false;

    char ntPath[MAX_PATH + 8];
    snprintf(ntPath, sizeof(ntPath), "\\??\\%s", sysPath);

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, "nanahira", SERVICE_ALL_ACCESS);
    if (svc) {
        ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
            SERVICE_NO_CHANGE, ntPath, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr);
    } else {
        svc = CreateServiceA(scm, "nanahira", "Nanahira",
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            ntPath, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    StartServiceA(svc, 0, nullptr);
    DWORD err = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return err == ERROR_SUCCESS || err == ERROR_SERVICE_ALREADY_RUNNING;
}

static void SetupReboot() {
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        TOKEN_PRIVILEGES tp = {};
        LookupPrivilegeValueA(nullptr, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
        CloseHandle(tok);
    }
    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM);
}

static void SetupPrintRow(const char* label, bool ok, bool canAuto) {
    if (ok) {
        printf("  " CLR_GREEN "[OK]" CLR_RESET "  %-32s\n", label);
    } else if (canAuto) {
        printf("  " CLR_RED "[!!]" CLR_RESET "  %-32s" CLR_GRAY " auto-fix available\n" CLR_RESET, label);
    } else {
        printf("  " CLR_RED "[!!]" CLR_RESET "  %-32s" CLR_YELLOW " manual required\n" CLR_RESET, label);
    }
}

static char SetupReadKey(const char* prompt) {
    printf("%s", prompt);
    fflush(stdout);
    char c = (char)tolower((unsigned char)_getch());
    printf("%c\n", c);
    return c;
}

static bool RunSetupWizard() {
    SetConsoleTitleA("Nanahira — Setup");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    EnableAnsiConsole();

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SMALL_RECT rect = { 0, 0, 99, 34 };
    SetConsoleWindowInfo(hOut, TRUE, &rect);

    printf("\n");
    printf(CLR_PURPLE CLR_BOLD "  N A N A H I R A\n" CLR_RESET);
    printf(CLR_GRAY   "  Setup Wizard  —  v3.0.0  —  by Kiy0w0\n\n" CLR_RESET);

    BOOL isAdmin = FALSE;
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION elev = {};
        DWORD sz = sizeof(elev);
        if (GetTokenInformation(tok, TokenElevation, &elev, sz, &sz))
            isAdmin = elev.TokenIsElevated;
        CloseHandle(tok);
    }

    if (!isAdmin) {
        printf("  " CLR_RED "[!!]" CLR_RESET "  Not running as Administrator.\n");
        printf("  " CLR_GRAY "Right-click nanahira.exe → Run as administrator.\n\n" CLR_RESET);
        SetupReadKey("  Press any key to exit...");
        return false;
    }

    printf(CLR_WHITE "  Checking system requirements...\n\n" CLR_RESET);

    bool testSign   = SetupCheckTestSigning();
    bool secureBoot = SetupCheckSecureBootDisabled();
    bool hvci       = SetupCheckHvciDisabled();
    bool cargoOk    = SetupCheckCargoInstalled();

    char driverPath[MAX_PATH];
    bool driverFound = SetupGetDriverPath(driverPath, MAX_PATH);

    SetupPrintRow("Test Signing enabled",    testSign,    true);
    SetupPrintRow("Secure Boot disabled",    secureBoot,  false);
    SetupPrintRow("Memory Integrity OFF",    hvci,        true);
    SetupPrintRow("driver.sys present",      driverFound, false);
    SetupPrintRow("pdb-parser (Rust/Cargo)", cargoOk,     false);

    if (!cargoOk) {
        printf("  " CLR_YELLOW "  Rust not found — offsets.h may be outdated for this\n" CLR_RESET);
        printf("  " CLR_YELLOW "  Windows build. Install Rust, rebuild driver before use.\n" CLR_RESET);
        printf("  " CLR_GRAY   "  https://rustup.rs\n\n" CLR_RESET);
    }

    printf("\n");

    if (!driverFound) {
        printf("  " CLR_RED "driver.sys not found at:\n" CLR_RESET);
        printf("  " CLR_GRAY "  %s\n\n" CLR_RESET, driverPath);
        printf("  " CLR_WHITE "Build the driver project (Release x64) first.\n\n" CLR_RESET);
        SetupReadKey("  Press any key to exit...");
        return false;
    }

    if (!SetupValidateDriverPE(driverPath)) {
        printf("  " CLR_RED "driver.sys is not a valid x64 PE:\n" CLR_RESET);
        printf("  " CLR_GRAY "  %s\n\n" CLR_RESET, driverPath);
        printf("  " CLR_WHITE "The file is corrupt or built for wrong architecture.\n" CLR_RESET);
        printf("  " CLR_WHITE "Rebuild the driver project (Release x64) and run again.\n\n" CLR_RESET);
        SetupReadKey("  Press any key to exit...");
        return false;
    }

    bool needRestart = false;

    if (!testSign) {
        printf(CLR_YELLOW "  [Test Signing] is disabled.\n" CLR_RESET);
        char c = SetupReadKey("  [A]uto enable  /  [S]kip > ");
        if (c == 'a') {
            if (SetupEnableTestSigning()) {
                printf("  " CLR_GREEN "Test Signing enabled. Restart required.\n\n" CLR_RESET);
                needRestart = true;
            } else {
                printf("  " CLR_RED "Failed. Run manually: bcdedit /set testsigning on\n\n" CLR_RESET);
            }
        } else {
            printf("  " CLR_GRAY "Skipped.\n\n" CLR_RESET);
        }
    }

    if (!secureBoot) {
        printf(CLR_YELLOW "  [Secure Boot] is enabled — must be disabled in UEFI BIOS.\n" CLR_RESET);
        printf(CLR_WHITE  "  Restart → BIOS → Security → Secure Boot → Disabled\n\n" CLR_RESET);
        SetupReadKey("  Press any key to continue...");
        printf("\n");
    }

    if (!hvci) {
        printf(CLR_YELLOW "  [Memory Integrity] is enabled.\n" CLR_RESET);
        char c = SetupReadKey("  [A]uto disable  /  [M]anual guide  /  [S]kip > ");
        if (c == 'a') {
            if (SetupDisableHvci()) {
                printf("  " CLR_GREEN "Memory Integrity disabled. Restart required.\n\n" CLR_RESET);
                needRestart = true;
            } else {
                printf("  " CLR_RED "Registry write failed.\n\n" CLR_RESET);
            }
        } else if (c == 'm') {
            printf("\n  " CLR_WHITE "Windows Security → Device Security → Core Isolation\n" CLR_RESET);
            printf("  " CLR_WHITE "→ Memory Integrity → Off\n\n" CLR_RESET);
            SetupReadKey("  Press any key after disabling...");
            printf("\n");
        } else {
            printf("  " CLR_GRAY "Skipped.\n\n" CLR_RESET);
        }
    }

    if (needRestart) {
        printf(CLR_YELLOW "  Restart required for changes to take effect.\n" CLR_RESET);
        char c = SetupReadKey("  [R]estart now  /  [L]ater > ");
        if (c == 'r') {
            printf("  " CLR_WHITE "Restarting...\n" CLR_RESET);
            Sleep(1000);
            SetupReboot();
            Sleep(5000);
        }
        printf("\n  " CLR_GRAY "Run nanahira.exe again after restart.\n\n" CLR_RESET);
        SetupReadKey("  Press any key to exit...");
        return false;
    }

    printf(CLR_WHITE "  Loading driver..." CLR_RESET);
    fflush(stdout);

    if (!SetupLoadDriver()) {
        DWORD loadErr = GetLastError();

        if (loadErr == 577) {
            printf(CLR_YELLOW " unsigned\n\n" CLR_RESET);
            printf("  " CLR_WHITE "driver.sys must be signed before loading.\n\n" CLR_RESET);
            printf("  " CLR_CYAN "  Run: sign_driver.bat" CLR_WHITE " as Administrator\n" CLR_RESET);
            printf("  " CLR_GRAY "  Then run nanahira.exe again.\n\n" CLR_RESET);
            SetupReadKey("  Press any key to exit...");
            return false;
        } else if (loadErr == 193) {
            printf(CLR_YELLOW " bad format\n\n" CLR_RESET);
            printf("  " CLR_WHITE "Stale service entry detected. Cleaning up..." CLR_RESET);
            fflush(stdout);
            SetupDeleteDriverService();
            printf(CLR_GREEN " OK\n" CLR_RESET);
            printf("  " CLR_WHITE "  Loading driver..." CLR_RESET);
            fflush(stdout);
            if (!SetupLoadDriver()) {
                printf(CLR_RED " failed (error %lu)\n\n" CLR_RESET, GetLastError());
                printf("  " CLR_GRAY "Rebuild the driver project and run again.\n\n" CLR_RESET);
                SetupReadKey("  Press any key to exit...");
                return false;
            }
            printf(CLR_GREEN " OK\n" CLR_RESET);
        } else {
            printf(CLR_RED " failed (error %lu)\n\n" CLR_RESET, loadErr);
            printf("  " CLR_GRAY "Ensure Test Signing is ON and Secure Boot is OFF,\n" CLR_RESET);
            printf("  " CLR_GRAY "then run nanahira.exe again.\n\n" CLR_RESET);
            SetupReadKey("  Press any key to exit...");
            return false;
        }
    } else {
        printf(CLR_GREEN " OK\n" CLR_RESET);
    }

    printf("\n  " CLR_GREEN "Driver loaded." CLR_RESET " Restarting to connect...\n\n" CLR_RESET);
    Sleep(1000);

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    ShellExecuteA(nullptr, "runas", exePath, nullptr, nullptr, SW_SHOW);
    return false;
}
