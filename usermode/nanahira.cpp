
#include "nanahira.h"
#include "discord_rpc.h"
#include <conio.h>

#define DISCORD_APP_ID "1472658353913204737"

INJECT_MODE g_InjectMode = MODE_KERNEL;

typedef struct { int r, g, b; } RGB;

static RGB LerpColor(RGB a, RGB b, float t) {
    RGB out;
    out.r = (int)(a.r + (b.r - a.r) * t);
    out.g = (int)(a.g + (b.g - a.g) * t);
    out.b = (int)(a.b + (b.b - a.b) * t);
    return out;
}

static void PrintGradientLine(const char* text, RGB start, RGB end) {
    int len = (int)strlen(text);
    for (int i = 0; i < len; i++) {
        float t = (len > 1) ? (float)i / (float)(len - 1) : 0.0f;
        RGB c = LerpColor(start, end, t);
        printf("\033[38;2;%d;%d;%dm%c", c.r, c.g, c.b, text[i]);
    }
    printf(CLR_RESET);
}

static void PrintBanner(void) {
    printf("\n");

    RGB gradStart = { 180, 100, 255 };
    RGB gradEnd   = { 80, 200, 255 };

    PrintGradientLine("  N A N A H I R A", gradStart, gradEnd);
    printf("\n");
    PrintGradientLine("  Kernel Manual Map Injector", gradEnd, gradStart);
    printf("\n\n");

    printf("  " CLR_DIM "by kiy0w0" CLR_RESET "\n");
    printf("  " CLR_DIM "v%d.%d.%d" CLR_RESET "\n", PROTO_VER_MAJOR, PROTO_VER_MINOR, 0);
    printf("  " CLR_DIM "https://github.com/Kiy0w0/kernel-mmi" CLR_RESET "\n");
    printf("\n");

    printf("  " CLR_PURPLE);
    for (int i = 0; i < 50; i++) printf("-");
    printf(CLR_RESET "\n\n");
}

static void PrintStatus(const char* icon, const char* color, const char* msg) {
    printf("  %s %s%s%s\n", icon, color, msg, CLR_RESET);
}

static void PrintInfo(const char* msg)    { PrintStatus("*", CLR_CYAN, msg); }
static void PrintOk(const char* msg)      { PrintStatus("+", CLR_GREEN, msg); }
static void PrintErr(const char* msg)     { PrintStatus("x", CLR_RED, msg); }
static void PrintWarn(const char* msg)    { PrintStatus("!", CLR_YELLOW, msg); }

static void PrintStep(int step, int total, const char* msg) {
    printf("  " CLR_PURPLE "[%d/%d]" CLR_RESET " %s%s%s\n",
        step, total, CLR_WHITE, msg, CLR_RESET);
}

static void DrawProgressBar(int pct, const char* label) {
    const int barWidth = 40;
    int filled = (pct * barWidth) / 100;

    printf("\r  " CLR_PURPLE "|" CLR_RESET " ");

    for (int i = 0; i < barWidth; i++) {
        float t = (float)i / (float)barWidth;
        int r = (int)(180 + (80 - 180) * t);
        int g = (int)(100 + (200 - 100) * t);
        int b = (int)(255 + (255 - 255) * t);

        if (i < filled)
            printf("\033[38;2;%d;%d;%dm#", r, g, b);
        else
            printf(CLR_GRAY ".");
    }

    printf(CLR_RESET " %3d%% " CLR_DIM "%s" CLR_RESET "    ", pct, label);
    fflush(stdout);
}

static SHARED_HEADER* ConnectToDriver(void) {

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    const BYTE* end = (BYTE*)si.lpMaximumApplicationAddress;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;

        if (mbi.State == MEM_COMMIT &&
            mbi.RegionSize >= sizeof(SHARED_HEADER) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READWRITE | PAGE_NOCACHE)) {

            __try {
                volatile SHARED_HEADER* hdr = (volatile SHARED_HEADER*)mbi.BaseAddress;
                if (hdr->Magic   == PROTO_MAGIC &&
                    hdr->Version == ((PROTO_VER_MAJOR << 16) | PROTO_VER_MINOR)) {
                    return (SHARED_HEADER*)mbi.BaseAddress;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        addr = (BYTE*)mbi.BaseAddress + (mbi.RegionSize ? mbi.RegionSize : 4096);
    }

    return NULL;
}

static void DisconnectDriver(SHARED_HEADER* hdr) {

    (void)hdr;
}

static BOOL WaitForResult(SHARED_HEADER* hdr, int timeoutMs) {
    DWORD start = GetTickCount();
    int lastPct = -1;

    while ((int)(GetTickCount() - start) < timeoutMs) {
        LONG status = InterlockedCompareExchange(&hdr->Status, 0, 0);
        LONG pct = InterlockedCompareExchange(&hdr->Progress, 0, 0);

        if (pct != lastPct) {
            DrawProgressBar((int)pct, hdr->Message);
            lastPct = (int)pct;
        }

        if (status == IPC_DONE) {
            DrawProgressBar(100, "Complete");
            printf("\n");
            return TRUE;
        }

        if (status >= IPC_ERR_PROCESS) {

            printf("\n");
            return FALSE;
        }

        Sleep(50);
    }

    printf("\n");
    return FALSE;
}

static const char* GetStatusString(LONG status) {
    switch (status) {
        case IPC_IDLE:           return "Idle";
        case IPC_READY:          return "Ready";
        case IPC_BUSY:           return "Processing";
        case IPC_DONE:           return "Success";
        case IPC_ERR_PROCESS:    return "Failed to access target process";
        case IPC_ERR_ALLOC:      return "Memory allocation failed in target";
        case IPC_ERR_PE:         return "Invalid PE / DLL format";
        case IPC_ERR_SECTIONS:   return "Section mapping failed";
        case IPC_ERR_RELOC:      return "Base relocation processing failed";
        case IPC_ERR_IMPORTS:    return "Import resolution failed";
        case IPC_ERR_PROTECT:    return "Memory protection setup failed";
        case IPC_ERR_ENTRYPOINT: return "DllMain execution failed";
        case IPC_ERR_TIMEOUT:    return "Operation timed out";
        case IPC_ERR_UNKNOWN:    return "Unknown error";
        default:                 return "Unrecognized status";
    }
}

static void InteractiveMode(void) {
    char procName[256]   = { 0 };
    char dllPath[MAX_PATH] = { 0 };
    char modeStr[32]     = { 0 };

    printf("  " CLR_CYAN "Target process name" CLR_RESET ": ");
    fflush(stdout);
    if (!fgets(procName, sizeof(procName), stdin)) return;
    procName[strcspn(procName, "\r\n")] = 0;

    printf("  " CLR_CYAN "DLL path" CLR_RESET ": ");
    fflush(stdout);
    if (!fgets(dllPath, sizeof(dllPath), stdin)) return;
    dllPath[strcspn(dllPath, "\r\n")] = 0;

    printf("  " CLR_CYAN "Mode" CLR_RESET " [kernel/hook/usermode, default=kernel]: ");
    fflush(stdout);
    if (fgets(modeStr, sizeof(modeStr), stdin)) {
        modeStr[strcspn(modeStr, "\r\n")] = 0;
        if (strcmp(modeStr, xor_a("hook")) == 0)     g_InjectMode = MODE_HOOK;
        else if (strcmp(modeStr, xor_a("usermode")) == 0) g_InjectMode = MODE_USERMODE;
        else                                           g_InjectMode = MODE_KERNEL;
    }

    printf("\n");

    if (g_InjectMode == MODE_HOOK) {
        PrintStep(1, 2, xor_a("Locating target process..."));
        DWORD pid = FindProcessId(procName);
        if (!pid) { PrintErr(xor_a("Process not found")); return; }
        char pidMsg[128]; sprintf_s(pidMsg, sizeof(pidMsg), "Found PID %u", pid);
        PrintOk(pidMsg);
        wchar_t wDll[MAX_PATH] = {};
        MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDll, MAX_PATH);
        PrintStep(2, 2, xor_a("Injecting via WinEventHook..."));
        if (HookInjector::inject(pid, wDll)) PrintOk(xor_a("Hook injection successful"));
        else PrintErr(xor_a("Hook injection failed"));
        return;
    }

    if (g_InjectMode == MODE_USERMODE) {
        PrintStep(1, 2, xor_a("Locating target process..."));
        DWORD pid = FindProcessId(procName);
        if (!pid) { PrintErr(xor_a("Process not found")); return; }
        char pidMsg[128]; sprintf_s(pidMsg, sizeof(pidMsg), "Found PID %u", pid);
        PrintOk(pidMsg);
        wchar_t wDll[MAX_PATH] = {};
        MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDll, MAX_PATH);
        PrintStep(2, 2, xor_a("Injecting via usermode fallback..."));
        if (UmInjector::inject(pid, wDll)) PrintOk(xor_a("Usermode injection successful"));
        else PrintErr(xor_a("Usermode injection failed"));
        return;
    }

    PrintStep(1, 6, "Locating target process...");

    DWORD pid = FindProcessId(procName);
    if (pid == 0) {
        char msg[512];
        sprintf_s(msg, sizeof(msg), "Process '%s' not found — is it running?", procName);
        PrintErr(msg);
        return;
    }

    char pidMsg[256];
    sprintf_s(pidMsg, sizeof(pidMsg), "Found: %s (PID %u)", procName, pid);
    PrintOk(pidMsg);

    PrintStep(2, 6, "Reading DLL file...");

    DWORD dllSize = 0;
    BYTE* dllData = ReadFileToBuffer(dllPath, &dllSize);
    if (!dllData) {
        char msg[512];
        sprintf_s(msg, sizeof(msg), "Cannot read: %s", dllPath);
        PrintErr(msg);
        return;
    }

    char sizeMsg[256];
    sprintf_s(sizeMsg, sizeof(sizeMsg), "DLL loaded: %u bytes (%.2f KB)", dllSize, dllSize / 1024.0);
    PrintOk(sizeMsg);

    if (dllSize > MAX_PAYLOAD_SIZE) {
        PrintErr("DLL exceeds maximum supported size (15 MB)");
        free(dllData);
        return;
    }

    PrintStep(3, 6, "Validating PE format...");

    if (!QuickValidatePE(dllData, dllSize)) {
        PrintErr("File is not a valid x64 DLL");
        free(dllData);
        return;
    }
    PrintOk("Valid x64 DLL confirmed");

    PrintStep(4, 6, "Connecting to driver...");

    SHARED_HEADER* hdr = ConnectToDriver();
    if (!hdr) {
        PrintErr("Cannot connect — is the driver loaded?");
        PrintWarn("Load driver first: kdmapper.exe driver.sys");
        free(dllData);
        return;
    }

    LONG drvStatus = InterlockedCompareExchange(&hdr->Status, 0, 0);
    if (drvStatus == IPC_BUSY) {
        PrintErr("Driver is busy with another operation");
        free(dllData);
        DisconnectDriver(hdr);
        return;
    }

    PrintOk("Driver connection established");

    PrintStep(5, 6, "Preparing payload...");

    BYTE* payloadDst = (BYTE*)hdr + PAYLOAD_DATA_OFFSET;
    memcpy(payloadDst, dllData, dllSize);

    hdr->TargetPid   = pid;
    hdr->PayloadSize  = dllSize;
    hdr->Flags        = INJ_FLAG_ERASE_HEADERS;
    hdr->BaseAddr     = 0;
    InterlockedExchange(&hdr->Progress, 0);

    free(dllData);
    PrintOk("Payload written to shared memory");

    PrintStep(6, 6, "Sending injection command...");
    printf("\n");

    InterlockedExchange(&hdr->Command, IPC_CMD_INJECT);

    if (WaitForResult(hdr, POLL_TIMEOUT_MS)) {
        printf("\n");
        printf("  " CLR_GREEN CLR_BOLD "INJECTION SUCCESSFUL" CLR_RESET "\n");

        char baseMsg[256];
        sprintf_s(baseMsg, sizeof(baseMsg), "Mapped base: 0x%llX", hdr->BaseAddr);
        PrintOk(baseMsg);

        char targetMsg[256];
        sprintf_s(targetMsg, sizeof(targetMsg), "Target: %s (PID %u)", procName, pid);
        PrintInfo(targetMsg);
    }
    else {
        printf("\n");
        LONG errStatus = InterlockedCompareExchange(&hdr->Status, 0, 0);
        printf("  " CLR_RED CLR_BOLD "INJECTION FAILED" CLR_RESET "\n");

        char errMsg[256];
        sprintf_s(errMsg, sizeof(errMsg), "Error: %s (code %ld)", GetStatusString(errStatus), errStatus);
        PrintErr(errMsg);

        if (hdr->Message[0]) {
            char drvMsg[256];
            sprintf_s(drvMsg, sizeof(drvMsg), "Driver: %s", hdr->Message);
            PrintWarn(drvMsg);
        }
    }

    printf("\n");
    DisconnectDriver(hdr);

    Discord_UpdatePresence(xor_a("Finished"), xor_a("Nanahira Kernel Injector"), xor_a("nanahira"), xor_a("Kernel Manual Map Injector"), xor_a("kiy0w0"), xor_a("by kiy0w0"));
}

int main(int argc, char* argv[])
{

    SetConsoleTitleA("nanahira — Kernel Manual Map Injector");

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    EnableAnsiConsole();

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SMALL_RECT rect = { 0, 0, 99, 39 };
    SetConsoleWindowInfo(hOut, TRUE, &rect);

    PrintBanner();

    Discord_Init(DISCORD_APP_ID);
    Discord_UpdatePresence("Idle", "Nanahira Kernel Injector", "nanahira", "Kernel Manual Map Injector", "kiy0w0", "by kiy0w0");

    BOOL isAdmin = FALSE;
    {
        HANDLE token = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elev;
            DWORD size = sizeof(elev);
            if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size)) {
                isAdmin = elev.TokenIsElevated;
            }
            CloseHandle(token);
        }
    }

    if (!isAdmin) {
        PrintWarn("Not running as Administrator");
        PrintWarn("Some operations may fail without elevation");
        printf("\n");
    } else {
        PrintOk("Running as Administrator");
        printf("\n");
    }

    if (argc >= 3) {
        const char* procName = argv[1];
        const char* dllPath  = argv[2];

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], xor_a("--mode=hook")) == 0)     g_InjectMode = MODE_HOOK;
            if (strcmp(argv[i], xor_a("--mode=usermode")) == 0) g_InjectMode = MODE_USERMODE;
            if (strcmp(argv[i], xor_a("--mode=kernel")) == 0)   g_InjectMode = MODE_KERNEL;
        }

        if (g_InjectMode == MODE_HOOK) {
            PrintStep(1, 2, xor_a("Locating target process..."));
            DWORD pid = FindProcessId(procName);
            if (!pid) { PrintErr(xor_a("Process not found")); _getch(); return 1; }
            wchar_t wDll[MAX_PATH] = {};
            MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDll, MAX_PATH);
            PrintStep(2, 2, xor_a("Injecting via WinEventHook..."));
            if (HookInjector::inject(pid, wDll)) PrintOk(xor_a("Hook injection successful"));
            else PrintErr(xor_a("Hook injection failed"));
            printf("\n  Press any key...\n"); _getch();
            return 0;
        }

        if (g_InjectMode == MODE_USERMODE) {
            PrintStep(1, 2, xor_a("Locating target process..."));
            DWORD pid = FindProcessId(procName);
            if (!pid) { PrintErr(xor_a("Process not found")); _getch(); return 1; }
            wchar_t wDll[MAX_PATH] = {};
            MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDll, MAX_PATH);
            PrintStep(2, 2, xor_a("Injecting via usermode fallback..."));
            if (UmInjector::inject(pid, wDll)) PrintOk(xor_a("Usermode injection successful"));
            else PrintErr(xor_a("Usermode injection failed"));
            printf("\n  Press any key...\n"); _getch();
            return 0;
        }

        PrintStep(1, 6, xor_a("Locating target process..."));

        DWORD pid = FindProcessId(procName);
        if (pid == 0) {
            char msg[512];
            sprintf_s(msg, sizeof(msg), "Process '%s' not found", procName);
            PrintErr(msg);
            printf("\n  Press any key to exit...\n");
            _getch();
            return 1;
        }

        char pidMsg[256];
        sprintf_s(pidMsg, sizeof(pidMsg), "Found: %s (PID %u)", procName, pid);
        PrintOk(pidMsg);

        PrintStep(2, 6, "Reading DLL file...");

        DWORD dllSize = 0;
        BYTE* dllData = ReadFileToBuffer(dllPath, &dllSize);
        if (!dllData) {
            char msg[512];
            sprintf_s(msg, sizeof(msg), "Cannot read: %s", dllPath);
            PrintErr(msg);
            printf("\n  Press any key to exit...\n");
            _getch();
            return 1;
        }

        char sizeMsg[256];
        sprintf_s(sizeMsg, sizeof(sizeMsg), "DLL loaded: %u bytes (%.2f KB)", dllSize, dllSize / 1024.0);
        PrintOk(sizeMsg);

        if (dllSize > MAX_PAYLOAD_SIZE) {
            PrintErr("DLL exceeds 15 MB limit");
            free(dllData);
            printf("\n  Press any key to exit...\n");
            _getch();
            return 1;
        }

        PrintStep(3, 6, "Validating PE format...");

        if (!QuickValidatePE(dllData, dllSize)) {
            PrintErr("Not a valid x64 DLL");
            free(dllData);
            printf("\n  Press any key to exit...\n");
            _getch();
            return 1;
        }
        PrintOk("Valid x64 DLL");

        PrintStep(4, 6, "Connecting to driver...");

        SHARED_HEADER* hdr = ConnectToDriver();
        if (!hdr) {
            PrintErr("Cannot connect — load driver first");
            free(dllData);
            printf("\n  Press any key to exit...\n");
            _getch();
            return 1;
        }
        PrintOk("Connected to driver");

        PrintStep(5, 6, "Preparing payload...");

        BYTE* payloadDst = (BYTE*)hdr + PAYLOAD_DATA_OFFSET;
        memcpy(payloadDst, dllData, dllSize);
        hdr->TargetPid  = pid;
        hdr->PayloadSize = dllSize;
        hdr->Flags       = INJ_FLAG_ERASE_HEADERS;
        hdr->BaseAddr    = 0;
        InterlockedExchange(&hdr->Progress, 0);
        free(dllData);
        PrintOk("Payload ready");

        PrintStep(6, 6, "Injecting...");
        printf("\n");

        InterlockedExchange(&hdr->Command, IPC_CMD_INJECT);

        if (WaitForResult(hdr, POLL_TIMEOUT_MS)) {
            printf("\n");
            printf("  " CLR_GREEN CLR_BOLD "INJECTION SUCCESSFUL" CLR_RESET "\n");
            char baseMsg[256];
            sprintf_s(baseMsg, sizeof(baseMsg), "Mapped base: 0x%llX", hdr->BaseAddr);
            PrintOk(baseMsg);
        } else {
            printf("\n");
            LONG err = InterlockedCompareExchange(&hdr->Status, 0, 0);
            printf("  " CLR_RED CLR_BOLD "INJECTION FAILED" CLR_RESET "\n");
            char errMsg[256];
            sprintf_s(errMsg, sizeof(errMsg), "Error: %s (code %ld)", GetStatusString(err), err);
            PrintErr(errMsg);
        }

        printf("\n");
        DisconnectDriver(hdr);

        Discord_UpdatePresence(xor_a("Finished"), xor_a("Nanahira Kernel Injector"), xor_a("nanahira"), xor_a("Kernel Manual Map Injector"), xor_a("kiy0w0"), xor_a("by kiy0w0"));

        printf("  Press any key to exit...\n");
        _getch();
        Discord_Shutdown();
        return 0;
    }
    } else {
        Discord_UpdatePresence(xor_a("Waiting for input"), xor_a("Nanahira Kernel Injector"), xor_a("nanahira"), xor_a("Kernel Manual Map Injector"), xor_a("kiy0w0"), xor_a("by kiy0w0"));
        InteractiveMode();
        printf("\n  Press any key to exit...\n");
        _getch();
        Discord_Shutdown();
        return 0;
    }
}

