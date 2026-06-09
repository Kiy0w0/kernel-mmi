#pragma once
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <string>
#include <vector>

struct ProcessEntry {
    DWORD       pid;
    std::string name;
};

struct ToastMsg {
    std::string text;
    float       r, g, b;
    DWORD       expireAt;
};

class NanahiraGUI {
public:
    bool Initialize();
    void Run();
    void Shutdown();
    void OnResize(UINT w, UINT h);

private:
    HWND    m_hwnd    = nullptr;
    bool    m_running = true;

    ID3D11Device*           m_device    = nullptr;
    ID3D11DeviceContext*    m_context   = nullptr;
    IDXGISwapChain*         m_swapChain = nullptr;
    ID3D11RenderTargetView* m_rtv       = nullptr;

    bool CreateDeviceD3D();
    void CleanupDevice();
    void CreateRenderTarget();
    void CleanupRenderTarget();

    char m_searchBuf[256] = {};

    std::vector<ProcessEntry> m_processes;
    int  m_selectedProc = -1;

    std::vector<std::string> m_dllPaths;
    int  m_selectedDll = -1;

    bool m_eraseHeaders   = true;
    bool m_stompHeaders   = false;
    bool m_threadHijack   = false;
    bool m_skipTls        = false;
    bool m_skipExceptions = false;
    int  m_mode           = 0;

    std::string m_statusMsg        = "Ready";
    float       m_progress         = 0.0f;
    bool        m_driverOnline     = false;
    bool        m_prevDriverOnline = false;
    void*       m_sharedHdr        = nullptr;

    bool        m_showSettings     = false;
    bool        m_alwaysOnTop      = false;
    bool        m_discordRpc       = true;
    int         m_injectCount      = 0;
    bool        m_injecting        = false;
    DWORD       m_injectDeadline   = 0;

    struct AltInjectJob {
        int          mode;
        DWORD        pid;
        std::wstring path;
        bool         result;
    };
    HANDLE        m_altThread = nullptr;
    AltInjectJob* m_altJob    = nullptr;

    std::vector<ToastMsg> m_toasts;
    void AddToast(const char* msg, float r, float g, float b);

    void SetupStyle();
    void DrawTitleBar();
    void DrawMainContent();
    void DrawProcessPanel();
    void DrawDllPanel();
    void DrawStatusBar();
    void DrawToasts();
    void DrawSettingsModal();
    void UpdateDiscordRpc(const char* state);

    void RefreshProcesses();
    bool OpenDllDialog();
    void DoInject();
    void PollInject();
    void CheckDriverStatus();
};
