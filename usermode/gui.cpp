#define NOMINMAX
#include "gui.h"
#include "discord_rpc.h"
#include "../shared/protocol.h"
#include "hook_inject.h"
#include "usermode_inject.h"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include <d3d11.h>
#include <dxgi.h>
#include <dwmapi.h>
#pragma push_macro("UNICODE")
#undef UNICODE
#include <tlhelp32.h>
#pragma pop_macro("UNICODE")
#include <commdlg.h>
#include <windowsx.h>
#include <algorithm>
#include <fstream>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#include <shellapi.h>

extern SHARED_HEADER* ConnectToDriver();
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static NanahiraGUI* g_inst = nullptr;

static constexpr ImVec4 kBgMain   = { 10/255.f,  8/255.f, 18/255.f, 1.f };
static constexpr ImVec4 kBgPanel  = { 16/255.f, 13/255.f, 30/255.f, 1.f };
static constexpr ImVec4 kBgHdr    = { 22/255.f, 17/255.f, 42/255.f, 1.f };
static constexpr ImVec4 kAccent   = {139/255.f, 92/255.f,246/255.f, 1.f };
static constexpr ImVec4 kAccentHv = {167/255.f,139/255.f,250/255.f, 1.f };
static constexpr ImVec4 kAccentAc = {109/255.f, 68/255.f,210/255.f, 1.f };
static constexpr ImVec4 kText     = {226/255.f,224/255.f,255/255.f, 1.f };
static constexpr ImVec4 kTextDim  = {107/255.f,104/255.f,128/255.f, 1.f };
static constexpr ImVec4 kGreen    = { 34/255.f,197/255.f, 94/255.f, 1.f };
static constexpr ImVec4 kRed      = {239/255.f, 68/255.f, 68/255.f, 1.f };
static constexpr ImVec4 kYellow   = {245/255.f,158/255.f, 11/255.f, 1.f };
static constexpr ImVec4 kBorder   = { 45/255.f, 37/255.f, 80/255.f, 1.f };

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
    case WM_SIZE:
        if (g_inst && wParam != SIZE_MINIMIZED)
            g_inst->OnResize(LOWORD(lParam), HIWORD(lParam));
        return 0;
    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProcW(hWnd, msg, wParam, lParam);
        if (hit == HTCLIENT) {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ScreenToClient(hWnd, &pt);
            RECT rc; GetClientRect(hWnd, &rc);
            if (pt.y < 36 && pt.x < rc.right - 72)
                return HTCAPTION;
        }
        return hit;
    }
    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

bool NanahiraGUI::CreateDeviceD3D() {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount                        = 2;
    sd.BufferDesc.Format                  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                       = m_hwnd;
    sd.SampleDesc.Count                   = 1;
    sd.Windowed                           = TRUE;
    sd.SwapEffect                         = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL levels[]      = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL featureLevel;
    return SUCCEEDED(D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        levels, 2, D3D11_SDK_VERSION, &sd,
        &m_swapChain, &m_device, &featureLevel, &m_context));
}

void NanahiraGUI::CreateRenderTarget() {
    ID3D11Texture2D* back = nullptr;
    m_swapChain->GetBuffer(0, IID_PPV_ARGS(&back));
    if (back) { m_device->CreateRenderTargetView(back, nullptr, &m_rtv); back->Release(); }
}

void NanahiraGUI::CleanupRenderTarget() {
    if (m_rtv) { m_rtv->Release(); m_rtv = nullptr; }
}

void NanahiraGUI::CleanupDevice() {
    CleanupRenderTarget();
    if (m_swapChain) { m_swapChain->Release(); m_swapChain = nullptr; }
    if (m_context)   { m_context->Release();   m_context   = nullptr; }
    if (m_device)    { m_device->Release();    m_device    = nullptr; }
}

void NanahiraGUI::OnResize(UINT w, UINT h) {
    if (!m_swapChain) return;
    CleanupRenderTarget();
    m_swapChain->ResizeBuffers(0, w, h, DXGI_FORMAT_UNKNOWN, 0);
    CreateRenderTarget();
}

bool NanahiraGUI::Initialize() {
    g_inst = this;

    HICON hIcon = (HICON)LoadImageW(
        GetModuleHandleW(nullptr),
        MAKEINTRESOURCEW(101),
        IMAGE_ICON, 0, 0,
        LR_DEFAULTSIZE | LR_SHARED
    );

    WNDCLASSEXW wc   = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon         = hIcon;
    wc.hIconSm       = hIcon;
    wc.lpszClassName = L"NanahiraWindow";
    RegisterClassExW(&wc);

    int cx = (GetSystemMetrics(SM_CXSCREEN) - 860) / 2;
    int cy = (GetSystemMetrics(SM_CYSCREEN) - 540) / 2;
    m_hwnd = CreateWindowExW(
        WS_EX_APPWINDOW, L"NanahiraWindow", L"Nanahira",
        WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_SYSMENU,
        cx, cy, 860, 540, nullptr, nullptr, wc.hInstance, nullptr);

    if (hIcon) {
        SendMessageW(m_hwnd, WM_SETICON, ICON_BIG,   (LPARAM)hIcon);
        SendMessageW(m_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }

    MARGINS mg = { 1,1,1,1 };
    DwmExtendFrameIntoClientArea(m_hwnd, &mg);
#if defined(DWMWA_WINDOW_CORNER_PREFERENCE)
    DWORD corner = 3;
    DwmSetWindowAttribute(m_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
#endif

    if (!CreateDeviceD3D()) { Shutdown(); return false; }
    CreateRenderTarget();
    ShowWindow(m_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(m_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io     = ImGui::GetIO();
    io.IniFilename  = nullptr;
    ImFontConfig fc;
    fc.OversampleH = 2;
    static const ImWchar fontRanges[] = { 0x0020, 0x00FF, 0x2600, 0x26FF, 0 };
    io.FontDefault = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 15.0f, &fc, fontRanges);
    if (!io.FontDefault) io.FontDefault = io.Fonts->AddFontDefault();

    ImGui_ImplWin32_Init(m_hwnd);
    ImGui_ImplDX11_Init(m_device, m_context);
    SetupStyle();
    RefreshProcesses();
    CheckDriverStatus();
    return true;
}

void NanahiraGUI::SetupStyle() {
    ImGuiStyle& s        = ImGui::GetStyle();
    s.WindowRounding     = 0.f;
    s.ChildRounding      = 6.f;
    s.FrameRounding      = 5.f;
    s.PopupRounding      = 6.f;
    s.ScrollbarRounding  = 4.f;
    s.GrabRounding       = 4.f;
    s.TabRounding        = 5.f;
    s.WindowBorderSize   = 0.f;
    s.ChildBorderSize    = 1.f;
    s.FrameBorderSize    = 0.f;
    s.ItemSpacing        = { 8.f, 5.f };
    s.WindowPadding      = { 12.f, 10.f };
    s.FramePadding       = { 8.f, 5.f };
    s.ScrollbarSize      = 8.f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]             = kBgMain;
    c[ImGuiCol_ChildBg]              = kBgPanel;
    c[ImGuiCol_PopupBg]              = kBgPanel;
    c[ImGuiCol_Border]               = kBorder;
    c[ImGuiCol_BorderShadow]         = { 0,0,0,0 };
    c[ImGuiCol_FrameBg]              = { 20/255.f,16/255.f,36/255.f,1.f };
    c[ImGuiCol_FrameBgHovered]       = { 28/255.f,22/255.f,50/255.f,1.f };
    c[ImGuiCol_FrameBgActive]        = { 35/255.f,28/255.f,65/255.f,1.f };
    c[ImGuiCol_TitleBg]              = kBgHdr;
    c[ImGuiCol_TitleBgActive]        = kBgHdr;
    c[ImGuiCol_Header]               = { kAccent.x,kAccent.y,kAccent.z,0.25f };
    c[ImGuiCol_HeaderHovered]        = { kAccent.x,kAccent.y,kAccent.z,0.40f };
    c[ImGuiCol_HeaderActive]         = { kAccent.x,kAccent.y,kAccent.z,0.60f };
    c[ImGuiCol_Button]               = { 32/255.f,26/255.f,56/255.f,1.f };
    c[ImGuiCol_ButtonHovered]        = { kAccent.x,kAccent.y,kAccent.z,0.70f };
    c[ImGuiCol_ButtonActive]         = kAccentAc;
    c[ImGuiCol_ScrollbarBg]          = { 0,0,0,0 };
    c[ImGuiCol_ScrollbarGrab]        = { kAccent.x,kAccent.y,kAccent.z,0.40f };
    c[ImGuiCol_ScrollbarGrabHovered] = { kAccent.x,kAccent.y,kAccent.z,0.70f };
    c[ImGuiCol_ScrollbarGrabActive]  = kAccent;
    c[ImGuiCol_CheckMark]            = kAccentHv;
    c[ImGuiCol_SliderGrab]           = kAccent;
    c[ImGuiCol_SliderGrabActive]     = kAccentHv;
    c[ImGuiCol_Separator]            = kBorder;
    c[ImGuiCol_SeparatorHovered]     = { kAccent.x,kAccent.y,kAccent.z,0.50f };
    c[ImGuiCol_SeparatorActive]      = kAccent;
    c[ImGuiCol_Tab]                  = { 22/255.f,17/255.f,42/255.f,1.f };
    c[ImGuiCol_TabHovered]           = { kAccent.x,kAccent.y,kAccent.z,0.50f };
    c[ImGuiCol_TabActive]            = { kAccent.x,kAccent.y,kAccent.z,0.80f };
    c[ImGuiCol_TabUnfocused]         = c[ImGuiCol_Tab];
    c[ImGuiCol_TabUnfocusedActive]   = c[ImGuiCol_TabActive];
    c[ImGuiCol_PlotHistogram]        = kAccent;
    c[ImGuiCol_PlotHistogramHovered] = kAccentHv;
    c[ImGuiCol_TextSelectedBg]       = { kAccent.x,kAccent.y,kAccent.z,0.35f };
    c[ImGuiCol_Text]                 = kText;
    c[ImGuiCol_TextDisabled]         = kTextDim;
    c[ImGuiCol_NavHighlight]         = kAccent;
    c[ImGuiCol_ResizeGrip]           = { kAccent.x,kAccent.y,kAccent.z,0.20f };
    c[ImGuiCol_ResizeGripHovered]    = { kAccent.x,kAccent.y,kAccent.z,0.50f };
    c[ImGuiCol_ResizeGripActive]     = kAccent;
}

void NanahiraGUI::Run() {
    MSG msg = {};
    while (m_running) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) m_running = false;
        }
        if (!m_running) break;

        PollInject();

        static DWORD lastCheck = 0;
        if (GetTickCount() - lastCheck > 2000) {
            CheckDriverStatus();
            lastCheck = GetTickCount();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGuiIO& io = ImGui::GetIO();
        ImGui::SetNextWindowPos({ 0, 0 });
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("##root", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse);

        DrawTitleBar();
        DrawMainContent();
        DrawStatusBar();
        DrawToasts();

        ImGui::End();

        const float clear[4] = { kBgMain.x, kBgMain.y, kBgMain.z, 1.f };
        m_context->OMSetRenderTargets(1, &m_rtv, nullptr);
        m_context->ClearRenderTargetView(m_rtv, clear);
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        m_swapChain->Present(1, 0);
    }
}

void NanahiraGUI::Shutdown() {
    if (ImGui::GetCurrentContext()) {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
    }
    CleanupDevice();
    if (m_hwnd) { DestroyWindow(m_hwnd); m_hwnd = nullptr; }
    UnregisterClassW(L"NanahiraWindow", GetModuleHandleW(nullptr));
}

void NanahiraGUI::AddToast(const char* msg, float r, float g, float b) {
    m_toasts.push_back({ msg, r, g, b, GetTickCount() + 3000 });
}

void NanahiraGUI::DrawTitleBar() {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgHdr);
    ImGui::BeginChild("##tb", { 0.f, 36.f }, false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImGui::SetCursorPos({ 12.f, 9.f });
    ImGui::PushStyleColor(ImGuiCol_Text, kAccentHv);
    ImGui::Text("N A N A H I R A");
    ImGui::PopStyleColor();
    ImGui::SameLine(0.f, 8.f);
    ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
    ImGui::Text("v3.0.0");
    ImGui::PopStyleColor();

    float w = ImGui::GetWindowWidth();

    float dotX = w - 268.f;
    float dotY = ImGui::GetCursorScreenPos().y + 18.f - ImGui::GetScrollY();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    if (m_driverOnline) {
        float pulse = 0.55f + 0.45f * sinf((float)ImGui::GetTime() * 4.0f);
        dl->AddCircleFilled({ dotX, dotY }, 5.5f, IM_COL32(80, 255, 120, (int)(60 * pulse)), 16);
        dl->AddCircleFilled({ dotX, dotY }, 3.5f, IM_COL32(60, 230, 100, 255), 16);
    } else {
        dl->AddCircleFilled({ dotX, dotY }, 4.f, IM_COL32(200, 60, 60, 180), 16);
    }

    ImGui::SameLine(w - 255.f);
    ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
    ImGui::SetCursorPosY(9.f);
    ImGui::Text("DRIVER");
    ImGui::PopStyleColor();
    ImGui::SameLine(0.f, 6.f);
    ImGui::PushStyleColor(ImGuiCol_Text, m_driverOnline
        ? ImVec4(0.24f, 0.90f, 0.47f, 1.f)
        : ImVec4(0.87f, 0.27f, 0.27f, 1.f));
    ImGui::SetCursorPosY(9.f);
    ImGui::Text(m_driverOnline ? "loaded >_<" : "offline");
    ImGui::PopStyleColor();

    ImGui::SetCursorPos({ w - 110.f, 5.f });
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0,0,0,0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.25f,0.20f,0.45f,0.7f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.35f,0.28f,0.60f,0.8f));
    if (ImGui::Button(u8"\u2699", { 30.f, 26.f })) ImGui::OpenPopup("##settings_popup");
    ImGui::PopStyleColor(3);

    ImGui::SetCursorPos({ w - 72.f, 5.f });
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0,0,0,0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f,0.3f,0.3f,0.5f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.4f,0.4f,0.4f,0.5f));
    if (ImGui::Button("_", { 30.f, 26.f })) ShowWindow(m_hwnd, SW_MINIMIZE);
    ImGui::SameLine(0.f, 2.f);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f,0.1f,0.1f,0.8f));
    if (ImGui::Button("x", { 30.f, 26.f })) m_running = false;
    ImGui::PopStyleColor(4);

    DrawSettingsModal();

    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Separator, kBorder);
    ImGui::Separator();
    ImGui::PopStyleColor();
}

void NanahiraGUI::DrawMainContent() {
    float availH = ImGui::GetContentRegionAvail().y - 34.f;
    float availW = ImGui::GetContentRegionAvail().x;
    float leftW  = availW * 0.38f;
    float rightW = availW - leftW - 1.f;

    ImGui::BeginChild("##left", { leftW, availH }, false);
    DrawProcessPanel();
    ImGui::EndChild();

    ImGui::SameLine(0.f, 0.f);
    ImDrawList* vdl = ImGui::GetWindowDrawList();
    ImVec2 vp = ImGui::GetCursorScreenPos();
    vdl->AddLine({ vp.x, vp.y }, { vp.x, vp.y + availH }, IM_COL32(45, 37, 80, 255), 1.f);
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 1.f);
    ImGui::SameLine(0.f, 0.f);

    ImGui::BeginChild("##right", { rightW, availH }, false);
    DrawDllPanel();
    ImGui::EndChild();
}

void NanahiraGUI::DrawProcessPanel() {
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6.f);
    ImGui::PushStyleColor(ImGuiCol_Text, kAccentHv);
    ImGui::Text("PROCESSES");
    ImGui::PopStyleColor();

    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputText("##search", m_searchBuf, sizeof(m_searchBuf));
    ImGui::Spacing();

    if (ImGui::Button("Refresh")) RefreshProcesses();
    ImGui::Separator();
    ImGui::Spacing();

    std::string search = m_searchBuf;
    std::transform(search.begin(), search.end(), search.begin(), ::tolower);

    ImGui::BeginChild("##procs", { 0.f, 0.f }, false);
    for (int i = 0; i < (int)m_processes.size(); i++) {
        const auto& p = m_processes[i];
        std::string lower = p.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (!search.empty() && lower.find(search) == std::string::npos) continue;

        char label[256];
        snprintf(label, sizeof(label), "%s  (%lu)", p.name.c_str(), p.pid);
        bool sel = (m_selectedProc == i);
        if (ImGui::Selectable(label, sel, 0, { 0.f, 20.f })) {
            m_selectedProc = i;
            char state[128];
            snprintf(state, sizeof(state), "Targeting: %s", p.name.c_str());
            UpdateDiscordRpc(state);
        }
    }
    ImGui::EndChild();
}

void NanahiraGUI::DrawDllPanel() {
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6.f);
    ImGui::PushStyleColor(ImGuiCol_Text, kAccentHv);
    ImGui::Text("DLL QUEUE");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::BeginChild("##dlls", { 0.f, 120.f }, false);
    for (int i = 0; i < (int)m_dllPaths.size(); i++) {
        const char* name = strrchr(m_dllPaths[i].c_str(), '\\');
        name = name ? name + 1 : m_dllPaths[i].c_str();
        bool sel = (m_selectedDll == i);
        if (ImGui::Selectable(name, sel, 0, { 0.f, 20.f }))
            m_selectedDll = i;
    }
    ImGui::EndChild();

    ImGui::Separator();
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
    ImGui::Text("Inject Options");
    ImGui::PopStyleColor();
    ImGui::Spacing();

    auto HelpMarker = [](const char* desc) {
        ImGui::SameLine(0.f, 4.f);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.45f, 0.65f, 1.f));
        ImGui::TextDisabled("(?)");
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
            ImGui::SetNextWindowSize({ 280.f, 0.f }, ImGuiCond_Always);
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(260.f);
            ImGui::TextUnformatted(desc);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    };

    ImGui::Checkbox("Erase Headers", &m_eraseHeaders);
    HelpMarker("Zeroes out the PE header of the injected DLL after mapping.\n\nRecommended: ON\nMakes the DLL invisible to memory signature scanners by removing the MZ/NT signature.");
    ImGui::SameLine(160.f);
    ImGui::Checkbox("Thread Hijack", &m_threadHijack);
    HelpMarker("Hijacks an existing thread in the target process to call DllMain. No new thread is created.\n\nRecommended: ON for stealth\nAvoids CreateThread callbacks monitored by EAC and BE.");

    ImGui::Checkbox("Stomp Headers", &m_stompHeaders);
    HelpMarker("Overwrites PE headers with LFSR random junk instead of zeroes. More aggressive than Erase Headers.\n\nRecommended: OFF unless Erase Headers is not sufficient.\nDo NOT enable both simultaneously.");
    ImGui::SameLine(160.f);
    ImGui::Checkbox("Skip TLS", &m_skipTls);
    HelpMarker("Skips execution of TLS (Thread Local Storage) callbacks in the injected DLL.\n\nRecommended: OFF\nOnly enable if the DLL crashes due to TLS conflicts. Disabling may break some DLLs.");

    ImGui::Checkbox("Skip Exceptions", &m_skipExceptions);
    HelpMarker("Skips registration of the DLL .pdata exception directory.\n\nRecommended: OFF\nOnly enable if the DLL has no C++ exceptions or SEH handlers.");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    static const char* kModes[] = { "Kernel", "Hook", "Usermode" };
    ImGui::SetNextItemWidth(120.f);
    ImGui::Combo("Mode", &m_mode, kModes, 3);

    ImGui::Spacing();
    ImGui::Spacing();

    ImVec2 btnSz = { 110.f, 32.f };

    if (ImGui::Button("+ Add DLL", btnSz)) {
        if (OpenDllDialog()) {
            AddToast("DLL added.", 139/255.f, 92/255.f, 246/255.f);
        }
    }
    ImGui::SameLine();

    bool canInject = (m_selectedProc >= 0 && m_selectedDll >= 0 && m_driverOnline);
    if (!canInject) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button, kAccentAc);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccent);
    if (ImGui::Button("Inject", btnSz)) DoInject();
    ImGui::PopStyleColor(2);
    if (!canInject) ImGui::EndDisabled();
    ImGui::SameLine();

    bool canRemove = (m_selectedDll >= 0);
    if (!canRemove) ImGui::BeginDisabled();
    if (ImGui::Button("Remove", btnSz)) {
        m_dllPaths.erase(m_dllPaths.begin() + m_selectedDll);
        m_selectedDll = -1;
        AddToast("DLL removed.", 245/255.f, 158/255.f, 11/255.f);
    }
    if (!canRemove) ImGui::EndDisabled();
}

void NanahiraGUI::DrawStatusBar() {
    float barH = 30.f;
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - barH - ImGui::GetStyle().WindowPadding.y);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgHdr);
    ImGui::BeginChild("##sb", { 0.f, barH }, false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImGui::SetCursorPos({ 10.f, 7.f });
    ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
    ImGui::Text("%s", m_statusMsg.c_str());
    ImGui::PopStyleColor();

    if (m_progress > 0.f && m_progress < 1.f) {
        ImGui::SameLine(ImGui::GetWindowWidth() - 180.f);
        ImGui::SetCursorPosY(8.f);
        ImGui::SetNextItemWidth(160.f);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, kAccent);
        ImGui::ProgressBar(m_progress, { 160.f, 14.f }, "");
        ImGui::PopStyleColor();
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void NanahiraGUI::DrawToasts() {
    DWORD now = GetTickCount();
    m_toasts.erase(
        std::remove_if(m_toasts.begin(), m_toasts.end(),
            [&](const ToastMsg& t) { return now > t.expireAt; }),
        m_toasts.end());

    ImGuiIO& io = ImGui::GetIO();
    float y = io.DisplaySize.y - 40.f;
    for (auto it = m_toasts.rbegin(); it != m_toasts.rend(); ++it) {
        ImVec2 tsz = ImGui::CalcTextSize(it->text.c_str());
        ImVec2 tpos = { io.DisplaySize.x - tsz.x - 24.f, y - tsz.y - 10.f };
        ImGui::SetNextWindowPos(tpos);
        ImGui::SetNextWindowSize({ tsz.x + 24.f, tsz.y + 16.f });
        ImGui::SetNextWindowBgAlpha(0.85f);
        char id[32]; snprintf(id, sizeof(id), "##toast%td", it - m_toasts.rbegin());
        ImGui::Begin(id, nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs |
            ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(it->r, it->g, it->b, 1.f));
        ImGui::Text("%s", it->text.c_str());
        ImGui::PopStyleColor();
        ImGui::End();
        y -= tsz.y + 22.f;
    }
}

void NanahiraGUI::RefreshProcesses() {
    m_processes.clear();
    m_selectedProc = -1;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snap, &pe)) {
        do {
            ProcessEntry e;
            e.pid  = pe.th32ProcessID;
            e.name = std::string(pe.szExeFile);
            m_processes.push_back(e);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

bool NanahiraGUI::OpenDllDialog() {
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn    = {};
    ofn.lStructSize      = sizeof(ofn);
    ofn.hwndOwner        = m_hwnd;
    ofn.lpstrFile        = path;
    ofn.nMaxFile         = sizeof(path);
    ofn.lpstrFilter      = "DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.Flags            = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameA(&ofn)) return false;
    for (const auto& p : m_dllPaths) if (p == path) return false;
    m_dllPaths.push_back(path);
    m_selectedDll = (int)m_dllPaths.size() - 1;
    return true;
}

void NanahiraGUI::CheckDriverStatus() {
    SHARED_HEADER* hdr = ConnectToDriver();
    bool wasOnline     = m_driverOnline;
    m_driverOnline     = (hdr != nullptr);
    m_sharedHdr        = hdr;

    if (m_driverOnline && !wasOnline) {
        AddToast("Driver loaded successfully  >_<", 0.24f, 0.90f, 0.47f);
        UpdateDiscordRpc("Idle");
    } else if (!m_driverOnline && wasOnline) {
        AddToast("Driver disconnected.", 0.87f, 0.27f, 0.27f);
        UpdateDiscordRpc("Idle");
    }
}

static DWORD WINAPI AltInjectWorker(LPVOID param)
{
    auto* job = static_cast<NanahiraGUI::AltInjectJob*>(param);
    if (job->mode == 1)
        job->result = HookInjector::inject(job->pid, job->path.c_str());
    else
        job->result = UmInjector::inject(job->pid, job->path.c_str());
    return 0;
}

void NanahiraGUI::DoInject() {
    if (m_mode != 0) {
        if (m_selectedProc < 0) { AddToast("Select a target process.", 239/255.f, 68/255.f, 68/255.f); return; }
        if (m_selectedDll  < 0) { AddToast("Select a DLL from the queue.", 239/255.f, 68/255.f, 68/255.f); return; }

        const std::string& path = m_dllPaths[m_selectedDll];
        int sz = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, nullptr, 0);
        std::wstring wpath(sz, 0);
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wpath.data(), sz);

        m_altJob    = new AltInjectJob{ m_mode, m_processes[m_selectedProc].pid, wpath, false };
        m_altThread = CreateThread(nullptr, 0, AltInjectWorker, m_altJob, 0, nullptr);

        m_statusMsg      = "Injecting...";
        m_progress       = 0.05f;
        m_injectDeadline = GetTickCount() + 15000;
        m_injecting      = true;
        return;
    }

    if (!m_sharedHdr) {
        m_statusMsg = "[ERR] No driver connection";
        AddToast("No driver connection.", 239/255.f, 68/255.f, 68/255.f);
        CheckDriverStatus();
        return;
    }
    if (m_selectedProc < 0) { m_statusMsg = "[ERR] No process selected";  AddToast("Select a target process.",    239/255.f, 68/255.f, 68/255.f); return; }
    if (m_selectedDll  < 0) { m_statusMsg = "[ERR] No DLL selected";       AddToast("Select a DLL from the queue.", 239/255.f, 68/255.f, 68/255.f); return; }

    auto* hdr = reinterpret_cast<SHARED_HEADER*>(m_sharedHdr);
    LONG  st  = InterlockedCompareExchange(&hdr->Status, 0, 0);

    if (st == IPC_DONE)
        InterlockedExchange(&hdr->Status, IPC_READY);

    st = InterlockedCompareExchange(&hdr->Status, 0, 0);
    if (st != IPC_READY) {
        char msg[64];
        snprintf(msg, sizeof(msg), "[ERR] Driver status %ld (not ready)", st);
        m_statusMsg = msg;
        AddToast(m_statusMsg.c_str(), 239/255.f, 68/255.f, 68/255.f);
        return;
    }

    const std::string& path = m_dllPaths[m_selectedDll];
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { AddToast("Cannot read DLL file.", 239/255.f, 68/255.f, 68/255.f); return; }
    std::streamsize sz = f.tellg(); f.seekg(0);
    if (sz <= 0 || (ULONG)sz > MAX_PAYLOAD_SIZE) { AddToast("DLL size invalid.", 239/255.f, 68/255.f, 68/255.f); return; }

    BYTE* payload = reinterpret_cast<BYTE*>(hdr) + PAYLOAD_DATA_OFFSET;
    f.read(reinterpret_cast<char*>(payload), sz);

    hdr->TargetPid   = m_processes[m_selectedProc].pid;
    hdr->PayloadSize = (ULONG)sz;
    hdr->Flags       = 0;
    if (m_eraseHeaders)   hdr->Flags |= INJ_FLAG_ERASE_HEADERS;
    if (m_stompHeaders)   hdr->Flags |= INJ_FLAG_STOMP_HEADERS;
    if (m_skipTls)        hdr->Flags |= INJ_FLAG_SKIP_TLS;
    if (m_skipExceptions) hdr->Flags |= INJ_FLAG_SKIP_EXCEPTIONS;
    if (m_threadHijack)   hdr->Flags |= INJ_FLAG_THREAD_HIJACK;

    InterlockedExchange(&hdr->Command, IPC_CMD_INJECT);

    m_statusMsg    = "Injecting...";
    m_progress     = 0.05f;
    m_injectDeadline = GetTickCount() + POLL_TIMEOUT_MS;
    m_injecting    = true;

    char state[128];
    snprintf(state, sizeof(state), "Injecting -> %s",
        m_processes[m_selectedProc].name.c_str());
    UpdateDiscordRpc(state);
}

void NanahiraGUI::PollInject() {
    if (!m_injecting) return;

    if (m_altThread) {
        if (WaitForSingleObject(m_altThread, 0) == WAIT_OBJECT_0) {
            bool ok = m_altJob->result;
            CloseHandle(m_altThread);
            m_altThread = nullptr;
            delete m_altJob;
            m_altJob    = nullptr;
            m_injecting = false;
            m_progress  = ok ? 1.f : 0.f;
            if (ok) {
                m_statusMsg = "Injection complete.";
                m_injectCount++;
                AddToast("Injection successful!", 34/255.f, 197/255.f, 94/255.f);
            } else {
                m_statusMsg = "Injection failed.";
                AddToast("Injection failed.", 239/255.f, 68/255.f, 68/255.f);
            }
        } else if (GetTickCount() >= m_injectDeadline) {
            m_injecting = false;
            m_progress  = 0.f;
            m_statusMsg = "Injection timed out.";
            AddToast("Injection timed out.", 245/255.f, 158/255.f, 11/255.f);
            m_altThread = nullptr;
            m_altJob    = nullptr;
        }
        return;
    }

    if (!m_sharedHdr) { m_injecting = false; return; }

    auto* hdr  = reinterpret_cast<SHARED_HEADER*>(m_sharedHdr);
    LONG  status = InterlockedCompareExchange(&hdr->Status, 0, 0);
    DWORD now    = GetTickCount();

    m_progress = 0.05f + 0.90f * (1.f - (float)(m_injectDeadline - now) / (float)POLL_TIMEOUT_MS);
    if (m_progress > 0.95f) m_progress = 0.95f;

    if (status == IPC_DONE) {
        m_progress   = 1.f;
        m_statusMsg  = "Injection complete.";
        m_injecting  = false;
        m_injectCount++;
        AddToast("Injection successful!", 34/255.f, 197/255.f, 94/255.f);
        InterlockedExchange(&hdr->Command, IPC_CMD_NONE);
        char state[128];
        snprintf(state, sizeof(state), "Injected -> %s  [%dx]",
            m_processes[m_selectedProc >= 0 ? m_selectedProc : 0].name.c_str(), m_injectCount);
        UpdateDiscordRpc(state);
        return;
    }

    if (status >= IPC_ERR_PROCESS) {
        m_progress  = 0.f;
        m_injecting = false;
        m_statusMsg = "Injection failed (err " + std::to_string(status) + ")";
        AddToast(m_statusMsg.c_str(), 239/255.f, 68/255.f, 68/255.f);
        InterlockedExchange(&hdr->Command, IPC_CMD_NONE);
        return;
    }

    if (now >= m_injectDeadline) {
        m_progress  = 0.f;
        m_injecting = false;
        m_statusMsg = "Injection timed out.";
        AddToast("Injection timed out.", 245/255.f, 158/255.f, 11/255.f);
        InterlockedExchange(&hdr->Command, IPC_CMD_NONE);
        UpdateDiscordRpc("Idle");
    }
}

void NanahiraGUI::UpdateDiscordRpc(const char* state) {
    if (!m_discordRpc) return;
    char details[64];
    if (m_injectCount > 0)
        snprintf(details, sizeof(details), "Driver: %s  |  %d injection%s",
            m_driverOnline ? "Online" : "Offline",
            m_injectCount,
            m_injectCount == 1 ? "" : "s");
    else
        snprintf(details, sizeof(details), "Driver: %s",
            m_driverOnline ? "Online" : "Offline");
    Discord_UpdatePresence(state, details, "nanahira", "Kernel Manual Map Injector", "kiy0w0", "by kiy0w0");
}

void NanahiraGUI::DrawSettingsModal() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(
        { io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f },
        ImGuiCond_Always, { 0.5f, 0.5f });
    ImGui::SetNextWindowSize({ 380.f, 0.f }, ImGuiCond_Always);

    ImGui::PushStyleColor(ImGuiCol_PopupBg, kBgPanel);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, { 20.f, 16.f });

    if (ImGui::BeginPopup("##settings_popup", ImGuiWindowFlags_NoMove)) {

        ImGui::PushStyleColor(ImGuiCol_Text, kAccentHv);
        float tw = ImGui::CalcTextSize("S E T T I N G S").x;
        ImGui::SetCursorPosX((380.f - tw) * 0.5f - 20.f);
        ImGui::Text("S E T T I N G S");
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Separator, kBorder);
        ImGui::Separator();
        ImGui::PopStyleColor();
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
        ImGui::Text("WINDOW");
        ImGui::PopStyleColor();
        ImGui::Spacing();

        if (ImGui::Checkbox("Always On Top", &m_alwaysOnTop))
            SetWindowPos(m_hwnd, m_alwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST,
                0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

        ImGui::Spacing();

        if (ImGui::Checkbox("Discord RPC", &m_discordRpc)) {
            if (m_discordRpc) {
                Discord_Init("1472658353913204737");
                Discord_UpdatePresence("Idle", "Kernel Injector", "nanahira", "Kernel Manual Map Injector", "kiy0w0", "by kiy0w0");
            } else {
                Discord_Shutdown();
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
        ImGui::Text("LINKS");
        ImGui::PopStyleColor();
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button,        { 20/255.f, 16/255.f, 36/255.f, 1.f });
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, { kAccent.x, kAccent.y, kAccent.z, 0.40f });
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  kAccentAc);

        if (ImGui::Button("  GitHub  -  kiy0w0 / kernel-mmi", { -1.f, 32.f }))
            ShellExecuteA(NULL, "open", "https://github.com/kiy0w0/kernel-mmi", NULL, NULL, SW_SHOW);

        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, { 0.96f, 0.37f, 0.20f, 0.45f });
        if (ImGui::Button("  Patreon  -  mizubankai", { -1.f, 32.f }))
            ShellExecuteA(NULL, "open", "https://www.patreon.com/mizubankai", NULL, NULL, SW_SHOW);
        ImGui::PopStyleColor(4);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
        char ver[48];
        snprintf(ver, sizeof(ver), "Nanahira  v%d.%d", PROTO_VER_MAJOR, PROTO_VER_MINOR);
        float vw = ImGui::CalcTextSize(ver).x;
        ImGui::SetCursorPosX((380.f - vw) * 0.5f - 20.f);
        ImGui::Text("%s", ver);
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::EndPopup();
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();
}
