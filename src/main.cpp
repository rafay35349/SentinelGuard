// SentinelGuard – src/main.cpp
// Win32 + DirectX 11 + Dear ImGui application entry point.
// Milestone 1

// ── System / D3D / WRL headers ───────────────────────────────────────────────
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>

// ── ImGui headers ────────────────────────────────────────────────────────────
#include <imgui.h>
#include <backends/imgui_impl_win32.h>
#include <backends/imgui_impl_dx11.h>

// ── Local headers ────────────────────────────────────────────────────────────
#include "core/Win32Handle.hpp"
#include "core/AlertEvent.hpp"
#include "core/EventBus.hpp"
#include "ui/Dashboard.hpp"

// ── WRL alias ────────────────────────────────────────────────────────────────
namespace wrl = Microsoft::WRL;

// ── File-local AppState ───────────────────────────────────────────────────────
namespace {

struct AppState
{
    wrl::ComPtr<ID3D11Device>            device;
    wrl::ComPtr<ID3D11DeviceContext>     context;
    wrl::ComPtr<IDXGISwapChain>          swapChain;
    wrl::ComPtr<ID3D11RenderTargetView>  renderTargetView;

    sentinel::core::RingBuffer<sentinel::core::AlertEvent, 500> ringBuffer;
    sentinel::ui::Dashboard* pDashboard{ nullptr };
    HWND hwnd{ nullptr };
};

// Minimum global required so WndProc (a plain C callback) can reach AppState.
AppState* g_appState = nullptr;

// ── Render-target helpers ─────────────────────────────────────────────────────

void CleanupRenderTarget(AppState& state) noexcept
{
    state.renderTargetView.Reset();
}

bool CreateRenderTarget(AppState& state) noexcept
{
    wrl::ComPtr<ID3D11Texture2D> backBuffer;
    HRESULT hr = state.swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    if (FAILED(hr))
        return false;

    hr = state.device->CreateRenderTargetView(backBuffer.Get(), nullptr, &state.renderTargetView);
    return SUCCEEDED(hr);
}

// ── Window procedure ──────────────────────────────────────────────────────────

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) noexcept
{
    // Let ImGui handle its own input first.
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return TRUE;

    switch (msg)
    {
    case WM_SIZE:
        if (g_appState && g_appState->device && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget(*g_appState);
            g_appState->swapChain->ResizeBuffers(
                0,
                static_cast<UINT>(LOWORD(lParam)),
                static_cast<UINT>(HIWORD(lParam)),
                DXGI_FORMAT_UNKNOWN,
                0);
            CreateRenderTarget(*g_appState);
        }
        return 0;

    case WM_CLIPBOARDUPDATE:
        OutputDebugStringW(L"[SentinelGuard] WM_CLIPBOARDUPDATE received\n");
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ── D3D11 device + swap-chain creation ───────────────────────────────────────

[[nodiscard]] bool CreateDeviceAndSwapChain(AppState& state) noexcept
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount                        = 2;
    sd.BufferDesc.Width                   = 0; // use window size
    sd.BufferDesc.Height                  = 0;
    sd.BufferDesc.Format                  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                       = state.hwnd;
    sd.SampleDesc.Count                   = 1;
    sd.SampleDesc.Quality                 = 0;
    sd.Windowed                           = TRUE;
    sd.SwapEffect                         = DXGI_SWAP_EFFECT_DISCARD;

    constexpr D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    };
    constexpr UINT numFeatureLevels = static_cast<UINT>(ARRAYSIZE(featureLevels));

    // Try hardware first, fall back to WARP.
    for (const D3D_DRIVER_TYPE driverType : { D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP })
    {
        HRESULT hr = D3D11CreateDeviceAndSwapChain(
            nullptr,
            driverType,
            nullptr,
            0,
            featureLevels,
            numFeatureLevels,
            D3D11_SDK_VERSION,
            &sd,
            &state.swapChain,
            &state.device,
            nullptr,
            &state.context);

        if (SUCCEEDED(hr))
            return true;
    }

    return false;
}

} // anonymous namespace

// ── WinMain ───────────────────────────────────────────────────────────────────

int WINAPI WinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE /*hPrevInstance*/,
    _In_     LPSTR     /*lpCmdLine*/,
    _In_     int       /*nShowCmd*/)
{
    // ── Register window class ─────────────────────────────────────────────────
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"SentinelGuardWnd";
    RegisterClassExW(&wc);

    // ── Center a 1280×720 window ──────────────────────────────────────────────
    constexpr int clientW = 1280;
    constexpr int clientH = 720;

    const int screenW = GetSystemMetrics(SM_CXSCREEN);
    const int screenH = GetSystemMetrics(SM_CYSCREEN);

    // Adjust for non-client area so the client area is exactly 1280×720.
    RECT rc{ 0, 0, clientW, clientH };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    const int winW = rc.right  - rc.left;
    const int winH = rc.bottom - rc.top;
    const int posX = (screenW - winW) / 2;
    const int posY = (screenH - winH) / 2;

    // ── Create AppState (stack-allocated) and expose to WndProc ──────────────
    AppState state{};

    state.hwnd = CreateWindowExW(
        0,
        L"SentinelGuardWnd",
        L"SentinelGuard \u2013 Privacy Monitor",
        WS_OVERLAPPEDWINDOW,
        posX, posY,
        winW, winH,
        nullptr,
        nullptr,
        hInstance,
        nullptr);

    if (!state.hwnd)
    {
        UnregisterClassW(L"SentinelGuardWnd", hInstance);
        return 1;
    }

    g_appState = &state;

    // ── D3D11 device + swap chain ─────────────────────────────────────────────
    if (!CreateDeviceAndSwapChain(state))
    {
        DestroyWindow(state.hwnd);
        UnregisterClassW(L"SentinelGuardWnd", hInstance);
        return 1;
    }

    if (!CreateRenderTarget(state))
    {
        DestroyWindow(state.hwnd);
        UnregisterClassW(L"SentinelGuardWnd", hInstance);
        return 1;
    }

    ShowWindow(state.hwnd, SW_SHOWDEFAULT);
    UpdateWindow(state.hwnd);

    // ── EventBus + RingBuffer wiring ──────────────────────────────────────────
    sentinel::core::EventBus bus;

    bus.subscribe([&state](const sentinel::core::AlertEvent& evt)
    {
        state.ringBuffer.push(evt);
    });

    bus.start();

    // ── Dashboard ─────────────────────────────────────────────────────────────
    sentinel::ui::Dashboard dashboard(
        [&state]() -> std::vector<sentinel::core::AlertEvent>
        {
            return state.ringBuffer.snapshot();
        });

    state.pDashboard = &dashboard;

    // ── ImGui init ────────────────────────────────────────────────────────────
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();

    ImGuiStyle& style     = ImGui::GetStyle();
    style.FrameRounding   = 4.f;
    style.WindowRounding  = 6.f;

    ImGui_ImplWin32_Init(state.hwnd);
    ImGui_ImplDX11_Init(state.device.Get(), state.context.Get());

    // ── Main loop ─────────────────────────────────────────────────────────────
    constexpr float clearColor[4] = { 0.09f, 0.09f, 0.10f, 1.00f };
    bool running = true;

    while (running)
    {
        MSG msg{};
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                running = false;
        }
        if (!running)
            break;

        // ── Build ImGui frame ─────────────────────────────────────────────────
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        dashboard.render();

        ImGui::Render();

        // ── D3D11 render ──────────────────────────────────────────────────────
        ID3D11RenderTargetView* const rtv = state.renderTargetView.Get();
        state.context->OMSetRenderTargets(1, &rtv, nullptr);
        state.context->ClearRenderTargetView(rtv, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        state.swapChain->Present(1, 0);
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────
    bus.stop();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    state.pDashboard = nullptr;
    g_appState       = nullptr;

    DestroyWindow(state.hwnd);
    UnregisterClassW(L"SentinelGuardWnd", hInstance);

    return 0;
}
