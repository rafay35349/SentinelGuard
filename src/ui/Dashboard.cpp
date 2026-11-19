#include "Dashboard.hpp"
#include <imgui.h>
#include <chrono>
#include <array>
#include <cstdio>   // std::snprintf
#include <windows.h> // WideCharToMultiByte, OutputDebugStringW

namespace sentinel::ui {

// ─── constants ────────────────────────────────────────────────────────────────
namespace {
    constexpr float  kSidebarWidth    = 220.0f;
    constexpr float  kStatusBarHeight = 24.0f;
    constexpr int    kMockEventCount  = 5;
    constexpr ImU32  kColorWarning    = IM_COL32(255, 204,   0, 60);
    constexpr ImU32  kColorCritical   = IM_COL32(255,  51,  51, 80);
    constexpr ImU32  kColorInfo       = IM_COL32(255, 255, 255,  0);

    // Convert a wide string to UTF-8 for ImGui display.
    [[nodiscard]] std::string wideToUtf8(std::wstring_view wstr)
    {
        if (wstr.empty()) return {};
        const int needed = ::WideCharToMultiByte(
            CP_UTF8, 0,
            wstr.data(), static_cast<int>(wstr.size()),
            nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return {};
        std::string result(static_cast<std::size_t>(needed), '\0');
        ::WideCharToMultiByte(
            CP_UTF8, 0,
            wstr.data(), static_cast<int>(wstr.size()),
            result.data(), needed, nullptr, nullptr);
        return result;
    }
} // anonymous namespace

// ─── ctor ─────────────────────────────────────────────────────────────────────
Dashboard::Dashboard(std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn)
    : snapshotFn_(std::move(snapshotFn))
{}

void Dashboard::setMockMode(bool enabled)
{
    mockMode_ = enabled;
}

// ─── render ───────────────────────────────────────────────────────────────────
void Dashboard::render()
{
    // Full-screen dockspace / host window
    ImGuiIO& io = ImGui::GetIO();

    // Position the host window to cover the entire display
    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize,    ImGuiCond_Always);

    constexpr ImGuiWindowFlags kHostFlags =
        ImGuiWindowFlags_NoTitleBar        |
        ImGuiWindowFlags_NoResize          |
        ImGuiWindowFlags_NoMove            |
        ImGuiWindowFlags_NoScrollbar       |
        ImGuiWindowFlags_NoScrollWithMouse |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNav             |
        ImGuiWindowFlags_NoDecoration      |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("SentinelGuard \xe2\x80\x93 Dashboard", nullptr, kHostFlags);
    ImGui::PopStyleVar();

    // Optional dockspace (available in ImGui docking branch)
#ifdef IMGUI_HAS_DOCK
    ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());
#endif

    // Gather events — inject mock data once when mockMode_ is active
    std::vector<sentinel::core::AlertEvent> events;

    if (mockMode_) {
        static bool s_mockCreated = false;
        static std::vector<sentinel::core::AlertEvent> s_mockEvents;

        if (!s_mockCreated) {
            s_mockCreated = true;
            namespace sc = sentinel::core;

            s_mockEvents = {
                sc::AlertEvent::make(sc::AlertCategory::Process,   sc::Severity::Info,     L"explorer.exe",  L"Process started"),
                sc::AlertEvent::make(sc::AlertCategory::Clipboard, sc::Severity::Warning,  L"ClipboardMgr",  L"Sensitive text copied"),
                sc::AlertEvent::make(sc::AlertCategory::Device,    sc::Severity::Critical, L"USB\\VID_1234", L"Unknown USB device attached"),
                sc::AlertEvent::make(sc::AlertCategory::Network,   sc::Severity::Warning,  L"svchost.exe",   L"Outbound connection on port 4444"),
                sc::AlertEvent::make(sc::AlertCategory::Process,   sc::Severity::Critical, L"cmd.exe",       L"Elevated process spawned"),
            };
        }
        events = s_mockEvents;
    } else {
        events = snapshotFn_();
    }

    renderSidebar();
    ImGui::SameLine();

    // Right-hand panel: table + status bar
    ImGui::BeginGroup();
    {
        // Reserve space for status bar at the bottom
        const float tableHeight = ImGui::GetContentRegionAvail().y - kStatusBarHeight;
        ImGui::BeginChild("##EventPanel", ImVec2(0.0f, tableHeight), false, ImGuiWindowFlags_NoScrollbar);
        renderEventTable(events);
        ImGui::EndChild();

        renderStatusBar();
    }
    ImGui::EndGroup();

    ImGui::End();
}

// ─── renderSidebar ────────────────────────────────────────────────────────────
void Dashboard::renderSidebar()
{
    const float sidebarHeight = ImGui::GetContentRegionAvail().y;
    ImGui::BeginChild("##Sidebar", ImVec2(kSidebarWidth, sidebarHeight), true);

    ImGui::TextUnformatted("\xf0\x9f\x9b\xa1 SentinelGuard v0.1"); // 🛡 in UTF-8
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextUnformatted("Active Monitors:");
    ImGui::Bullet(); ImGui::TextUnformatted("Process Monitor \xe2\x9c\x93");   // ✓
    ImGui::Bullet(); ImGui::TextUnformatted("Clipboard Monitor \xe2\x9c\x93");
    ImGui::Bullet(); ImGui::TextUnformatted("Device Monitor \xe2\x9c\x93");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Clear Events", ImVec2(-1.0f, 0.0f))) {
        OutputDebugStringW(L"[Dashboard] Clear Events requested (stub)\n");
    }

    ImGui::EndChild();
}

// ─── renderEventTable ─────────────────────────────────────────────────────────
void Dashboard::renderEventTable(const std::vector<sentinel::core::AlertEvent>& events)
{
    constexpr int kColumnCount = 5;

    constexpr ImGuiTableFlags kTableFlags =
        ImGuiTableFlags_Resizable      |
        ImGuiTableFlags_Sortable       |
        ImGuiTableFlags_BordersOuter   |
        ImGuiTableFlags_BordersInnerH  |
        ImGuiTableFlags_RowBg          |
        ImGuiTableFlags_ScrollY;

    if (!ImGui::BeginTable("##EventTable", kColumnCount, kTableFlags)) {
        return;
    }

    ImGui::TableSetupScrollFreeze(0, 1); // keep header visible
    ImGui::TableSetupColumn("Time",     ImGuiTableColumnFlags_WidthFixed,   72.0f);
    ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed,   80.0f);
    ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed,   72.0f);
    ImGui::TableSetupColumn("Source",   ImGuiTableColumnFlags_WidthStretch,  0.3f);
    ImGui::TableSetupColumn("Detail",   ImGuiTableColumnFlags_WidthStretch,  0.7f);
    ImGui::TableHeadersRow();

    // Iterate in reverse order — newest first
    if (!events.empty()) {
        for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(events.size()) - 1; i >= 0; --i) {
            const sentinel::core::AlertEvent& ev = events[static_cast<std::size_t>(i)];

            ImGui::TableNextRow();

            // Row background tint by severity
            const ImU32 rowColor = [&]() -> ImU32 {
                switch (ev.severity) {
                    case sentinel::core::Severity::Warning:  return kColorWarning;
                    case sentinel::core::Severity::Critical: return kColorCritical;
                    default:                                 return kColorInfo;
                }
            }();
            if (rowColor != kColorInfo) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, rowColor);
            }

            // Time column — format as HH:MM:SS
            ImGui::TableSetColumnIndex(0);
            {
                const std::time_t tt = std::chrono::system_clock::to_time_t(ev.timestamp);
                std::tm tm{};
#if defined(_MSC_VER)
                localtime_s(&tm, &tt);
#else
                localtime_r(&tt, &tm);
#endif
                char timeBuf[9]; // "HH:MM:SS\0"
                std::snprintf(timeBuf, sizeof(timeBuf), "%02d:%02d:%02d",
                              tm.tm_hour, tm.tm_min, tm.tm_sec);
                ImGui::TextUnformatted(timeBuf);
            }

            // Category
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(categoryLabel(ev.category));

            // Severity (colored text)
            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(severityColor(ev.severity), "%s", severityLabel(ev.severity));

            // Source (wstring → UTF-8 for ImGui)
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(wideToUtf8(ev.source).c_str());

            // Detail (wstring → UTF-8 for ImGui)
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(wideToUtf8(ev.detail).c_str());
        }
    }

    ImGui::EndTable();
}

// ─── renderStatusBar ──────────────────────────────────────────────────────────
void Dashboard::renderStatusBar()
{
    ImGui::Separator();
    ImGui::TextUnformatted("Real-time monitoring active");
}

// ─── static helpers ───────────────────────────────────────────────────────────
const char* Dashboard::categoryLabel(sentinel::core::AlertCategory cat)
{
    switch (cat) {
        case sentinel::core::AlertCategory::Process:   return "Process";
        case sentinel::core::AlertCategory::Clipboard: return "Clipboard";
        case sentinel::core::AlertCategory::Device:    return "Device";
        case sentinel::core::AlertCategory::Network:   return "Network";
        default:                                       return "Unknown";
    }
}

const char* Dashboard::severityLabel(sentinel::core::Severity sev)
{
    switch (sev) {
        case sentinel::core::Severity::Info:     return "Info";
        case sentinel::core::Severity::Warning:  return "Warning";
        case sentinel::core::Severity::Critical: return "Critical";
        default:                                 return "Unknown";
    }
}

ImVec4 Dashboard::severityColor(sentinel::core::Severity sev)
{
    switch (sev) {
        case sentinel::core::Severity::Warning:  return ImVec4(1.0f, 0.8f, 0.0f, 1.0f); // yellow
        case sentinel::core::Severity::Critical: return ImVec4(1.0f, 0.2f, 0.2f, 1.0f); // red
        default:                                 return ImVec4(1.0f, 1.0f, 1.0f, 1.0f); // white
    }
}

} // namespace sentinel::ui
