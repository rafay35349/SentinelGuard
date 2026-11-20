#include "Dashboard.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>
#include <array>
#include <cstdio>
#include <ctime>

namespace sentinel::ui {

// ─── constants ────────────────────────────────────────────────────────────────
namespace {
    constexpr float  kSidebarWidth    = 280.0f;
    constexpr float  kSidebarPadX     = 12.0f;
    constexpr float  kStatusBarHeight = 28.0f;
    constexpr ImU32  kColorWarning    = IM_COL32(255, 204,   0, 60);
    constexpr ImU32  kColorCritical   = IM_COL32(255,  51,  51, 80);
    constexpr ImU32  kColorInfo       = IM_COL32(255, 255, 255,  0);

    // Pure C++ wide-to-UTF8 converter with zero Win32 headers.
    // Handles UTF-16 surrogate pairs so non-BMP names (e.g. emoji) render
    // correctly; lone surrogates degrade to U+FFFD.
    [[nodiscard]] std::string wideToUtf8(std::wstring_view wstr)
    {
        std::string out;
        out.reserve(wstr.size());

        for (std::size_t i = 0; i < wstr.size(); ++i) {
            uint32_t cp = static_cast<uint32_t>(wstr[i]);

            if (cp >= 0xD800u && cp <= 0xDBFFu && i + 1 < wstr.size()) {
                const uint32_t low = static_cast<uint32_t>(wstr[i + 1]);
                if (low >= 0xDC00u && low <= 0xDFFFu) {
                    cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u);
                    ++i;
                }
            }
            if (cp >= 0xD800u && cp <= 0xDFFFu) {
                cp = 0xFFFDu;
            }

            if (cp < 0x80u) {
                out.push_back(static_cast<char>(cp));
            } else if (cp < 0x800u) {
                out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            } else if (cp < 0x10000u) {
                out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            } else {
                out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            }
        }
        return out;
    }
} // anonymous namespace

// ─── ctor & setters ───────────────────────────────────────────────────────────
Dashboard::Dashboard(std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn)
    : snapshotFn_(std::move(snapshotFn))
{}

void Dashboard::setInspectCallback(InspectCallback cb)
{
    inspectCb_ = std::move(cb);
}

void Dashboard::setKillCallback(KillCallback cb)
{
    killCb_ = std::move(cb);
}

void Dashboard::setAllowlistCallbacks(GetAllowlistCallback getCb,
                                      AddAllowlistCallback addCb,
                                      RemoveAllowlistCallback remCb)
{
    getAllowlistCb_    = std::move(getCb);
    addAllowlistCb_    = std::move(addCb);
    removeAllowlistCb_ = std::move(remCb);
}

void Dashboard::setMockMode(bool enabled)
{
    mockMode_ = enabled;
}

void Dashboard::setMonitorStates(MonitorStates states) noexcept
{
    monitorStates_ = states;
}

// ─── render ───────────────────────────────────────────────────────────────────
void Dashboard::render()
{
    ImGuiIO& io = ImGui::GetIO();
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
    ImGui::Begin("SentinelGuard \xe2\x80\x93 HostWindow", nullptr, kHostFlags);
    ImGui::PopStyleVar();

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

    ImGui::BeginGroup();
    {
        // Clamp: a very short window must not yield a negative child height.
        const float tableHeight =
            (std::max)(1.0f, ImGui::GetContentRegionAvail().y - kStatusBarHeight);
        ImGui::BeginChild("##EventPanel", ImVec2(0.0f, tableHeight), false, ImGuiWindowFlags_NoScrollbar);
        renderEventTable(events);
        ImGui::EndChild();

        renderStatusBar(events.size());
    }
    ImGui::EndGroup();

    ImGui::End();
}

// ─── renderSidebar ────────────────────────────────────────────────────────────
void Dashboard::renderSidebar()
{
    const float sidebarHeight = ImGui::GetContentRegionAvail().y;

    // Extra left padding: a bordered child defaults to 8 px, which the rounded
    // border visually eats into and leaves headings flush against the edge.
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(kSidebarPadX, 8.0f));
    ImGui::BeginChild("##Sidebar", ImVec2(kSidebarWidth, sidebarHeight), true);
    ImGui::PopStyleVar();

    ImGui::TextUnformatted("SentinelGuard v0.1");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextUnformatted("Active Monitors:");

    // ASCII-only status tags: the default ImGui font has no icon glyphs.
    const auto monitorRow = [](const char* label, bool live)
    {
        ImGui::Bullet();
        ImGui::TextUnformatted(label);
        ImGui::SameLine(175.0f);
        if (live) {
            ImGui::TextColored(ImVec4(0.30f, 0.90f, 0.45f, 1.0f), "[LIVE]");
        } else {
            ImGui::TextDisabled("[OFF]");
        }
    };

    monitorRow("Process Control",  true);
    monitorRow("Clipboard Monitor", monitorStates_.clipboard);
    monitorRow("Device Monitor",    monitorStates_.device);
    monitorRow("Network Monitor",   monitorStates_.network);

    ImGui::Spacing();
    ImGui::Checkbox("Show Mock Events", &mockMode_);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    renderProcessSection();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    renderAllowlistSection();

    ImGui::EndChild();
}

// ─── renderProcessSection ─────────────────────────────────────────────────────
void Dashboard::renderProcessSection()
{
    ImGui::TextUnformatted("Process Control");
    ImGui::Spacing();

    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt("PID", &targetPid_);
    if (targetPid_ < 0) {
        targetPid_ = 0;
    }

    if (ImGui::Button("Inspect") && inspectCb_) {
        lastKillResult_.reset();
        lastLookup_ = inspectCb_(static_cast<uint32_t>(targetPid_));
    }

    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.2f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.5f, 0.05f, 0.05f, 1.0f));
    if (ImGui::Button("Kill Process") && killCb_) {
        lastKillResult_ = killCb_(static_cast<uint32_t>(targetPid_));
    }
    ImGui::PopStyleColor(3);

    if (lastLookup_.has_value()) {
        ImGui::Spacing();
        const auto& r = *lastLookup_;
        if (r.success) {
            ImGui::Text("Name: %s", r.name.c_str());
            if (r.isProtected) {
                ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "Status: PROTECTED SYSTEM");
            } else {
                ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Status: Terminating Allowed");
            }
            if (!r.fullPath.empty()) {
                ImGui::TextWrapped("Path: %s", r.fullPath.c_str());
            }
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "%s", r.message.c_str());
        }
    }

    if (lastKillResult_.has_value()) {
        ImGui::Spacing();
        const auto& kr = *lastKillResult_;
        if (kr.success) {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s", kr.message.c_str());
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "%s", kr.message.c_str());
        }
    }
}

// ─── renderAllowlistSection ───────────────────────────────────────────────────
void Dashboard::renderAllowlistSection()
{
    ImGui::TextUnformatted("Trusted Allowlist Policy");
    ImGui::Spacing();

    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputTextWithHint("##AllowName", "e.g. zoom.exe", newAllowName_, sizeof(newAllowName_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    ImGui::InputTextWithHint("##AllowNote", "Note", newAllowNote_, sizeof(newAllowNote_));

    ImGui::Checkbox("Device", &newAllowDevice_);
    ImGui::SameLine();
    ImGui::Checkbox("Process", &newAllowProcess_);
    ImGui::SameLine();
    ImGui::Checkbox("Clip", &newAllowClipboard_);
    ImGui::Checkbox("Network", &newAllowNetwork_);

    if (ImGui::Button("Add to Allowlist") && addAllowlistCb_) {
        if (newAllowName_[0] != '\0') {
            AllowlistUiEntry entry{};
            entry.processName    = newAllowName_;
            entry.note           = newAllowNote_;
            entry.allowAll       = false;
            entry.allowDevice    = newAllowDevice_;
            entry.allowProcess   = newAllowProcess_;
            entry.allowClipboard = newAllowClipboard_;
            entry.allowNetwork   = newAllowNetwork_;
            addAllowlistCb_(entry);
            newAllowName_[0] = '\0';
            newAllowNote_[0] = '\0';
        }
    }

    if (getAllowlistCb_) {
        const auto entries = getAllowlistCb_();
        if (!entries.empty()) {
            ImGui::Spacing();
            ImGui::BeginChild("##AllowListEntries", ImVec2(0.0f, 110.0f), true);
            for (const auto& e : entries) {
                ImGui::PushID(e.processName.c_str());
                if (ImGui::SmallButton("X") && removeAllowlistCb_) {
                    removeAllowlistCb_(e.processName);
                }
                ImGui::SameLine();
                ImGui::Text("%s", e.processName.c_str());
                if (!e.note.empty()) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(%s)", e.note.c_str());
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
        }
    }
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

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Time",     ImGuiTableColumnFlags_WidthFixed,   72.0f);
    ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed,   80.0f);
    ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed,   72.0f);
    ImGui::TableSetupColumn("Source",   ImGuiTableColumnFlags_WidthStretch,  0.3f);
    ImGui::TableSetupColumn("Detail",   ImGuiTableColumnFlags_WidthStretch,  0.7f);
    ImGui::TableHeadersRow();

    if (!events.empty()) {
        for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(events.size()) - 1; i >= 0; --i) {
            const sentinel::core::AlertEvent& ev = events[static_cast<std::size_t>(i)];
            ImGui::TableNextRow();

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

            ImGui::TableSetColumnIndex(0);
            {
                const std::time_t tt = std::chrono::system_clock::to_time_t(ev.timestamp);
                std::tm tm{};
#if defined(_MSC_VER)
                localtime_s(&tm, &tt);
#else
                localtime_r(&tt, &tm);
#endif
                char timeBuf[9]{};
                std::snprintf(timeBuf, sizeof(timeBuf), "%02d:%02d:%02d",
                              tm.tm_hour, tm.tm_min, tm.tm_sec);
                ImGui::TextUnformatted(timeBuf);
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(categoryLabel(ev.category));

            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(severityColor(ev.severity), "%s", severityLabel(ev.severity));

            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(wideToUtf8(ev.source).c_str());

            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(wideToUtf8(ev.detail).c_str());
        }
    }

    ImGui::EndTable();
}

// ─── renderStatusBar ──────────────────────────────────────────────────────────
void Dashboard::renderStatusBar(std::size_t eventCount)
{
    // Own padded child so the line is never clipped by the window edge.
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 4.0f));
    ImGui::BeginChild("##StatusBar", ImVec2(0.0f, kStatusBarHeight), false,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::Separator();
    const std::string status = "Real-time monitoring active  |  " +
                               std::to_string(eventCount) + " stored events";
    ImGui::TextUnformatted(status.c_str());
    ImGui::EndChild();
    ImGui::PopStyleVar();
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
        case sentinel::core::Severity::Warning:  return ImVec4(1.0f, 0.8f, 0.0f, 1.0f);
        case sentinel::core::Severity::Critical: return ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
        default:                                 return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    }
}

} // namespace sentinel::ui
