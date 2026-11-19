#pragma once

#include "../core/AlertEvent.hpp"
#include <imgui.h>
#include <vector>
#include <string>
#include <string_view>
#include <functional>
#include <optional>
#include <cstdint>

namespace sentinel::ui {

// ---------------------------------------------------------------------------
// Plain data structs for Process and Allowlist UI - zero Win32 headers required.
// ---------------------------------------------------------------------------
struct ProcessLookupResult {
    bool        success{ false };
    bool        isProtected{ false };
    std::string name;
    std::string fullPath;
    std::string message;
};

struct ProcessKillUiResult {
    bool        success{ false };
    std::string message;
};

struct AllowlistUiEntry {
    std::string processName;
    bool        allowAll{ false };
    bool        allowProcess{ true };
    bool        allowClipboard{ false };
    bool        allowDevice{ true };
    bool        allowNetwork{ false };
    std::string note;
};

using InspectCallback         = std::function<ProcessLookupResult(uint32_t pid)>;
using KillCallback            = std::function<ProcessKillUiResult(uint32_t pid)>;
using GetAllowlistCallback    = std::function<std::vector<AllowlistUiEntry>()>;
using AddAllowlistCallback    = std::function<void(AllowlistUiEntry)>;
using RemoveAllowlistCallback = std::function<bool(std::string_view)>;

// ---------------------------------------------------------------------------
// Dashboard – Dear ImGui view layer.
// ---------------------------------------------------------------------------
class Dashboard {
public:
    explicit Dashboard(std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn);

    // Callbacks for process operations
    void setInspectCallback(InspectCallback cb);
    void setKillCallback(KillCallback cb);

    // Callbacks for allowlist policy
    void setAllowlistCallbacks(GetAllowlistCallback getCb,
                               AddAllowlistCallback addCb,
                               RemoveAllowlistCallback remCb);

    // Called each frame — renders the full ImGui UI
    void render();

    // When true, injects synthetic mock events on each render (created only once)
    void setMockMode(bool enabled);

private:
    std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn_;
    InspectCallback         inspectCb_;
    KillCallback            killCb_;
    GetAllowlistCallback    getAllowlistCb_;
    AddAllowlistCallback    addAllowlistCb_;
    RemoveAllowlistCallback removeAllowlistCb_;
    bool                    mockMode_{ true };

    // Process UI State
    int targetPid_{ 0 };
    std::optional<ProcessLookupResult> lastLookup_;
    std::optional<ProcessKillUiResult> lastKillResult_;

    // Allowlist UI State
    char newAllowName_[128]{};
    char newAllowNote_[128]{};
    bool newAllowAll_{ false };
    bool newAllowProcess_{ true };
    bool newAllowClipboard_{ false };
    bool newAllowDevice_{ true };
    bool newAllowNetwork_{ false };

    // Helpers
    void renderSidebar();
    void renderProcessSection();
    void renderAllowlistSection();
    void renderEventTable(const std::vector<sentinel::core::AlertEvent>& events);
    void renderStatusBar();

    static const char* categoryLabel(sentinel::core::AlertCategory cat);
    static const char* severityLabel(sentinel::core::Severity sev);
    static ImVec4      severityColor(sentinel::core::Severity sev);
};

} // namespace sentinel::ui
