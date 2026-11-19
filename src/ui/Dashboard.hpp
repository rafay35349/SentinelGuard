#pragma once

#include "../core/AlertEvent.hpp"
#include <imgui.h>
#include <vector>
#include <string>
#include <functional>
#include <optional>
#include <cstdint>

namespace sentinel::ui {

// ---------------------------------------------------------------------------
// Plain data structs for Process UI - no Win32 headers required.
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

using InspectCallback = std::function<ProcessLookupResult(uint32_t pid)>;
using KillCallback    = std::function<ProcessKillUiResult(uint32_t pid)>;

// ---------------------------------------------------------------------------
// Dashboard – Dear ImGui view layer.
// ---------------------------------------------------------------------------
class Dashboard {
public:
    explicit Dashboard(std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn);

    // Callbacks for process operations (wired by main / application controller)
    void setInspectCallback(InspectCallback cb);
    void setKillCallback(KillCallback cb);

    // Called each frame — renders the full ImGui UI
    void render();

    // When true, injects synthetic mock events on each render (created only once)
    void setMockMode(bool enabled);

private:
    std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn_;
    InspectCallback inspectCb_;
    KillCallback    killCb_;
    bool            mockMode_{ true };

    // Process UI State
    int targetPid_{ 0 };
    std::optional<ProcessLookupResult> lastLookup_;
    std::optional<ProcessKillUiResult> lastKillResult_;

    // Helpers
    void renderSidebar();
    void renderProcessSection();
    void renderEventTable(const std::vector<sentinel::core::AlertEvent>& events);
    void renderStatusBar();

    static const char* categoryLabel(sentinel::core::AlertCategory cat);
    static const char* severityLabel(sentinel::core::Severity sev);
    static ImVec4      severityColor(sentinel::core::Severity sev);
};

} // namespace sentinel::ui
