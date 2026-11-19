#pragma once

#include "../core/AlertEvent.hpp"
#include <imgui.h>
#include <vector>
#include <string>
#include <functional>

namespace sentinel::ui {

class Dashboard {
public:
    explicit Dashboard(std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn);

    // Called each frame — renders the full ImGui UI
    void render();

    // When true, injects synthetic mock events on each render (created only once)
    void setMockMode(bool enabled);

private:
    std::function<std::vector<sentinel::core::AlertEvent>()> snapshotFn_;
    bool mockMode_{ true };

    // Helpers
    void renderSidebar();
    void renderEventTable(const std::vector<sentinel::core::AlertEvent>& events);
    void renderStatusBar();

    static const char* categoryLabel(sentinel::core::AlertCategory cat);
    static const char* severityLabel(sentinel::core::Severity sev);
    static ImVec4      severityColor(sentinel::core::Severity sev);
};

} // namespace sentinel::ui
