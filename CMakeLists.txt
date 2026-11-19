cmake_minimum_required(VERSION 3.20)

project(SentinelGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# FetchContent: Dear ImGui
# ---------------------------------------------------------------------------
include(FetchContent)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.91.6
    SOURCE_DIR     ${CMAKE_SOURCE_DIR}/third_party/imgui
)

FetchContent_MakeAvailable(imgui)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)

# ---------------------------------------------------------------------------
# imgui_lib — static library
# ---------------------------------------------------------------------------
add_library(imgui_lib STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(imgui_lib PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

# ---------------------------------------------------------------------------
# SentinelGuard executable
# ---------------------------------------------------------------------------
add_executable(SentinelGuard
    src/main.cpp
    src/core/EventBus.cpp
    src/ui/Dashboard.cpp
)

target_include_directories(SentinelGuard PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

target_link_libraries(SentinelGuard PRIVATE
    imgui_lib
    d3d11
    dxgi
    d3dcompiler
    dwmapi
)

# ---------------------------------------------------------------------------
# Compiler flags
# ---------------------------------------------------------------------------
if(MSVC)
    target_compile_options(SentinelGuard PRIVATE
        /W4 /WX /permissive- /utf-8 /Zc:__cplusplus
    )
    target_compile_options(imgui_lib PRIVATE /W0)  # suppress warnings in third-party code
else()
    target_compile_options(SentinelGuard PRIVATE
        -Wall -Wextra -Wpedantic -Werror
    )
endif()

# ---------------------------------------------------------------------------
# WIN32 subsystem (MSVC)
# ---------------------------------------------------------------------------
if(MSVC)
    set_target_properties(SentinelGuard PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# ---------------------------------------------------------------------------
# Tests subdirectory (optional — only added when present)
# ---------------------------------------------------------------------------
if(EXISTS ${CMAKE_SOURCE_DIR}/tests/CMakeLists.txt)
    add_subdirectory(tests)
endif()
