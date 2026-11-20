# SentinelGuard

**A native Windows privacy and activity monitor built with C++20, Win32, Dear ImGui, and DirectX 11.**

SentinelGuard observes selected runtime activity on a Windows machine and presents events in a live desktop dashboard. It monitors process activity, clipboard content patterns, webcam/microphone usage, and newly observed TCP connections.

> **Project scope:** SentinelGuard is a monitoring and visibility project, not an antivirus or a complete endpoint-detection product. It does not scan files on disk, inspect file contents, hook the Windows kernel, or guarantee that an event is malicious. Clipboard classification is heuristic and should not be treated as a security verdict.

---

## Screenshots

### Dashboard with sample events

The screenshot below uses **Show Mock Events** to display example rows for the four event categories. These rows are demonstration data, not real detections.

![SentinelGuard dashboard showing mock events](assets/screenshots/dashboard-live.png)

### Process control and allowlist

The dashboard also provides process inspection controls and per-category allowlist rules. This screenshot shows the interface with no mock events displayed.

![SentinelGuard process control and allowlist interface](assets/screenshots/allowlist-process-control.png)

---

## Features

| Monitor / component | What it does |
|---|---|
| **Process control** | Inspects a process by PID, displays its executable name and path, and refuses termination of protected system processes. |
| **Clipboard monitor** | Classifies clipboard text using heuristic checks such as entropy, JWT-like structure, and card-like digit sequences. |
| **Device monitor** | Detects webcam and microphone activity using the current user's Windows consent-store information. |
| **Network monitor** | Polls the Windows TCP table and reports newly observed connections with their owning process where available. |
| **Trusted allowlist** | Suppresses selected event categories for specified process names. Rules are saved locally. |
| **Live dashboard** | Displays events by time, category, severity, source, and detail. Supports sorting and column resizing. |
| **Mock events** | Displays a fixed set of example events so the interface can be demonstrated without waiting for activity. |

## Technology

- **Language:** C++20
- **Platform:** Windows 10/11, x64
- **Build system:** CMake 3.20+
- **Compiler:** MSVC (Visual Studio 2022 / MSVC v143)
- **UI:** Dear ImGui 1.91.6
- **Graphics:** Win32 + DirectX 11
- **Concurrency:** `std::jthread`, mutexes, and a publish/subscribe event bus

Dear ImGui is fetched by CMake during the first configuration, so an internet connection is required for the initial build.

---

## Getting started — build and run on Windows

There is currently no prebuilt installer or executable download documented here. To run SentinelGuard, build it from the source code using the steps below.

### 1. Install the prerequisites

Install:

1. **Visual Studio 2022** with the **Desktop development with C++** workload.
   - Ensure the MSVC v143 compiler and a Windows 10/11 SDK are selected.
2. **CMake 3.20 or newer.**
   - The CMake installation bundled with Visual Studio is sufficient.
3. **Git for Windows**, if you do not already have Git installed.

You can check whether CMake and Git are available from PowerShell:

```powershell
cmake --version
git --version
```

### 2. Clone the repository

Open PowerShell and run:

```powershell
git clone https://github.com/rafay35349/SentinelGuard.git
cd SentinelGuard
```

If you have already downloaded the repository as a ZIP, extract it and open PowerShell in the extracted `SentinelGuard` folder instead.

### 3. Configure the project

Run this command from the folder containing `CMakeLists.txt`:

```powershell
cmake -S . -B build
```

CMake creates the `build` directory and downloads Dear ImGui through `FetchContent` on the first configuration.

### 4. Build SentinelGuard

Build the Release version:

```powershell
cmake --build build --config Release
```

If the build succeeds, the application will be created at:

```text
build\Release\SentinelGuard.exe
```

### 5. Run the application

Make sure your PowerShell working directory is still the **repository root** — the folder containing `CMakeLists.txt` — then run:

```powershell
.\build\Release\SentinelGuard.exe
```

The SentinelGuard dashboard should open in a desktop window. Close it using the window's **X** button.

> **Important:** Run the executable from the repository root as shown above. The allowlist file is stored relative to the working directory, so launching it from a different directory may cause the rules file to be created somewhere else.

---

## Using the dashboard

### Event table

The main table displays:

- **Time** — when the event was recorded.
- **Category** — Process, Clipboard, Device, or Network.
- **Severity** — Info, Warning, or Critical.
- **Source** — the process or component associated with the event.
- **Detail** — a short description of the event.

Warning rows are highlighted in amber and Critical rows in red. The table headers can be clicked to sort, and the column boundaries can be dragged to resize columns. The status bar displays the monitoring status and the number of stored events.

### Process control

1. Find the process ID (PID) in Task Manager under **Details**, or use PowerShell:

   ```powershell
   Get-Process -Name notepad | Select-Object Id, ProcessName
   ```

2. Enter the PID in the **PID** field.
3. Click **Inspect** to view the executable name, full path, and termination status.
4. Use **Kill Process** only when you intentionally want to terminate that process.

SentinelGuard checks for protected system processes and refuses to terminate those it identifies as protected. Do not terminate unfamiliar processes just because they appear in the event table.

### Trusted allowlist policy

1. Enter the process name as it appears in the event table's **Source** column (for example, `zoom.exe`).
2. Optionally enter a note.
3. Select the categories to suppress: **Device**, **Process**, **Clip**, and/or **Network**.
4. Click **Add to Allowlist**.

The category checkboxes are independent. Only selected categories are suppressed for that process. Process-name matching is case-insensitive. Adding an existing process name updates its rule, and saved entries can be removed from the list.

Clipboard events use `ClipboardMonitor` as their source label, because the clipboard listener does not identify the application that performed the copy. To suppress clipboard events, add `ClipboardMonitor` and select **Clip**.

### Mock events

Enable **Show Mock Events** to display five fixed example rows covering the event categories and severity colours. This is useful for screenshots and demonstrations. Disable it to return the table to the live event feed.

Mock rows are demonstration data. They should not be interpreted as actual system activity.

---

## Running the verification tests

The repository includes standalone verification programs for milestones 2–5. Build the project first using the steps above. Then, from the repository root, run:

```powershell
.\build\tests\Release\VerifyMilestone2.exe
.\build\tests\Release\VerifyMilestone3.exe
.\build\tests\Release\VerifyMilestone4.exe
.\build\tests\Release\VerifyMilestone5.exe
```

Each program prints pass/fail results and returns exit code `0` when its checks pass.

| Test program | Main coverage |
|---|---|
| `VerifyMilestone2` | Process inspection, protected-process refusal, and termination result handling |
| `VerifyMilestone3` | Clipboard payload classification, entropy boundaries, JWT-like patterns, card-like digit sequences, and input-size limit |
| `VerifyMilestone4` | Allowlist operations and persistence, plus device/event-bus plumbing |
| `VerifyMilestone5` | TCP table parsing, IPv4 formatting, connection-state filtering, and initial baseline behaviour |

---

## Project structure

```text
SentinelGuard/
├── assets/
│   ├── sentinelguard.ico
│   └── screenshots/
│       ├── dashboard-live.png
│       └── allowlist-process-control.png
├── resources/
│   ├── SentinelGuard.rc
│   └── resource.h
├── src/
│   ├── core/
│   ├── monitors/
│   ├── process/
│   ├── ui/
│   └── main.cpp
├── tests/
│   ├── CMakeLists.txt
│   ├── VerifyMilestone2.cpp
│   ├── VerifyMilestone3.cpp
│   ├── VerifyMilestone4.cpp
│   └── VerifyMilestone5.cpp
├── CMakeLists.txt
└── README.md
```

---

## Design notes

- Background monitors publish events through a shared event bus.
- A subscriber applies allowlist filtering before accepted events are stored.
- Events are held in a fixed-capacity ring buffer containing up to 500 recent entries.
- The dashboard reads a snapshot of the buffer for rendering rather than holding references to shared storage.
- Monitor threads use `std::jthread` and are stopped before the event bus and graphics resources are shut down.
- Windows handles use RAII wrappers, and shared state is protected with synchronization primitives.

---

## Runtime files

The application may create these files in its working directory:

| File | Purpose |
|---|---|
| `sentinel_allowlist.txt` | Stores trusted-process rules and their category settings. |
| `imgui.ini` | Stores Dear ImGui window layout and table-column settings. |

These are local runtime files and are not required to be committed to the repository.

---

## Limitations

- Device activity detection relies on the current user's Windows webcam/microphone consent-store information. It is not a kernel-level capture detector.
- Network monitoring currently uses the Windows IPv4 TCP owner-PID table. It does not represent every type of network traffic.
- Clipboard classification is heuristic. It does not prove that text is malicious or sensitive.
- Process termination can cause data loss or interrupt applications. Protected-process checks do not make arbitrary process termination risk-free.
- SentinelGuard is a learning and systems-programming project, not a replacement for Windows Security, antivirus software, EDR, or a firewall.

## How SentinelGuard Works

SentinelGuard uses a modular, event-driven architecture to monitor selected Windows activities and display them through a real-time desktop dashboard.

Rather than relying on a single monitoring loop, the application separates system monitoring, event processing, and user interaction into independent components.

### 1. System Monitoring

SentinelGuard uses native Windows APIs to collect information from different areas of the operating system.

Its monitoring components observe:

- **Process Activity:** Retrieves information about running processes, including process names, process IDs, and executable paths.
- **Clipboard Activity:** Inspects clipboard content and applies heuristic checks to identify potentially sensitive patterns, such as payment-card-like numbers, JWT-like tokens, and high-entropy strings.
- **Webcam and Microphone Activity:** Checks Windows user consent information to identify applications associated with camera and microphone access.
- **Network Activity:** Monitors IPv4 TCP connections and associates them with their owning processes where possible.

### 2. Event Collection and Processing

When a monitoring component detects relevant activity, it generates an event containing information about the observation.

These events are passed through a thread-safe event pipeline. SentinelGuard uses C++20 concurrency features, including `std::jthread`, to manage background monitoring tasks.

A bounded ring buffer stores recent events, allowing the application to maintain a limited event history without continuously increasing memory usage.

### 3. Event Analysis and Trust Management

Collected events are evaluated and presented with relevant context.

SentinelGuard also includes an allowlist that allows users to identify trusted processes. This helps distinguish expected activity from processes that may deserve closer inspection.

Clipboard detections rely on heuristic pattern analysis rather than claiming to definitively identify malicious content.

### 4. Dashboard and User Interaction

The graphical interface is built using Dear ImGui and DirectX 11.

The dashboard presents collected activity in a readable format, allowing users to:

- Review recent monitoring events.
- Inspect process information.
- Manage trusted processes through the allowlist.
- Terminate selected processes where permitted.
- Generate mock events to test and demonstrate the interface.

### 5. Testing and Verification

SentinelGuard includes standalone verification programs for its development milestones. These allow individual components to be tested independently of the main graphical application.

This makes it easier to validate functionality and identify issues without relying entirely on manual interaction with the dashboard.

### Overall Workflow

1. Background monitoring components observe selected Windows activities.
2. Relevant observations are converted into structured events.
3. Events enter the thread-safe event pipeline.
4. Recent events are stored in a bounded ring buffer.
5. The dashboard retrieves and displays the available information.
6. Users inspect activity and perform supported actions through the interface.

### Design Philosophy

SentinelGuard is designed as a lightweight, user-facing Windows activity and privacy monitor. Its primary focus is providing visibility into selected system activities and giving users greater control over their processes.

It is not intended to replace antivirus software or a full Endpoint Detection and Response (EDR) solution. It does not rely on kernel-level monitoring and does not guarantee detection of all malicious activity.

**Repository:** [github.com/rafay35349/SentinelGuard](https://github.com/rafay35349/SentinelGuard)
