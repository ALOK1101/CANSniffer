# ⚡ CAN Sniffer - Hardware-in-the-Loop Diagnostic System

A powerful, multithreaded desktop application designed for real-time CAN bus reverse engineering, diagnostics, and active vehicle network interaction. 

This project was developed as the core software component of my **B.Sc. Engineering Thesis** at AGH University of Krakow. It works in tandem with a custom-built ESP32-based hardware interface to provide a comprehensive Hardware-in-the-Loop (HIL) testing environment.

## ⚠️ Developer Note: Architecture & Technical Debt

Currently, the application is structured as a single-file monolith (`main.py` ~1000 lines). This architecture was an intentional trade-off made during the rapid prototyping phase of my thesis to facilitate quick hardware-software integration tests directly inside a vehicle.

**Refactoring Roadmap:**
The immediate next step for this project is modularizing the codebase to adhere to the Single Responsibility Principle (SRP). The planned structure will be:
* `main.py` - Application entry point.
* `gui/` - CustomTkinter views, dialogs, and UI components.
* `core/serial_handler.py` - UART communication and FIFO queue management.
* `core/can_parser.py` - Frame decoding, Delta analysis, and data validation.
* `data/` - JSON database managers and CSV exporters.

---

## ✨ Key Features

### 🔍 Real-Time Analysis & Reverse Engineering
* **Delta Analysis (Visual Highlighting):** Automatically compares incoming frames to their previous states and highlights changed bytes in red with an animated fade-out, making it incredibly easy to map physical actions (e.g., pressing a steering wheel button) to CAN signals.
* **Dual View Modes:** 
  * *Grouped View:* Displays the current state of the vehicle network (one row per ID).
  * *Stream View:* Displays a chronological terminal-like log of all incoming frames.
* **Advanced Filtering:** Filter by ID, DLC range, whitelist/blacklist. Features options to hide periodic heartbeats or frames with all-zero data, drastically reducing visual noise.
* **ID & Function Mapping:** Save discovered CAN IDs and byte patterns to local JSON databases (`deciphered_ids.json`, `function_codes.json`) with human-readable labels.

### 🕹️ Active Network Transmission
* **Manual Transmit:** Build custom CAN frames byte-by-byte (ID, RTR, IDE, DLC, Data) or paste raw hex strings.
* **Quick Send:** Instantly transmit previously mapped functions.
* **Message Queue Manager:** Create automated transmission sequences. Define repeat counts and millisecond delays to simulate complex vehicle events or perform replay attacks.

### 📼 Offline Playback & Simulation
* **Session Recording:** Log thousands of real-time frames and export them to a timestamped CSV file.
* **Playback Simulator:** Load recorded CSV sessions and play them back offline.
* **Adjustable Speed:** Slow down playback to 0.25x to analyze rapid sequences, or speed it up to 10x.
* **Replay Attacks:** Option to actively transmit the offline playback frames back to the live CAN bus.

## 🛠️ Hardware Requirements

To use this software with a real vehicle, you need a serial bridge. The intended hardware setup is:
1. **Microcontroller:** ESP32 (utilizing its internal TWAI/CAN controller).
2. **Transceiver:** SN65HVD230 (3.3V CAN transceiver).
3. **Connection:** Standard OBD-II cable tapping into CAN-High and CAN-Low (e.g., B-CAN or C-CAN).
4. **Interface:** Connected to the PC via USB/UART at 115200 baud.

*The software expects incoming UART data in the format: `FRAME:ID|RTR|IDE|DLC|D0 D1 D2 D3 D4 D5 D6 D7`*

## 🚀 Installation & Setup

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_GITHUB_USERNAME/can-sniffer.git](https://github.com/YOUR_GITHUB_USERNAME/can-sniffer.git)
   cd can-sniffer
