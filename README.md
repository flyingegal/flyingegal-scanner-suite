# 🦅 flyingegal Recon & Security Suite Pro

An enterprise-grade, local network reconnaissance, physical RF discovery, and Android ADB management web dashboard. Designed with an iOS glassmorphism interface and built to run **100% offline** without broadband or active WAN uplinks.

---

## 📑 Table of Contents
- [Features](#-features)
- [Project Architecture](#-project-architecture)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
  - [Windows Setup (PowerShell / CMD)](#1-windows-setup)
  - [Linux Setup (Ubuntu / Debian / Lubuntu)](#2-linux-setup)
- [Execution & Access](#-execution--access)
- [Feature Walkthrough & Usage](#-feature-walkthrough--usage)
- [Troubleshooting & FAQs](#-troubleshooting--faqs)

---

## ⚡ Features

* **Layer-2/3 Network Sweep:** Multi-vector discovery utilizing ARP broadcast frames and Nmap active-host evaluation (`-Pn`) to wake sleeping or idle smartphones.
* **Spatial Topology Radar:** Live HTML5 Canvas radar projecting active nodes into functional sectors (Surveillance, Mobile, Gateways, Workstations) with distance calculated via signal strength.
* **Android ADB Device Manager:**
  * Auto-discovers devices with open wireless debug ports (TCP 5555).
  * Android 11+ dynamic port pairing (`adb pair`).
  * One-click package home launcher switcher (`cmd package set-home-activity`).
  * System permissions (`WRITE_SECURE_SETTINGS`, `SYSTEM_ALERT_WINDOW`).
  * App cache clearing and screen mirroring via `scrcpy`.
* **CCTV & RTSP Live Snapshots:** Connects to port 554 on Hikvision, Dahua, and ONVIF cameras via FFmpeg to grab live preview frames.
* **IPConfig & Kernel Baseline Inspector:** Compares active sweeps against internal operating system ARP neighbor tables (`ip neigh` / `arp -a`).
* **RF Airspace Sniffing:** Scans ambient 802.11 beacon frames and 2.4 GHz Bluetooth Low Energy (BLE) advertisements.
* **Rogue Device Auditing:** Local SQLite database tracks first-seen timestamps and flags unrecognized MAC addresses.

---

## 📂 Project Architecture

```text
flyingegal-scanner-suite/
│
├── app.py                 # Core Flask backend API & discovery engine
├── inventory.db           # SQLite local audit database (auto-created, git-ignored)
├── requirements.txt       # Python package dependencies
├── run.bat                # 1-click Windows launcher script
├── run.sh                 # 1-click Linux launcher script
├── .gitignore             # Git ignore definitions
├── README.md              # Documentation
└── templates/
    └── index.html         # Responsive web dashboard

```

---

## 🔧 Prerequisites

### Windows

* **Python 3.10+** (ensure "Add python.exe to PATH" was enabled during installation).
* **Git for Windows** (for version control and updates).
* **Optional Binaries (Add to system PATH for full capability):**
* `adb.exe` (from Android SDK Platform-Tools).
* `nmap.exe` (with Npcap installed).
* `ffmpeg.exe` (for RTSP camera stream snapshotting).



### Linux (Ubuntu / Debian / Mint / Lubuntu)

* Python 3 & pip (`python3-flask`).
* Root privileges (`sudo`) for Layer-2 raw packet transmission (`arp-scan`, `tshark`).
* Native packages: `nmap`, `bluez`, `iw`, `adb`, `ffmpeg`, `scrcpy`.

---

## 🚀 Installation & Setup

### 1. Windows Setup

#### Step 1: Clone the Repository

Open PowerShell or CMD on your Desktop:

```powershell
cd C:\Users\$env:USERNAME\Desktop
git clone [https://github.com/flyingegal/flyingegal-scanner-suite.git](https://github.com/flyingegal/flyingegal-scanner-suite.git)
cd flyingegal-scanner-suite

```

#### Step 2: Install Python Dependencies

```powershell
pip install -r requirements.txt

```

#### Step 3: Run the Application

Double-click `run.bat` or run via PowerShell:

```powershell
python app.py

```

*Open your browser and navigate to `http://127.0.0.1:5000`.*

---

### 2. Linux Setup

#### Step 1: Install System Dependencies

Open your terminal and install the required networking toolchain:

```bash
sudo apt update
sudo apt install -y python3-flask arp-scan nmap tshark bluez iw sqlite3 adb ffmpeg scrcpy

```

#### Step 2: Clone the Repository

```bash
cd ~/Desktop
git clone [https://github.com/flyingegal/flyingegal-scanner-suite.git](https://github.com/flyingegal/flyingegal-scanner-suite.git)
cd flyingegal-scanner-suite

```

#### Step 3: Run with Elevated Privileges

Make the launcher executable and run:

```bash
chmod +x run.sh
sudo ./run.sh

```

*Or directly run: `sudo python3 app.py`.*
*Open your browser and navigate to `http://127.0.0.1:5000`.*

---

## 💻 Feature Walkthrough & Usage

1. **⚡ Network Sweep:**
* Broadcasts Layer-2 ARP frames and evaluates TCP sockets across your subnet.
* Discovered nodes populate the canvas radar and card feed.
* Devices with port 5555 open will automatically receive the **`⚡ ADB Available`** badge.


2. **📋 IPConfig / Raw Cache:**
* Slides open the inspection drawer.
* Shows local IP address, subnet CIDR, and compares kernel-cached ARP neighbors (`arp -a` / `ip neigh`) against active sweep results.


3. **🤖 ADB Device Manager:**
* **Connect:** Enter the phone's IP and tap **Connect Port 5555**.
* **Android 11+ Pair:** Tap **Android 11+ Pair PIN**, enter the dynamic port and 6-digit code shown in Developer Options, and pair wirelessly.
* **Launcher Kiosk:** Enter your custom app package name (e.g., `com.company.kiosk`) and tap **Set Default Home**.
* **Permissions:** Tap **Grant Perms** to auto-assign secure settings and screen overlay permissions.


4. **▶ Live RTSP Snapshot:**
* Located on IP Camera and Hikvision NVR cards.
* Tapping initiates an FFmpeg capture on `rtsp://<camera-ip>:554/` and renders a live JPEG frame inside the viewer drawer.



---

## ❓ Troubleshooting & FAQs

* **Only the router is detected on Network Sweep:**
* Modern smartphones enter deep sleep when locked. Wake your phone's screen and ensure it is connected to the same Wi-Fi SSID and frequency (2.4 GHz vs 5 GHz).


* **Permission Denied (Linux):**
* `arp-scan` and raw socket diagnostics require elevated privileges. Always launch on Linux using `sudo python3 app.py`.


* **ADB Command Fails / No Devices Listed:**
* Verify **USB Debugging** and **Wireless Debugging** are toggled **ON** under your phone's Developer Options.


* **Port 5000 Already in Use:**
* Terminate any existing background Flask or Python instance using `taskkill /F /IM python.exe` (Windows) or `sudo killall python3` (Linux).



```

```
