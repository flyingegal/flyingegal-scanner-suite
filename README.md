\# flyingegal Recon \& Security Suite Pro



A local, cross-platform (Windows \& Linux) network reconnaissance and hardware diagnostic web dashboard. Built with Python, Flask, and native network stack tooling, designed to run 100% offline on any local subnet.



\---



\## Features



\- \*\*Layer-2/3 Network Discovery:\*\* Discovers connected clients, IP cameras, and network gateways without needing external broadband.

\- \*\*Topology \& Distance Radar:\*\* Dynamic HTML5 Canvas radar mapping nodes with signal-strength distance heuristics.

\- \*\*Android ADB Controller:\*\* Automatic discovery of wireless ADB nodes (port 5555), pairing for Android 11+, package management, launcher switcher, permission granting, and screen mirroring via `scrcpy`.

\- \*\*CCTV RTSP Snapshotting:\*\* Live single-frame extraction from RTSP cameras (port 554) via FFmpeg.

\- \*\*Spectrum \& Wi-Fi Airspace:\*\* Nearby access point detection and signal monitoring.

\- \*\*Persistent Inventory:\*\* SQLite audit tracking to flag unexpected or rogue devices.



\---



\## Project Structure



```text

flyingegal-suite/

│

├── app.py                 # Core Flask backend (routes, scans, ADB)

├── inventory.db           # SQLite audit database (auto-generated)

├── requirements.txt       # Python dependencies

├── README.md              # Project documentation

└── templates/

&#x20;   └── index.html         # Responsive web dashboard

