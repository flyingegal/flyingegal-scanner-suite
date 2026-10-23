import os
import re
import socket
import sqlite3
import subprocess
import time
from flask import Flask, jsonify, render_template, request, Response

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inventory.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY, first_seen TIMESTAMP, last_seen TIMESTAMP,
                    ip TEXT, vendor TEXT, type TEXT, os TEXT, is_trusted INTEGER DEFAULT 0
                )''')
    conn.commit()
    conn.close()

init_db()

def get_windows_network_info():
    """Detects active interface IP, gateway, and subnet mask via ipconfig."""
    my_ip = "127.0.0.1"
    gateway = ""
    subnet = "192.168.1.0/24"
    try:
        out = subprocess.check_output("ipconfig", shell=True, text=True, stderr=subprocess.DEVNULL)
        current_ipv4 = None
        for line in out.splitlines():
            ip_m = re.search(r"IPv4 Address[^\:]*:\s*([0-9\.]+)", line)
            if ip_m and not ip_m.group(1).startswith("127."):
                current_ipv4 = ip_m.group(1)
            gw_m = re.search(r"Default Gateway[^\:]*:\s*([0-9\.]+)", line)
            if gw_m and current_ipv4:
                gateway = gw_m.group(1)
                my_ip = current_ipv4
                octs = my_ip.split(".")
                subnet = f"{octs[0]}.{octs[1]}.{octs[2]}.0/24"
                break
    except Exception:
        pass
    return my_ip, gateway, subnet

def detect_device_category(vendor, mac, ip, ports):
    t = (vendor + " " + mac).lower()
    os_name = "Windows / Linux Node"
    cat = "iot"
    icon = "⚡"
    vname = vendor if vendor and vendor != "Unknown Vendor" else "Network Node"

    if any(k in t for k in ["hikvision", "dahua", "cp plus", "uniview", "reolink", "ezviz", "24:b1:05"]) or ip == "192.168.1.64":
        cat = "camera"
        icon = "📹"
        vname = "Hikvision Surveillance Node" if ip == "192.168.1.64" else "IP Camera / NVR"
        os_name = "Embedded Linux (HikOS)"
    elif any(k in t for k in ["tp-link", "cisco", "netgear", "d-link", "tenda"]) or ip.endswith(".1"):
        cat = "router"
        icon = "🌐"
        vname = "Network Gateway / Router"
        os_name = "RouterOS / Embedded Linux"
    elif any(k in t for k in ["apple", "iphone", "ipad"]):
        cat = "mobile"
        icon = "📱"
        vname = "Apple iOS Device"
        os_name = "Apple iOS / iPadOS"
    elif any(k in t for k in ["samsung", "oneplus", "oppo", "vivo", "realme", "xiaomi", "motorola", "google", "huawei"]):
        cat = "mobile"
        icon = "📱"
        vname = "Android Smartphone"
        os_name = "Android"
    elif any(k in t for k in ["dell", "lenovo", "hp", "intel", "acer", "asus", "microsoft"]):
        cat = "computer"
        icon = "💻"
        vname = "PC / Workstation"
        os_name = "Microsoft Windows / Ubuntu"

    if cat == "iot" and mac.startswith(("82-", "8E-", "86-", "52-", "5E-", "02-", "06-", "0A-", "9E-", "DA-")):
        cat = "mobile"
        icon = "📱"
        vname = "Mobile Device (Private MAC)"
        os_name = "Android / iOS (Randomized MAC)"

    if 5555 in ports:
        os_name = "Android (ADB Port 5555 Open)"
        cat = "mobile"
        icon = "📱"

    return vname, cat, icon, os_name

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/ipconfig")
def get_ipconfig_details():
    my_ip, gateway, subnet = get_windows_network_info()
    raw_neighbors = []
    try:
        arp_out = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in arp_out.splitlines():
            m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F\-]{17})\s+(\w+)", line)
            if m:
                ip, mac, st = m.group(1), m.group(2).upper(), m.group(3)
                if not (ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255.")):
                    raw_neighbors.append({
                        "ip": ip,
                        "mac": mac,
                        "state": st,
                        "is_gateway": (ip == gateway)
                    })
    except Exception:
        pass

    return jsonify({
        "status": "success",
        "interface": {"ip": my_ip, "gateway": gateway, "subnet": subnet, "os": "Microsoft Windows"},
        "count": len(raw_neighbors),
        "neighbors": raw_neighbors
    })

@app.route("/api/scan")
def scan_network():
    devices = {}
    my_ip, gateway, subnet = get_windows_network_info()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = int(time.time())

    # Step 1: Pre-populate from Windows ARP table
    try:
        arp_out = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in arp_out.splitlines():
            m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F\-]{17})", line)
            if m:
                ip, mac = m.group(1), m.group(2).upper()
                if not (ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255.") or ip == my_ip):
                    vname, cat, icon, os_name = detect_device_category("", mac, ip, [])
                    devices[ip] = {
                        "ip": ip, "mac": mac, "vendor": vname, "type": cat, "icon": icon,
                        "os": os_name, "ports": [], "is_new": False, "gateway": (ip == gateway),
                        "adb_ready": False
                    }
    except Exception:
        pass

    # Step 2: Nmap sweep (if installed on Windows)
    try:
        targets = f"{subnet} 192.168.1.64" if subnet != "192.168.1.0/24" else subnet
        nmap_cmd = f"nmap -sn -PR {targets}"
        nmap_out = subprocess.check_output(nmap_cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10)
        curr_ip = None
        for line in nmap_out.splitlines():
            ip_m = re.search(r"Nmap scan report for .*?([\d\.]+)\)?", line)
            if ip_m:
                curr_ip = ip_m.group(1)
                if curr_ip not in devices and curr_ip != my_ip:
                    vname, cat, icon, os_name = detect_device_category("", "", curr_ip, [])
                    devices[curr_ip] = {
                        "ip": curr_ip, "mac": "Resolved Host", "vendor": vname, "type": cat, "icon": icon,
                        "os": os_name, "ports": [], "is_new": False, "gateway": (curr_ip == gateway),
                        "adb_ready": False
                    }
            mac_m = re.search(r"MAC Address: ([0-9A-Fa-f:]{17}) \((.*)\)", line)
            if mac_m and curr_ip and curr_ip in devices:
                devices[curr_ip]["mac"] = mac_m.group(1).upper().replace(":", "-")
                vname, cat, icon, os_name = detect_device_category(mac_m.group(2), devices[curr_ip]["mac"], curr_ip, [])
                devices[curr_ip]["vendor"] = vname
                devices[curr_ip]["type"] = cat
                devices[curr_ip]["icon"] = icon
    except Exception:
        pass

    # Step 3: Fast TCP port check on target devices (Checks 5555, 80, 554)
    for dev_ip in list(devices.keys()):
        for port in [80, 554, 5555, 8000]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.35)
                res = s.connect_ex((dev_ip, port))
                if res == 0:
                    if port not in devices[dev_ip]["ports"]:
                        devices[dev_ip]["ports"].append(port)
                    if port == 5555:
                        devices[dev_ip]["adb_ready"] = True
                        devices[dev_ip]["os"] = "Android (ADB Wireless Open)"
                        devices[dev_ip]["type"] = "mobile"
                s.close()
            except Exception:
                pass

    conn.commit()
    conn.close()
    device_list = sorted(list(devices.values()), key=lambda x: [int(n) for n in x["ip"].split(".") if n.isdigit()])
    return jsonify({"status": "success", "count": len(device_list), "subnet": subnet, "my_ip": my_ip, "devices": device_list})

@app.route("/api/airspace")
def scan_airspace():
    """Reads nearby Wi-Fi SSIDs using Windows netsh wlan."""
    aps = []
    try:
        out = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, text=True, stderr=subprocess.DEVNULL)
        current_ssid = "[Hidden SSID]"
        for line in out.splitlines():
            ssid_m = re.search(r"SSID\s+\d+\s*:\s*(.*)", line)
            if ssid_m:
                current_ssid = ssid_m.group(1).strip() or "[Hidden SSID]"
            bssid_m = re.search(r"BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", line)
            sig_m = re.search(r"Signal\s*:\s*(\d+)%", line)
            if bssid_m:
                bssid = bssid_m.group(1).upper()
                aps.append({
                    "mac": bssid, "vendor": f"Wi-Fi AP: {current_ssid}", "type": "wifi_ap", "icon": "📡",
                    "os": "Wireless Access Point", "signal": 75, "meta": "802.11 Airspace Beacon"
                })
    except Exception:
        pass
    return jsonify({"status": "success", "count": len(aps), "devices": aps})

@app.route("/api/bluetooth")
def scan_bluetooth():
    return jsonify({
        "status": "success",
        "count": 0,
        "devices": [],
        "note": "Native BLE discovery on Windows requires Windows.Devices.Bluetooth WinRT APIs."
    })

# ==================== ADB MANAGEMENT (WINDOWS) ====================

@app.route("/api/adb/devices")
def get_adb_devices():
    devices = []
    try:
        out = subprocess.check_output("adb devices -l", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "device" in line and not line.startswith("List of devices"):
                parts = line.split()
                serial = parts[0]
                state = parts[1]
                model = "Android Device"
                m_match = re.search(r"model:(\S+)", line)
                if m_match:
                    model = m_match.group(1).replace("_", " ")

                devices.append({
                    "serial": serial, "state": state, "model": model,
                    "type": "Network (Wi-Fi)" if ":" in serial else "USB Hardware", "raw": line
                })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "success", "count": len(devices), "devices": devices})

@app.route("/api/adb/connect", methods=["POST"])
def adb_connect():
    data = request.json or {}
    ip = data.get("ip")
    port = data.get("port", "5555")
    if not ip:
        return jsonify({"status": "error", "output": "IP address is required."}), 400
    try:
        out = subprocess.check_output(f"adb connect {ip}:{port}", shell=True, text=True, stderr=subprocess.STDOUT, timeout=6)
        return jsonify({"status": "success", "output": out.strip()})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)})

@app.route("/api/adb/pair", methods=["POST"])
def adb_pair():
    data = request.json or {}
    ip, port, code = data.get("ip"), data.get("port"), data.get("code")
    if not (ip and port and code):
        return jsonify({"status": "error", "output": "IP, dynamic port, and 6-digit pairing code are required."}), 400
    try:
        out = subprocess.check_output(f"adb pair {ip}:{port} {code}", shell=True, text=True, stderr=subprocess.STDOUT, timeout=8)
        return jsonify({"status": "success", "output": out.strip()})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)})

@app.route("/api/adb/action", methods=["POST"])
def adb_action():
    data = request.json or {}
    target = data.get("target")
    action = data.get("action")
    pkg = data.get("pkg", "").strip()
    activity = data.get("activity", "").strip()

    if not target:
        return jsonify({"status": "error", "output": "No target device selected."}), 400

    s_flag = f"-s {target}"
    cmd = ""

    if action == "tcpip":
        cmd = f"adb {s_flag} tcpip 5555"
    elif action == "set_launcher":
        target_component = f"{pkg}/{activity}" if activity else pkg
        cmd = f"adb {s_flag} shell cmd package set-home-activity {target_component}"
    elif action == "disable_oem_launcher":
        cmd = f"adb {s_flag} shell pm disable-user --user 0 {pkg}"
    elif action == "enable_oem_launcher":
        cmd = f"adb {s_flag} shell pm enable {pkg}"
    elif action == "clear_cache":
        cmd = f"adb {s_flag} shell pm clear {pkg}"
    elif action == "grant_permissions":
        cmd = f"adb {s_flag} shell pm grant {pkg} android.permission.WRITE_SECURE_SETTINGS && adb {s_flag} shell appops set {pkg} SYSTEM_ALERT_WINDOW allow"
    elif action == "reboot":
        cmd = f"adb {s_flag} reboot"
    elif action == "mirror":
        subprocess.Popen(f"scrcpy -s {target}", shell=True)
        return jsonify({"status": "success", "output": f"Triggered scrcpy on {target}."})

    try:
        out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=10)
        return jsonify({"status": "success", "output": out.strip() or "Executed successfully."})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)})

@app.route("/api/snapshot/<ip>")
def grab_snapshot(ip):
    try:
        cmd = f"ffmpeg -stimeout 2000000 -rtsp_transport tcp -y -i rtsp://{ip}:554/ -vframes 1 -f image2pipe -vcodec mjpeg -"
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=4)
        return Response(out, mimetype='image/jpeg')
    except Exception:
        return jsonify({"error": "RTSP unauthenticated or stream closed."}), 404

@app.route("/api/tool/<tool>/<ip>")
def run_tool(tool, ip):
    output = ""
    try:
        if tool == "rustscan":
            cmd = f"nmap -T4 -F {ip}"
            output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=8)
        elif tool == "scapy":
            cmd = f"ping -n 2 {ip}"
            p_out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
            ttl_m = re.search(r"TTL=(\d+)", p_out)
            ttl_val = ttl_m.group(1) if ttl_m else "Unknown"
            output = f"Windows Diagnostic Echo ({ip}):\n- Ping Response: Host Reached\n- Header TTL: {ttl_val}\n- Predicted Stack: {'Windows OS (~128)' if ttl_val.isdigit() and int(ttl_val)>64 else 'Linux / Android / RTOS (~64)'}"
    except Exception as e:
        output = f"Execution details:\n{str(e)}"
    return jsonify({"status": "success", "output": output})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)