import os
import streamlit as st
import nmap
import socket
import datetime

# Manually add Nmap path to environment variables
NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"
os.environ["PATH"] += os.pathsep + os.path.dirname(NMAP_PATH)

# Initialize Nmap Scanner with custom path
scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))

st.title("🔍 Network Scanner")
st.write("Scan networks for open ports, services, and OS details.")

def scan_target(ip, ports, os_detection=False):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.write(f"\n🔍 Scanning {ip} for open ports and services at {timestamp}...")

        # Construct scan arguments
        scan_args = "-sT -Pn -sV"
        if os_detection:
            scan_args += " -O"

        # Execute the Nmap scan
        scanner.scan(hosts=ip, arguments=f"-p {ports} {scan_args}")
        st.write(f"🛠️ Command Executed: {NMAP_PATH} -p {ports} {scan_args} {ip}")

        # Check detected hosts
        detected_hosts = scanner.all_hosts()
        if ip not in detected_hosts:
            st.error("⚠️ Target not found in scan results. Check if the host is reachable.")
            return

        # Extract scan results
        results = []
        for port, port_data in scanner[ip]["tcp"].items():
            state = port_data["state"]
            service = port_data.get("name", "unknown")
            version = port_data.get("version", "").strip()
            status_emoji = "🟢 Open" if state == "open" else "🔴 Closed"
            results.append([port, service, version, status_emoji])

        # Display results in a table
        st.table(results)

        # OS Detection Info
        if os_detection:
            os_matches = scanner[ip].get("osmatch", [])
            if os_matches:
                st.success(f"🖥️ OS Detected: {os_matches[0]['name']} ({os_matches[0]['accuracy']}% accuracy)")
            else:
                st.warning("⚠️ OS detection failed or insufficient data.")

    except Exception as e:
        st.error(f"⚠️ Scan failed: {e}")

# User Input
ip_target = st.text_input("Enter IP or domain to scan", "scanme.nmap.org")
ports = st.text_input("Enter ports to scan (default: 22,80,443 or '1-1024')", "22,80,443")
os_detection = st.checkbox("Enable OS Detection")

if st.button("Start Scan"):
    try:
        ip = socket.gethostbyname(ip_target)
        st.success(f"Resolved {ip_target} to {ip}")
        scan_target(ip, ports, os_detection)
    except socket.gaierror:
        st.error("❌ Invalid domain or IP address")
