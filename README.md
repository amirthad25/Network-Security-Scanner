🔍 Network Security Scanner
A Python-based network scanner that uses Nmap and Streamlit to scan networks for open ports, services, and optionally detect operating systems. This tool is designed for network diagnostics and security analysis, helping users monitor their network’s health and identify potential vulnerabilities.

 Features
🛠️ Scan IP addresses or domains for open ports and services
🖥️ OS detection to identify the operating system of a target machine (optional)
🌐 Supports scanning of multiple ports
✅ Real-time scan results displayed in an interactive table
🖼️ Intuitive Streamlit UI for easy interaction

🧠 Tech Stack
Python – Core language for logic
Nmap – Network scanning tool
Streamlit – Web framework for creating the user interface
Socket – For domain/IP resolution
Datetime – For timestamping the scan

🚀 How It Works
Input: The user enters a target IP or domain and selects ports to scan.
Scan Execution: The application uses Nmap to scan the target for open ports, services, and OS.
Output: Results are displayed as a table with port status (open/closed), service name, version, and OS details (if detected).

📂 File Structure
├── app.py                # Main Streamlit application
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
🛠️ Setup Instructions

Clone the repository:
git clone https://github.com/your-username/network-security-scanner.git
cd network-security-scanner

Install required dependencies:
pip install -r requirements.txt

Ensure Nmap is installed on your system. You can download it from here.

Run the app:
streamlit run app.py
📜 Configuration Notes
Nmap Path: The script uses a local installation of Nmap. Modify the NMAP_PATH variable in the script if Nmap is installed in a different directory on your system.

OS Detection: This feature requires Nmap's OS detection capabilities. The accuracy may vary based on the target's network environment.

🔮 Future Enhancements
🌐 Integrate real-time scanning for live targets

📈 Visualize scan results with graphs for easy analysis

🛡️ Add more advanced scanning techniques like stealth scanning and version scanning

🔒 User authentication for storing and managing scans securely

🤝 Contributing
Feel free to fork the repository, raise issues, or create pull requests to contribute. Contributions are always welcome to improve the functionality and security of this tool!

