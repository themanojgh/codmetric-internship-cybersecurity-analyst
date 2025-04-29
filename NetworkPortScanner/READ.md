# 🔍 Network Port Scanner (GUI) with Export Options

A Python-based network port scanner that allows users to scan open, closed, and filtered TCP ports over custom port ranges using a simple graphical interface. The results can optionally be exported as PDF or plain text.

## 🧠 Features

- Scan for **open**, **closed**, and **filtered** TCP ports
- Supports **custom IP address** and **custom port ranges**
- **GUI built with Tkinter** for ease of use
- Optional **PDF or Text file export** of scan results
- Includes logging and error handling for reliability
- Beginner-friendly, well-commented codebase

## 🚀 Technologies Used

- `Python 3.x`
- `Tkinter` for GUI
- `socket` for port scanning
- `reportlab` for PDF generation
- `threading` for non-blocking scans

## 📦 Installation

1. **Clone the repo**
   ```bash
   git clone https://github.com/themanojgh/codmetric-internship-cybersecurity-analyst-internship/NetworkPortScanner.git
   cd NetworkPortScanner

2. **Install dependencies**
   ```bash
   pip install reportlab
   ```
## ▶️ How to Use
1. **Run the script**
```bash
   python port_scanner_gui.py
```

2. **In the GUI:**
- Enter the target IP
- Enter start and end port
- Click Start Scan
- Choose whether to export and select your desired format

## 📁 Output
 - Scan results are displayed inside the GUI.
 - If export is enabled:
   - PDF reports are saved as scan_report.pdf
   - Text reports are saved as scan_report.txt
## 🛡️ Disclaimer
This tool is created for educational and authorized testing purposes only. Do not scan networks without explicit permission.

Feel free to fork, contribute, or share!
