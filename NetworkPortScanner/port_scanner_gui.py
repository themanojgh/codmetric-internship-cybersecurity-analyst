import socket
import threading
import tkinter as tk
from tkinter import messagebox
from fpdf import FPDF
import time
import logging
import argparse

# Setup logging
logging.basicConfig(filename="port_scanner.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logging.info("Port scanner started")

# Global flag to control scan status
stop_scan = False

# Function to scan ports
def scan_ports(target, start_port, end_port, output_file, scan_results):
    global stop_scan  # Use the global stop flag
    scan_results.delete(1.0, tk.END)
    logging.info(f"Scanning ports from {start_port} to {end_port} on {target}")
    
    for port in range(start_port, end_port + 1):
        if stop_scan:
            scan_results.insert(tk.END, "Scan Stopped\n")
            logging.info("Scan stopped by user")
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                scan_results.insert(tk.END, f"Port {port}: OPEN\n")
                logging.info(f"Port {port} is OPEN")
            else:
                scan_results.insert(tk.END, f"Port {port}: CLOSED\n")
                logging.info(f"Port {port} is CLOSED")
            sock.close()
        except socket.error as e:
            scan_results.insert(tk.END, f"Port {port}: FILTERED\n")
            logging.error(f"Error scanning port {port}: {e}")
    
    scan_results.insert(tk.END, "Scan Complete\n")
    logging.info("Scan complete")
    
    if output_file:
        generate_report(target, start_port, end_port, scan_results.get(1.0, tk.END))

# Function to generate PDF report
def generate_report(target, start_port, end_port, scan_data):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(200, 10, txt=f"Port Scan Report for {target}", ln=True, align='C')
        pdf.ln(10)  # Line break
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 10, f"Scan Results from Port {start_port} to {end_port}:\n{scan_data}")
        pdf.output("port_scan_report.pdf")
        logging.info("Report generated successfully")
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        messagebox.showerror("Error", "Failed to generate report")

# Start scanning in a separate thread
def start_scan_thread(target, start_port, end_port, output_file, scan_results):
    global stop_scan
    stop_scan = False
    scan_thread = threading.Thread(target=scan_ports, args=(target, start_port, end_port, output_file, scan_results))
    scan_thread.start()

# Stop the scanning process
def stop_scan_action():
    global stop_scan
    stop_scan = True

# Command-line argument parsing
def parse_args():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", help="Target IP address to scan")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    parser.add_argument("--report", action="store_true", help="Generate a PDF report")
    return parser.parse_args()

# GUI Setup
def setup_gui():
    root = tk.Tk()
    root.title("Network Port Scanner")
    
    # Target IP entry
    tk.Label(root, text="Target IP Address:").grid(row=0, column=0)
    target_ip = tk.Entry(root)
    target_ip.grid(row=0, column=1)
    
    # Start Port entry
    tk.Label(root, text="Start Port:").grid(row=1, column=0)
    start_port = tk.Entry(root)
    start_port.grid(row=1, column=1)
    
    # End Port entry
    tk.Label(root, text="End Port:").grid(row=2, column=0)
    end_port = tk.Entry(root)
    end_port.grid(row=2, column=1)
    
    # Output File checkbox
    output_file_var = tk.BooleanVar()
    output_file_checkbox = tk.Checkbutton(root, text="Generate Report", variable=output_file_var)
    output_file_checkbox.grid(row=3, columnspan=2)
    
    # Text area for scan results
    scan_results = tk.Text(root, height=15, width=50)
    scan_results.grid(row=4, column=0, columnspan=2)

    # Start Scan Button
    start_button = tk.Button(root, text="Start Scan", command=lambda: start_scan_thread(target_ip.get(), int(start_port.get()), int(end_port.get()), output_file_var.get(), scan_results))
    start_button.grid(row=5, column=0)
    
    # Stop Scan Button
    stop_button = tk.Button(root, text="Stop Scan", command=stop_scan_action)
    stop_button.grid(row=5, column=1)
    
    root.mainloop()

if __name__ == "__main__":
    # If the program is run from the command line, handle args
    if len(sys.argv) > 1:
        args = parse_args()
        logging.info(f"Started scanning with target: {args.target}, start port: {args.start_port}, end port: {args.end_port}, report: {args.report}")
        target = args.target
        start_port = args.start_port
        end_port = args.end_port
        output_file = args.report
        scan_results = None  # Since this is command-line, there will be no GUI results output

        # Call scan_ports directly without GUI
        scan_ports(target, start_port, end_port, output_file, scan_results)
    else:
        setup_gui()

