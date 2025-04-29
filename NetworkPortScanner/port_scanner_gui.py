import socket
import tkinter as tk
from tkinter import messagebox, filedialog
from fpdf import FPDF
import threading

# ----------------------------
# PDF Report Generator Class
# ----------------------------
class PDFReport(FPDF):
    def __init__(self, results):
        super().__init__()
        self.results = results

    def header(self):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, 'Network Scan Report', ln=True, align='C')
        self.ln(10)

    def generate(self):
        self.add_page()
        self.set_font('Arial', '', 12)
        for line in self.results:
            self.cell(0, 10, line, ln=True)
        filepath = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if filepath:
            self.output(filepath)
            messagebox.showinfo("Export Success", f"Report saved to {filepath}")

# ----------------------------
# Main Scanner Functionality
# ----------------------------
def scan_ports(host, start_port, end_port, output_box):
    results = []
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        messagebox.showerror("Error", "Hostname could not be resolved.")
        return

    output_box.insert(tk.END, f"Scanning {host} ({target_ip}) from port {start_port} to {end_port}...\n")
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                status = f"Port {port}: OPEN"
            else:
                status = f"Port {port}: CLOSED or FILTERED"
            sock.close()
        except Exception as e:
            status = f"Port {port}: ERROR - {str(e)}"
        output_box.insert(tk.END, status + "\n")
        results.append(status)
    return results

# ----------------------------
# Thread Wrapper for Scanner
# ----------------------------
def start_scan_thread(host_entry, start_entry, end_entry, output_box, export_var):
    host = host_entry.get()
    try:
        start_port = int(start_entry.get())
        end_port = int(end_entry.get())
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", "Please enter valid port numbers (0-65535).")
        return

    output_box.delete(1.0, tk.END)  # Clear output box before new scan
    def thread_func():
        results = scan_ports(host, start_port, end_port, output_box)
        if export_var.get():
            pdf = PDFReport(results)
            pdf.generate()

    threading.Thread(target=thread_func).start()

# ----------------------------
# GUI Setup
# ----------------------------
app = tk.Tk()
app.title("Python Network Port Scanner")
app.geometry("600x500")

# Host input
tk.Label(app, text="Target Host (IP or Domain):").pack()
host_entry = tk.Entry(app, width=50)
host_entry.pack()

# Port range inputs
frame_ports = tk.Frame(app)
tk.Label(frame_ports, text="Start Port:").pack(side=tk.LEFT)
start_entry = tk.Entry(frame_ports, width=10)
start_entry.pack(side=tk.LEFT)
tk.Label(frame_ports, text="End Port:").pack(side=tk.LEFT)
end_entry = tk.Entry(frame_ports, width=10)
end_entry.pack(side=tk.LEFT)
frame_ports.pack(pady=10)

# Export option
export_var = tk.IntVar()
export_check = tk.Checkbutton(app, text="Export results to PDF", variable=export_var)
export_check.pack()

# Output display
output_box = tk.Text(app, height=15)
output_box.pack(padx=10, pady=10)

# Scan button
tk.Button(app, text="Start Scan", command=lambda: start_scan_thread(host_entry, start_entry, end_entry, output_box, export_var)).pack()

app.mainloop()
