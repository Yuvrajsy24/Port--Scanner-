import socket
import threading
import queue
import json
import csv
import logging
import platform
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
import os

# ================= GLOBALS & CONSTANTS =================
COLORS = {
    "bg": "#0B0E14",
    "card": "#131722",
    "accent": "#00FF9D",
    "accent_hover": "#00FFB3",
    "text": "#E6EDF3",
    "text_muted": "#8B949E",
    "error": "#FF7B72",
    "info": "#79C0FF",
    "border": "#21262D"
}

# ================= CORE SCANNER ENGINE =================

class PortScannerEngine:
    def __init__(self, log_callback, progress_callback, finish_callback):
        self.log_cb = log_callback
        self.progress_cb = progress_callback
        self.finish_cb = finish_callback
        self.stop_requested = False
        self.is_running = False
        self.lock = threading.Lock()

    def start_scan(self, target, start_port, end_port, threads, timeout):
        self.stop_requested = False
        self.is_running = True
        
        try:
            ip = socket.gethostbyname(target)
            self.log_cb(f"[*] Target Resolved: {ip}\n", "info")
        except:
            self.log_cb(f"[!] Target resolution failed: {target}\n", "error")
            self.finish_cb()
            return

        total_ports = end_port - start_port + 1
        q = queue.Queue()
        for p in range(start_port, end_port + 1):
            q.put(p)

        self.completed_count = 0
        def worker():
            while not q.empty() and not self.stop_requested:
                port = q.get()
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        service = self.guess_service(port)
                        self.log_cb(f"[+] TCP Port {port:<5} | OPEN | Service: {service}\n", "success")
                    s.close()
                except: pass
                
                with self.lock:
                    self.completed_count += 1
                    self.progress_cb(self.completed_count, total_ports)
                q.task_done()

        for _ in range(min(threads, total_ports)):
            t = threading.Thread(target=worker, daemon=True)
            t.start()

        def monitor():
            q.join()
            self.is_running = False
            self.finish_cb()
        
        threading.Thread(target=monitor, daemon=True).start()

    def stop(self):
        self.stop_requested = True
        self.is_running = False

    def guess_service(self, port):
        common = {20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
                  110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"}
        return common.get(port, "Unknown")

# ================= UI APPLICATION =================

class StandaloneScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("KALI-CORE | Ultra-Fast Port Scanner")
        self.root.geometry("850x700")
        self.root.configure(bg=COLORS["bg"])
        
        self.engine = PortScannerEngine(self.log, self.update_progress, self.on_scan_finish)
        self.setup_ui()

    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, bg=COLORS["card"], padx=30, pady=25)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="KALI-CORE", font=("Consolas", 24, "bold"), bg=COLORS["card"], fg=COLORS["accent"]).pack(side=tk.LEFT)
        tk.Label(header, text="v1.0 STANDALONE", font=("Segoe UI", 9, "bold"), bg=COLORS["card"], fg=COLORS["text_muted"]).pack(side=tk.LEFT, padx=15, pady=(8,0))

        # Main Container
        container = tk.Frame(self.root, bg=COLORS["bg"], padx=30, pady=30)
        container.pack(fill=tk.BOTH, expand=True)

        # Control Panel
        ctrl_card = tk.Frame(container, bg=COLORS["card"], padx=25, pady=25, highlightthickness=1, highlightbackground=COLORS["border"])
        ctrl_card.pack(fill=tk.X)

        # Row 1: Target
        r1 = tk.Frame(ctrl_card, bg=COLORS["card"])
        r1.pack(fill=tk.X)
        self.target_entry = self.create_input(r1, "Target Address (IP/Domain)", "127.0.0.1", 40)
        self.target_entry.pack(side=tk.LEFT, padx=(0, 20))
        self.threads_entry = self.create_input(r1, "Thread Count", "500", 12)
        self.threads_entry.pack(side=tk.LEFT)

        # Row 2: Ports & Timeout
        r2 = tk.Frame(ctrl_card, bg=COLORS["card"], pady=20)
        r2.pack(fill=tk.X)
        self.start_port = self.create_input(r2, "Start Port", "1", 15)
        self.start_port.pack(side=tk.LEFT, padx=(0, 20))
        self.end_port = self.create_input(r2, "End Port", "1024", 15)
        self.end_port.pack(side=tk.LEFT, padx=(0, 20))
        self.timeout_entry = self.create_input(r2, "Timeout (s)", "0.5", 15)
        self.timeout_entry.pack(side=tk.LEFT)

        # Actions
        self.btn_scan = tk.Button(ctrl_card, text="INITIATE PORT DISCOVERY", bg=COLORS["accent"], fg="#000",
                                font=("Segoe UI", 11, "bold"), bd=0, pady=12, cursor="hand2", command=self.toggle_scan)
        self.btn_scan.pack(fill=tk.X, pady=(10, 0))

        # Progress & Status
        self.status_var = tk.StringVar(value="System Ready")
        tk.Label(container, textvariable=self.status_var, font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["text_muted"]).pack(anchor="w", pady=(20, 5))
        
        self.pb_var = tk.DoubleVar()
        self.pb = ttk.Progressbar(container, variable=self.pb_var, maximum=100, style="Modern.Horizontal.TProgressbar")
        self.pb.pack(fill=tk.X, pady=(0, 20))

        # Output Terminal
        output_frame = tk.Frame(container, bg="#000", bd=1, highlightthickness=1, highlightbackground=COLORS["border"])
        output_frame.pack(fill=tk.BOTH, expand=True)

        self.terminal = scrolledtext.ScrolledText(output_frame, bg="#000", fg=COLORS["text"],
                                                font=("Consolas", 10), bd=0, padx=15, pady=15)
        self.terminal.pack(fill=tk.BOTH, expand=True)
        self.terminal.tag_config("success", foreground=COLORS["accent"])
        self.terminal.tag_config("error", foreground=COLORS["error"])
        self.terminal.tag_config("info", foreground=COLORS["info"])

    def create_input(self, parent, label, default, width):
        frame = tk.Frame(parent, bg=COLORS["card"])
        tk.Label(frame, text=label, font=("Segoe UI", 9, "bold"), bg=COLORS["card"], fg=COLORS["text_muted"]).pack(anchor="w")
        e = tk.Entry(frame, bg="#0B0E14", fg="#FFF", font=("Consolas", 11), bd=0, insertbackground="#FFF", width=width)
        e.pack(pady=(8, 5), ipady=8, padx=2)
        e.insert(0, default)
        tk.Frame(frame, bg=COLORS["border"], height=1).pack(fill=tk.X)
        return frame

    def get_val(self, frame):
        for w in frame.winfo_children():
            if isinstance(w, tk.Entry): return w.get()
        return ""

    def toggle_scan(self):
        if self.engine.is_running:
            self.engine.stop()
            self.log("[!] Scan Interrupted by user.\n", "error")
            return

        target = self.get_val(self.target_entry)
        try:
            sp = int(self.get_val(self.start_port))
            ep = int(self.get_val(self.end_port))
            th = int(self.get_val(self.threads_entry))
            to = float(self.get_val(self.timeout_entry))
        except:
            messagebox.showerror("Error", "Check numeric parameters.")
            return

        self.terminal.delete(1.0, tk.END)
        self.btn_scan.config(text="STOP ACTIVE SCAN", bg=COLORS["error"])
        self.status_var.set(f"Scanning {target}...")
        self.pb_var.set(0)
        
        threading.Thread(target=self.engine.start_scan, args=(target, sp, ep, th, to), daemon=True).start()

    def log(self, text, tag="text"):
        if self.root.winfo_exists():
            self.root.after(0, lambda: self._safe_append(text, tag))

    def _safe_append(self, text, tag):
        try:
            self.terminal.insert(tk.END, text, tag)
            self.terminal.see(tk.END)
        except: pass

    def update_progress(self, current, total):
        pct = (current / total) * 100
        self.root.after(0, lambda: self.pb_var.set(pct))

    def on_scan_finish(self):
        self.root.after(0, self._ui_finish)

    def _ui_finish(self):
        self.btn_scan.config(text="INITIATE PORT DISCOVERY", bg=COLORS["accent"])
        self.status_var.set("Scan Complete")
        self.log("\n[*] Ready for new operation.\n", "info")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use('clam')
    
    # Correctly define the style including the Horizontal prefix to prevent Layout errors
    style.configure("Modern.Horizontal.TProgressbar", 
                    thickness=10, 
                    troughcolor="#0B0E14", 
                    background=COLORS["accent"], 
                    borderwidth=0)
    
    app = StandaloneScannerApp(root)
    root.mainloop()
