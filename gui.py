import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from scanner import WebSecurityScanner
from fpdf import FPDF
from concurrent.futures import ThreadPoolExecutor
import threading
import random

class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner")
        self.root.geometry("820x700")
        self.root.configure(bg="#f0f4ff")

        self.main_frame = tk.Frame(root, bg="#f0f4ff")
        self.main_frame.pack(fill="both", expand=True)

        self.banner = tk.Frame(self.main_frame, bg="#6a5acd")
        self.banner.pack(fill="x")
        tk.Label(self.banner, text="🕷️ BUG FINDER BY SWETHAN 🔍", font=("Comic Sans MS", 20, "bold"), bg="#6a5acd", fg="white").pack(pady=10)

        ttk.Label(self.main_frame, text="🌐 Enter a website to scan:", background="#f0f4ff").pack(pady=(20, 5))
        self.url_entry = ttk.Entry(self.main_frame, width=80, font=("Segoe UI", 10))
        self.url_entry.pack(pady=5)

        self.toggle_frame = tk.Frame(self.main_frame, bg="#f0f4ff")
        self.toggle_frame.pack(pady=10)
        ttk.Label(self.toggle_frame, text="🎛️ Select vulnerability types to scan:", background="#f0f4ff").pack()

        self.vuln_options = [
            "SQL Injection", "Cross-Site Scripting (XSS)", "Sensitive Information Exposure",
            "Open Redirect", "Command Injection", "Directory Traversal", "Clickjacking",
            "Insecure Cookies", "Exposed Debug Info", "Admin Panel Exposure", "HTML Comment Disclosure"
        ]

        self.selected_vulns = set()
        self.button_refs = {}

        grid = tk.Frame(self.toggle_frame, bg="#f0f4ff")
        grid.pack()

        for i, vuln in enumerate(["All"] + self.vuln_options):
            btn = tk.Button(
                grid, text=vuln, width=22, relief="raised", bg="#ffffff",
                command=lambda v=vuln: self.toggle_vuln(v)
            )
            btn.grid(row=i // 3, column=i % 3, padx=5, pady=5)
            self.button_refs[vuln] = btn

        self.button_frame = tk.Frame(self.main_frame, bg="#f0f4ff")
        self.button_frame.pack(pady=10)

        self.scan_button = tk.Button(self.button_frame, text="🚀 Start Scan", command=self.start_scan, font=("Segoe UI", 10, "bold"))
        self.scan_button.pack(side=tk.LEFT, padx=10)

        self.port_button = tk.Button(self.button_frame, text="🛠️ Scan Open Ports", command=self.start_port_scan, font=("Segoe UI", 10, "bold"))
        self.port_button.pack(side=tk.LEFT, padx=10)

        self.pdf_button = tk.Button(self.button_frame, text="📝 Export PDF Report", command=self.export_pdf_report, font=("Segoe UI", 10, "bold"), state=tk.DISABLED)
        self.pdf_button.pack(side=tk.LEFT, padx=10)

        self.tip_button = tk.Button(self.button_frame, text="💡 Cyber Tip", command=self.show_cyber_tip, font=("Segoe UI", 10, "bold"))
        self.tip_button.pack(side=tk.LEFT, padx=10)

        self.result_box = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=95, height=20, font=("Courier New", 10))
        self.result_box.pack(padx=15, pady=10)
        self.result_box.tag_configure('header', font=('Segoe UI', 10, 'bold'), foreground='#6a5acd')

        self.status_frame = tk.Frame(self.main_frame, bg="#f0f4ff")
        self.status_frame.pack(pady=5)

        self.scan_status_label = tk.Label(self.status_frame, text="", font=("Segoe UI", 11, "bold"), bg="#f0f4ff")
        self.scan_status_label.pack()
        self.bug_count_label = tk.Label(self.status_frame, text="", font=("Segoe UI", 11), bg="#f0f4ff", fg="#6a5acd")
        self.bug_count_label.pack()

        self.vulnerabilities = []

    def toggle_vuln(self, vuln):
        if vuln == "All":
            self.selected_vulns = set(self.vuln_options) if len(self.selected_vulns) < len(self.vuln_options) else set()
        else:
            self.selected_vulns.symmetric_difference_update([vuln])

        for v in self.vuln_options:
            self.button_refs[v].config(bg="#cce5ff" if v in self.selected_vulns else "#ffffff")
        self.button_refs["All"].config(bg="#cce5ff" if len(self.selected_vulns) == len(self.vuln_options) else "#ffffff")

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("❗ Input Error", "Please enter a URL.")
            return
        if not self.selected_vulns:
            messagebox.showerror("❗ Selection Error", "Please select at least one vulnerability type.")
            return

        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"🔍 Starting scan on: {url}\n\n")
        self.scan_status_label.config(text="")
        self.bug_count_label.config(text="")
        self.pdf_button.config(state=tk.DISABLED)
        threading.Thread(target=self.run_scanner, args=(url, list(self.selected_vulns)), daemon=True).start()

    def start_port_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("❗ Input Error", "Please enter a URL.")
            return

        self.result_box.insert(tk.END, f"\n🛠️ Starting port scan on: {url}\n")
        threading.Thread(target=self.run_port_scan, args=(url,), daemon=True).start()

    def run_port_scan(self, url):
        scanner = WebSecurityScanner(url)
        scanner.scan_ports()
        self.vulnerabilities.extend(scanner.vulnerabilities)
        self.pdf_button.config(state=tk.NORMAL)
        self.display_results()

    def run_scanner(self, url, selected_types):
        scanner = WebSecurityScanner(url)
        scanner.crawl(url)

        scan_map = {
            "SQL Injection": scanner.check_sql_injection,
            "Cross-Site Scripting (XSS)": scanner.check_xss,
            "Sensitive Information Exposure": scanner.check_sensitive_info,
            "Open Redirect": scanner.check_open_redirect,
            "Command Injection": scanner.check_command_injection,
            "Directory Traversal": scanner.check_directory_traversal,
            "Clickjacking": scanner.check_clickjacking,
            "Insecure Cookies": scanner.check_insecure_cookies,
            "Exposed Debug Info": scanner.check_debug_info,
            "Admin Panel Exposure": scanner.check_admin_paths,
            "HTML Comment Disclosure": scanner.check_html_comments
        }

        with ThreadPoolExecutor(max_workers=8) as executor:
            for vuln_type in selected_types:
                func = scan_map.get(vuln_type)
                if func:
                    if vuln_type == "Admin Panel Exposure":
                        executor.submit(func)
                    else:
                        for link in scanner.visited_urls:
                            executor.submit(func, link)

        self.vulnerabilities = scanner.vulnerabilities
        self.scan_status_label.config(text="✅ Scan Completed!")
        self.bug_count_label.config(text=f"🐞 Total Bugs Found: {len(self.vulnerabilities)}")
        self.pdf_button.config(state=tk.NORMAL)
        self.display_results()

    def display_results(self):
        self.result_box.insert(tk.END, f"🐞 Total Bugs Found: {len(self.vulnerabilities)}\n\n")
        if not self.vulnerabilities:
            self.result_box.insert(tk.END, "🎉 No vulnerabilities found.\n")
            return

        grouped = {}
        for v in self.vulnerabilities:
            grouped.setdefault(v["type"], []).append(v)

        for vtype, items in grouped.items():
            self.result_box.insert(tk.END, f"🔒 === {vtype} ===\n", 'header')
            for v in items:
                self.result_box.insert(tk.END, f"🔗 URL: {v.get('url', '')}\n")
                for key in ["parameter", "payload", "match", "info_type", "comment", "cookie", "status_code", "ports"]:
                    if v.get(key):
                        if isinstance(v[key], list):
                            self.result_box.insert(tk.END, f"{key.capitalize():<12}: {', '.join(str(p) for p in v[key])}\n")
                        else:
                            self.result_box.insert(tk.END, f"{key.capitalize():<12}: {v[key]}\n")
                self.result_box.insert(tk.END, "\n")
            self.result_box.insert(tk.END, "----------------------------------------\n\n")

    def export_pdf_report(self):
        if not self.vulnerabilities:
            messagebox.showinfo("📢 Heads Up", "No vulnerabilities to export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Save PDF Report")
        if not file_path:
            return

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, "BUG FINDER REPORT", ln=True, align="C")
        pdf.set_font("Arial", "", 12)
        pdf.ln(10)
        pdf.cell(200, 10, f"Total Bugs Found: {len(self.vulnerabilities)}", ln=True)

        grouped = {}
        for v in self.vulnerabilities:
            grouped.setdefault(v["type"], []).append(v)

        for vtype, items in grouped.items():
            pdf.set_font("Arial", "B", 14)
            pdf.cell(200, 10, f"\n{vtype}", ln=True)
            for v in items:
                pdf.set_font("Arial", "", 11)
                pdf.multi_cell(0, 8, f"URL: {v.get('url', '')}")
                for key in ["parameter", "payload", "match", "info_type", "comment", "cookie", "status_code", "ports"]:
                    if v.get(key):
                        if isinstance(v[key], list):
                            pdf.multi_cell(0, 8, f"{key.capitalize()}: {', '.join(str(p) for p in v[key])}")
                        else:
                            pdf.multi_cell(0, 8, f"{key.capitalize()}: {v[key]}")
                pdf.ln(4)

        try:
            pdf.output(file_path)
            messagebox.showinfo("✅ Success", f"PDF Report saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("❌ PDF Error", f"Failed to save PDF: {e}")

    def show_cyber_tip(self):
        tips = [
            "🛡️ Use strong, unique passwords for every account.",
            "🔍 Don't click on suspicious links.",
            "🔒 Enable 2FA wherever possible.",
            "🧠 Always think before you click!",
            "💾 Back up your data regularly!",
            "⚠️ Beware of public Wi-Fi and phishing emails."
        ]
        messagebox.showinfo("💡 Cyber Tip", random.choice(tips))

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
