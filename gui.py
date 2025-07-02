import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scanner import WebSecurityScanner
from fpdf import FPDF
import threading
import random
import json

class BugFinderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🐞 Bug Finder By Swethan")
        self.root.geometry("1080x850")
        self.root.configure(bg="#f5f5f5")

        self.vuln_filter = tk.StringVar(value="All")
        self.report_format = tk.StringVar(value="PDF")
        self.last_results = []

        self.setup_style()
        self.setup_widgets()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#f5f5f5", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.configure("TFrame", background="#f5f5f5")
        style.configure("Custom.TCombobox",
                        fieldbackground="white", background="#e0f0ff",
                        foreground="#000000", borderwidth=1, relief="solid")
        style.map("Custom.TCombobox",
                  fieldbackground=[("readonly", "#d0ebff")],
                  background=[("readonly", "#d0ebff")],
                  foreground=[("readonly", "#000000")])

    def setup_widgets(self):
        ttk.Label(self.root, text="🐞 Bug Finder By Swethan", font=("Segoe UI", 20, "bold"),
                  background="#f5f5f5", foreground="#007acc").pack(pady=15)

        form_frame = ttk.Frame(self.root)
        form_frame.pack()

        for i in range(6): form_frame.columnconfigure(i, weight=1)

        ttk.Label(form_frame, text="🌐 Target URL:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.url_entry = ttk.Entry(form_frame, width=85)
        self.url_entry.grid(row=0, column=1, columnspan=5, sticky="ew", padx=5, pady=5)

        ttk.Label(form_frame, text="📏 Depth:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.depth_entry = ttk.Entry(form_frame, width=10)
        self.depth_entry.insert(0, "2")
        self.depth_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="🗂️ Format:").grid(row=1, column=2, sticky="e", padx=5, pady=5)
        self.format_combo = ttk.Combobox(form_frame, textvariable=self.report_format,
                                         values=["PDF", "JSON"], width=10,
                                         state="readonly", style="Custom.TCombobox")
        self.format_combo.grid(row=1, column=3, padx=5, pady=5)

        ttk.Label(form_frame, text="🎯 Filter:").grid(row=1, column=4, sticky="e", padx=5, pady=5)
        self.filter_combo = ttk.Combobox(form_frame, textvariable=self.vuln_filter, width=30,
                                         values=[
                                             "All", "SQL Injection", "Cross-Site Scripting (XSS)",
                                             "Command Injection", "Open Redirect",
                                             "Sensitive Info Exposure", "CSRF Vulnerability",
                                             "Clickjacking", "Admin Panel Exposure",
                                             "HTML Comment Disclosure", "Open Ports"
                                         ],
                                         state="readonly", style="Custom.TCombobox")
        self.filter_combo.grid(row=1, column=5, padx=5, pady=5)
        self.filter_combo.set("All")

        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="🚀 Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="💾 Save Results", command=self.save_results).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="🛠️ Scan Ports", command=self.scan_ports_only).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="💡 Cyber Tip", command=self.show_tips).pack(side=tk.LEFT, padx=10)

        output_frame = ttk.Frame(self.root)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        output_frame.configure(height=500)

        self.output_text = tk.Text(output_frame, wrap=tk.WORD, font=("Consolas", 11),
                                   bg="#ffffff", fg="#000000", insertbackground="black")
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def start_scan(self):
        threading.Thread(target=self._scan).start()

    def _scan(self):
        url = self.url_entry.get().strip()
        try:
            depth = int(self.depth_entry.get().strip())
        except:
            messagebox.showerror("⚠️ Error", "Invalid crawl depth.")
            return

        if not url:
            messagebox.showerror("⚠️ Error", "Please enter a valid URL.")
            return

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"🔍 Scanning {url} with depth {depth}...\n\n")
        self.root.update()

        scanner = WebSecurityScanner(url, depth)
        self.last_results = scanner.scan()

        self.output_text.insert(tk.END, f"\n✅ Scan complete. {len(self.last_results)} vulnerabilities found.\n")
        self.display_results()

    def display_results(self):
        self.output_text.insert(tk.END, f"\n🎯 Filter: {self.vuln_filter.get()}\n\n")
        self.output_text.insert(tk.END, "━" * 80 + "\n")

        selected_type = self.vuln_filter.get().strip().lower()
        count = 0

        for vuln in self.last_results:
            vuln_type = vuln.get("type", "").strip().lower()
            if selected_type != "all" and selected_type not in vuln_type:
                continue

            count += 1
            self.output_text.insert(tk.END, f"🛑 Type: {vuln.get('type', 'N/A')}\n")
            self.output_text.insert(tk.END, f"🌍 URL: {vuln.get('url', 'N/A')}\n")

            for key in ["parameter", "payload", "info_type", "match", "cookie", "ports", "status_code", "comment"]:
                if key in vuln:
                    val = vuln[key]
                    value = ", ".join(str(v) for v in val) if isinstance(val, list) else str(val)
                    self.output_text.insert(tk.END, f"📌 {key.capitalize()}: {value}\n")

            self.output_text.insert(tk.END, "━" * 80 + "\n")

        if count == 0:
            self.output_text.insert(tk.END, "\n⚠️ No results for this filter.\n")

    def save_results(self):
        if not self.last_results:
            messagebox.showinfo("ℹ️ Info", "No results to save.")
            return

        format_selected = self.report_format.get()
        file_ext = ".pdf" if format_selected == "PDF" else ".json"
        file_path = filedialog.asksaveasfilename(defaultextension=file_ext,
                                                 filetypes=[("PDF", "*.pdf")] if file_ext == ".pdf" else [("JSON", "*.json")])
        if not file_path:
            return

        if format_selected == "PDF":
        
                try:
                    pdf = FPDF()
                    pdf.add_page()
                    pdf.set_font("Arial", size=12)
                    pdf.set_title("Bug Finder Report")
                    pdf.cell(200, 10, txt="Bug Finder By Swethan - Report", ln=True, align='C')
                    pdf.ln(10)

                    for vuln in self.last_results:
                        try:
                            vuln_type = str(vuln.get('type', '')).encode('ascii', 'ignore').decode()
                            pdf.set_font("Arial", "B", 12)
                            pdf.multi_cell(0, 10, f"Type: {vuln_type}")

                            url = str(vuln.get('url', '')).encode('ascii', 'ignore').decode()
                            pdf.set_font("Arial", "", 11)
                            pdf.multi_cell(0, 8, f"URL: {url}")

                            for key in ["parameter", "payload", "info_type", "match", "cookie", "ports", "status_code", "comment"]:
                                if key in vuln:
                                    raw_label = key.replace("_", " ").capitalize()
                                    raw_value = ", ".join(str(v) for v in vuln[key]) if isinstance(vuln[key], list) else str(vuln[key])

                                    # Ensure encoding-safe versions
                                    label = raw_label.encode('ascii', 'ignore').decode()
                                    value = raw_value.encode('ascii', 'ignore').decode()
                                    pdf.multi_cell(0, 8, f"{label}: {value}")
                            pdf.ln(5)
                        except Exception as entry_error:
                            print(f"[WARNING] Skipped one entry due to encoding: {entry_error}")

                    pdf.output(file_path)
                    messagebox.showinfo("✅ Success", "PDF saved successfully.")
                except Exception as e:
                    messagebox.showerror("❌ Error", f"PDF save failed: {e}")

        else:
            try:
                with open(file_path, "w") as f:
                    json.dump(self.last_results, f, indent=4)
                messagebox.showinfo("✅ Success", "JSON saved successfully.")
            except Exception as e:
                messagebox.showerror("❌ Error", f"JSON save failed: {e}")

    def scan_ports_only(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("⚠️ Error", "Enter a URL first.")
            return

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"\n🛠️ Scanning open ports on {url}...\n")
        scanner = WebSecurityScanner(url)
        scanner.scan_ports()

        port_results = [v for v in scanner.vulnerabilities if v.get("type") == "Open Ports"]

        self.output_text.insert(tk.END, f"\n🔌 Open Ports Found: {len(port_results)}\n")
        for vuln in port_results:
            self.output_text.insert(tk.END, f"🛑 Type: {vuln.get('type')}\n")
            self.output_text.insert(tk.END, f"🌍 URL: {vuln.get('url')}\n")
            ports = ", ".join(str(p) for p in vuln.get("ports", []))
            self.output_text.insert(tk.END, f"📌 Ports: {ports}\n")
            self.output_text.insert(tk.END, "━" * 80 + "\n")

    def show_tips(self):
        tips = [
            "🔐 Use strong, unique passwords.",
            "🛡️ Always validate user inputs.",
            "📡 Use HTTPS on all endpoints.",
            "🧪 Regularly scan for vulnerabilities.",
            "🚪 Close unused open ports.",
            "🔑 Enable 2FA wherever possible.",
            "🛠️ Patch dependencies often.",
            "🕵️ Monitor logs for anomalies.",
            "📧 Avoid phishing — verify links."
        ]
        messagebox.showinfo("💡 Cybersecurity Tip", random.choice(tips))

if __name__ == "__main__":
    root = tk.Tk()
    app = BugFinderGUI(root)
    root.mainloop()
