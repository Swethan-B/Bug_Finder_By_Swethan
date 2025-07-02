# Bug Finder By Swethan

**Bug Finder By Swethan** is a powerful yet easy-to-use graphical web vulnerability scanner. Designed for cybersecurity learners, penetration testers, and developers, it scans websites for a wide range of web vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), Open Redirect, Command Injection, and Sensitive Information Exposure and etc...

---

## 🚀 Features

* 🔍 **Crawls websites recursively** with configurable depth
* 🛡️ Detects:

  * SQL Injection (SQLi)
  * Cross-Site Scripting (XSS)
  * Open Redirect
  * Command Injection
  * Sensitive Information Exposure (emails, API keys) and etc..
* 🎛️ **Graphical Interface** using `tkinter`
* 📂 **Result Export** to pdf or json
* 🧮 Live Filtering by vulnerability type
* 🧠 Multithreaded scanning for faster results

---


## 📦 Installation

1. **Clone the Repository**

```bash
https://github.com/Swethan-B/Bug_Finder_By_Swethan.git

cd bug-finder
```

2. **Install Dependencies**

```bash
pip install -r requirements.txt
```

> Required modules: `requests`, `beautifulsoup4`, `colorama`, `fpdf`

3. **Run the GUI Application**

```bash
python gui.py
```

---

## 🛠️ Usage

1. Enter the target website URL (e.g. `https://example.com`)
2. Select the vulnerability type
3. Click **"🚀 Start Scan"**
4. View results filtered by vulnerability type
5. Click **"💾 Save Results"** to export to Pdf
6. Click **"🛠️ Scan Open Ports"** to scan for open ports
7. Click **"💡 Cyber Tip"** to view some CyberSecurity tips

---

## 📁 Project Structure

```
bug/
├── gui.py               # GUI application (main entry)
├── scanner.py           # Scanner logic
├── README.md            # This file
├── requirements.txt     # Contains all requuirements
├── BugFinder.spec       # Optional
```

---

## 🔒 Disclaimer

This tool is intended for **educational and ethical testing only**. Do not use it against websites without proper authorization.

---

## 👨‍💻 Author

**Swethan B**
Cybersecurity Enthusiast

---

## 📄 License

This project is licensed under the MIT License.
