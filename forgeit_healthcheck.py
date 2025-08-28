import os
import socket
import psutil
import nmap
import speedtest
import subprocess
from datetime import datetime
from collections import Counter
import tkinter as tk
from tkinter import scrolledtext, messagebox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import requests
import matplotlib.pyplot as plt
import tempfile

# ---------- Configuration ----------
LOGO_PATH = r"C:\Users\boxos\Pictures\ForgeIT Logo.png"
OLLAMA_API_URL = "http://chat.mystuffs.online/api/chat/completions"
OLLAMA_API_KEY = "sk-e31ce7a3ce314d0b85c893cdba02d905"
OLLAMA_MODEL = "llama3:latest"
RISKY_PORTS = {
    21: "FTP - often targeted",
    22: "SSH - potential brute force",
    23: "Telnet - insecure",
    3389: "RDP - remote exploits",
    445: "SMB - known vulnerabilities"
}
BACKUP_KEYWORDS = ["backup", "restore", "data"]

# ---------- Network Scan ----------
def run_full_network_scan(target="192.168.1.0/24"):
    nm = nmap.PortScanner()
    # TCP & UDP scans, aggressive OS detection
    nm.scan(hosts=target, arguments="-A -T4 -sU -sS")
    hosts_info = []
    for host in nm.all_hosts():
        host_data = {
            "IP": host,
            "Status": nm[host]['status']['state'],
            "MAC": None,
            "Vendor": None,
            "OS Guess": "Unknown",
            "Open Ports": [],
            "Service Banners": [],
            "Backup Shares": []
        }
        # MAC/vendor info
        if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
            host_data["MAC"] = nm[host]['addresses']['mac']
            host_data["Vendor"] = nm[host]['vendor'].get(host_data["MAC"], "Unknown")
        # OS guess
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            host_data["OS Guess"] = nm[host]['osmatch'][0]['name']
        # Open ports
        for proto in ['tcp', 'udp']:
            if proto in nm[host]:
                for port in nm[host][proto]:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', '')
                    banner = nm[host][proto][port].get('product', '')
                    host_data["Open Ports"].append(f"{port}/{state} ({service})")
                    if banner:
                        host_data["Service Banners"].append(f"{service}: {banner}")
                    # Detect possible backup shares
                    if proto == 'tcp' and port in [445,139]:
                        for kw in BACKUP_KEYWORDS:
                            if kw in service.lower():
                                host_data["Backup Shares"].append(service)
        hosts_info.append(host_data)
    return hosts_info

# ---------- Internet Speed ----------
def run_speed_test():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = round(st.download() / 1_000_000, 2)
        upload = round(st.upload() / 1_000_000, 2)
        ping = st.results.ping
        return {"Ping (ms)": ping, "Download (Mbps)": download, "Upload (Mbps)": upload}
    except Exception:
        return {"Ping (ms)": "Failed", "Download (Mbps)": "Failed", "Upload (Mbps)": "Failed"}

# ---------- LLM Action Plan ----------
def generate_hosts_summary_text(hosts):
    text = ""
    for h in hosts:
        text += f"Host: {h['IP']}, OS: {h['OS Guess']}, MAC: {h['MAC'] or 'N/A'}, Vendor: {h['Vendor'] or 'Unknown'}, Open Ports: {', '.join(h['Open Ports'])}, Backup Shares: {', '.join(h['Backup Shares'])}\n"
    return text

def generate_action_plan_with_ollama(hosts):
    summary_text = generate_hosts_summary_text(hosts)
    prompt = f"""
You are an IT consultant. Here's a client's network summary:

{summary_text}

Please generate a clear, client-friendly action plan:
- Highlight outdated OS guesses
- Highlight risky open ports
- Highlight detected backup shares
- Recommend actions to improve security and performance
- Keep it understandable for non-technical management
"""
    headers = {
        "Authorization": f"Bearer {OLLAMA_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 400
    }
    response = requests.post(OLLAMA_API_URL, headers=headers, json=payload, timeout=240)
    if response.status_code == 200:
        result = response.json()
        return result.get("choices", [{}])[0].get("message", {}).get("content", "[No response]")
    else:
        return f"[!] Ollama API error {response.status_code}: {response.text}"

# ---------- Executive Summary ----------
def generate_executive_summary(hosts):
    total_devices = len(hosts)
    outdated_os = sum(1 for h in hosts if "XP" in h['OS Guess'] or "7" in h['OS Guess'])
    risky_ports_count = sum(1 for h in hosts if any(int(p.split('/')[0]) in RISKY_PORTS for p in h['Open Ports']))
    backup_shares_count = sum(1 for h in hosts if h['Backup Shares'])
    summary = (
        f"Scanned {total_devices} devices.\n"
        f"- {outdated_os} devices have potentially outdated OS.\n"
        f"- {risky_ports_count} devices have open ports that may be vulnerable.\n"
        f"- {backup_shares_count} devices have detected backup shares.\n\n"
        "Recommendations:\n"
        "- Update any outdated operating systems.\n"
        "- Close unnecessary open ports and review firewall settings.\n"
        "- Ensure backups are secured and not exposed.\n"
    )
    return summary

# ---------- PDF Report ----------
def add_title(c, width, height, client_name="Client"):
    if os.path.exists(LOGO_PATH):
        c.drawImage(LOGO_PATH, 50, height - 120, width=80, height=80, preserveAspectRatio=True)
    c.setFillColor(colors.HexColor("#FF4500"))
    c.setFont("Helvetica-Bold", 18)
    c.drawString(150, height - 50, f"Forge IT Health Check Report for {client_name}")
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 12)
    c.drawString(150, height - 80, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def generate_pdf(hosts, speed_results, filename="ForgeIT_HealthCheck_Report.pdf", client_name="Client"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    add_title(c, width, height, client_name)
    y = height - 150

    # Network Devices
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Network Devices Found")
    y -= 20
    c.setFont("Helvetica", 12)
    for host in hosts[:10]:
        c.drawString(60, y, f"{host['IP']} - {host['OS Guess']} - {host['Status']}")
        y -= 15

    # Internet Speed
    if speed_results:
        y -= 10
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Internet Speed Test")
        y -= 20
        c.setFont("Helvetica", 12)
        for k, v in speed_results.items():
            c.drawString(60, y, f"{k}: {v}")
            y -= 15

    # Executive Summary
    y -= 10
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Executive Summary")
    y -= 20
    c.setFont("Helvetica", 12)
    summary_text = generate_executive_summary(hosts).split("\n")
    for line in summary_text:
        if y < 50:
            c.showPage()
            add_title(c, width, height, client_name)
            y = height - 150
            c.setFont("Helvetica", 12)
        c.drawString(60, y, line)
        y -= 12

    c.save()

# ---------- GUI ----------
class HealthCheckApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Forge IT - Health Check Tool")
        self.root.geometry("700x600")
        self.root.configure(bg="#333333")

        tk.Label(root, text="Forge IT Health Check Tool", bg="#333333", fg="#FF4500", font=("Helvetica", 16, "bold")).pack(pady=10)
        tk.Label(root, text="Client Name:", bg="#333333", fg="white", font=("Helvetica", 12)).pack(pady=2)
        self.client_name_entry = tk.Entry(root, width=40)
        self.client_name_entry.pack(pady=2)

        self.log = scrolledtext.ScrolledText(root, width=85, height=20, bg="black", fg="white", insertbackground="white")
        self.log.pack(pady=10)

        tk.Button(root, text="Run Full Check", command=self.run_full_check, bg="#FF4500", fg="white").pack(pady=10)
        tk.Button(root, text="Generate PDF Report", command=self.make_report, bg="grey", fg="white").pack(pady=5)
        tk.Button(root, text="Generate LLM Action Plan", command=self.generate_llm_plan, bg="#FF4500", fg="white").pack(pady=5)

        self.hosts = []
        self.speeds = {}

    def logmsg(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.root.update()

    def run_full_check(self):
        self.logmsg("[*] Running full network scan...")
        self.hosts = run_full_network_scan()
        self.logmsg(f"[+] Found {len(self.hosts)} devices")
        self.logmsg("[*] Running speed test...")
        self.speeds = run_speed_test()
        self.logmsg(f"[+] Speed test complete: {self.speeds}")
        self.logmsg("[+] Full check completed")

    def make_report(self):
        client_name = self.client_name_entry.get().strip() or "Client"
        filename = f"ForgeIT_HealthCheck_Report_{client_name.replace(' ', '_')}.pdf"
        generate_pdf(self.hosts, self.speeds, filename, client_name)
        self.logmsg(f"[+] PDF Report Generated for {client_name}")
        messagebox.showinfo("Forge IT", f"Health Check Report Generated for {client_name}!")

    def generate_llm_plan(self):
        if not self.hosts:
            self.logmsg("[!] Run a network scan first!")
            return
        self.logmsg("[*] Generating LLM Action Plan via Ollama...")
        try:
            plan = generate_action_plan_with_ollama(self.hosts)
            self.logmsg("[+] LLM Action Plan Generated:\n" + plan)
        except Exception as e:
            self.logmsg(f"[!] Failed to generate LLM action plan: {e}")

# ---------- Run ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = HealthCheckApp(root)
    root.mainloop()
