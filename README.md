# Forge IT Health Check Tool

![Forge IT Logo](assets/ForgeIT_Logo.ico)

**Forge IT Health Check Tool** is a Python application that collects system and network information, performs internet speed tests, and generates a professional PDF report with an executive summary and an LLM-generated action plan.

---

## Features

- Detect Windows version, installed patches, CPU/Memory usage, and uptime
- Detect installed antivirus software
- Scan local network for hosts, open ports, MAC addresses, and vendor info
- Perform internet speed tests
- Generate PDF reports with:
  - Logo
  - System information
  - Network scan results
  - Internet speed
  - Executive summary
  - LLM action plan (via Ollama/OpenWebUI server)
- GUI interface for easy usage
- Custom client name entry for personalized reports

---

## Installation

1. **Clone the repository**:

```
git clone https://github.com/YourUsername/forgeit-healthcheck.git
cd forgeit-healthcheck
```
2. **Install Python dependencies**:

```
pip install -r requirements.txt
```

Note: tkinter may already be included with Python.
Ensure Nmap is installed and accessible in your system PATH.

3. **Update configuration in forgeit_healthcheck.py**:

```
LOGO_PATH = "assets/ForgeIT_Logo.png"
OLLAMA_API_URL = "http://chat.mystuffs.online/api/chat/completions"
OLLAMA_API_KEY = "sk-your-api-key"
OLLAMA_MODEL = "llama3"
```

**Usage**
Run the tool:

```
python forgeit_healthcheck.py
```
Enter the client's name in the GUI.

Click buttons to run:

System Info

Network Scan

Speed Test

Full Check (all of the above)

Generate:

PDF Report (ForgeIT_HealthCheck_Report_<ClientName>.pdf)

LLM Action Plan (from your Ollama server)

Notes
No admin privileges required.

LLM action plan requires an accessible Ollama/OpenWebUI server.

Out-of-date OS or AV, open ports, and other findings are summarized in the executive report in plain, client-friendly language.
