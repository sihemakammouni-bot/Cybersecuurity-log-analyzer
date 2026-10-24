
# 🛡️ Cybersecurity Log Analyzer

A Python-based cybersecurity monitoring dashboard built with **Streamlit**. It analyzes login logs, detects repeated failed login attempts, identifies suspicious activity patterns, and presents security insights through interactive charts.

## ✨ Features

- 📊 **Security Dashboard:** View login statistics and security metrics.
- 🔐 **Login Analysis:** Track successful and failed login attempts.
- 🚨 **Suspicious Activity Detection:** Identify IP addresses with repeated failed logins.
- ⏱️ **Time-Window Detection:** Detect repeated failures within a configurable time window.
- 📈 **Interactive Charts:** Visualize login status, failed attempts by IP, and activity over time.
- 🔎 **Log Filtering:** Filter events by status and search by IP address.
- 🔄 **Automatic Refresh:** Periodically reload the selected log file.
- 📥 **Report Export:** Download filtered events as CSV and security reports as TXT.
- 🧪 **Unit Tests:** Test the core log parsing and analysis functions.

## 🧰 Technologies

- Python
- Streamlit
- Pandas
- Regular expressions
- Python `unittest`

## 📁 Project Structure

```text
cybersecurity-log-analyzer/
├── app.py
├── analyzer.py
├── requirements.txt
├── sample_logs.txt
├── test_analyzer.py
└── README.md
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/sihemakammouni-bot/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## ▶️ Run the Application

Start the Streamlit dashboard:

```bash
python -m streamlit run app.py
```

Open the local URL displayed in your terminal, usually:

```text
http://localhost:8501
```

## 🧪 Run Tests

```bash
python -m unittest -v test_analyzer.py
```

## 📝 Supported Log Format

The analyzer currently supports login events in this format:

```text
2026-10-24 10:00:00 LOGIN SUCCESS IP=192.168.1.10
2026-10-24 10:00:05 LOGIN FAILED IP=203.0.113.25
```

Each event contains a timestamp, login status, and IP address.

## ⚠️ Limitations

- The application analyzes the supported text-log format; it does not automatically collect logs from every operating system or network device.
- The dashboard periodically rereads the selected log file.
- Alerts indicate activity that may require investigation; they do not prove that an attack occurred.
- Use only log files you are authorized to access.

## 🔮 Future Improvements

- Support for additional log formats.
- More advanced detection rules.
- Configurable thresholds through the interface.
- Integration with centralized logging systems.
- Additional security analytics and alert management.

## 👩‍💻 Author

**Sihem Akammouni**

Computer Science and Cybersecurity Enthusiast

---

*This project is an educational cybersecurity tool designed to practice Python development, log analysis, and security monitoring.*
