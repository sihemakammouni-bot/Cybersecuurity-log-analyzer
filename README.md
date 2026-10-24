
# Cybersecurity Log Analyzer

A Python and Streamlit application for analyzing login logs,
detecting repeated failed login attempts, and displaying
security indicators in a web dashboard.

## Features

- Login event parsing and validation
- Successful and failed login statistics
- Failed attempts grouped by IP address
- Repeated-failure detection within a time window
- Automatic refresh of the selected log file
- Search and status filters
- CSV event export
- Downloadable text reports
- Unit tests for core analysis functions

## Requirements

- Python 3.10 or newer
- pip

## Installation

Create and activate a virtual environment.

### Windows PowerShell

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell activation is unavailable, use Command Prompt:

```bat
venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

## Run the application

```bash
python -m streamlit run app.py
```

Streamlit will print a local URL in the terminal.
Open that URL in your browser.

## Run tests

```bash
python -m unittest -v test_analyzer.py
```

## Supported log format

```text
YYYY-MM-DD HH:MM:SS LOGIN SUCCESS IP=192.168.1.10
YYYY-MM-DD HH:MM:SS LOGIN FAILED IP=203.0.113.25
```

Each event must use the timestamp format shown above,
followed by LOGIN, a status, and an IP field.

## Important limitations

This is an educational project and a basic detection tool.
Alerts are indicators for further investigation, not proof
of malicious activity.

The dashboard rereads the selected file on each refresh.
For large production log streams, use a more scalable
collection and processing architecture.

Only analyze logs you are authorized to access.
