# Hackathon Local Network Scanner

## Overview
This project is a **local network scanner** and **terminal emulator** built with **Flask + GPT analysis** and a hacker-themed frontend.  
It demonstrates **GPT-OSS local agent** usage for analyzing network devices.

## Features
- Scan your LAN for devices (IP, hostname, status)
- Scan common ports for any device
- Terminal command execution (`ping`, `traceroute`, `netstat`, `ifconfig/ipconfig`)
- GPT-powered device analysis (online/offline summary)
- Interactive hacker-style UI with black/red/green theme

## Requirements
- Python 3.10+
- Flask, flask-cors, matplotlib
- Optional: OpenAI API key if using GPT-OSS analysis

## Installation
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
python app.py
