# app.py
# Full Backend for Local Network Scanner Web App

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
import subprocess
import socket
import ipaddress
import concurrent.futures
import os
import shlex
import platform
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import time
import matplotlib.pyplot as plt
from io import BytesIO

# ------------------ Logging ------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------ Configuration ------------------
ALLOWED_IPS = ["127.0.0.1", "192.168.1.0/24"]
APP_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = APP_ROOT.parent / "frontend"
DEFAULT_CIDR = os.environ.get("SUBNET_CIDR", "192.168.1.0/24")
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 993, 995, 3389]

# ------------------ Flask App ------------------
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

def is_ip_allowed(remote_addr: str) -> bool:
    """Check if the request IP is allowed"""
    try:
        ip = ipaddress.ip_address(remote_addr)
        for allowed in ALLOWED_IPS:
            if "/" in allowed:
                network = ipaddress.ip_network(allowed, strict=False)
                if ip in network:
                    return True
            else:
                if str(ip) == allowed:
                    return True
        return False
    except ValueError:
        return False

@app.before_request
def check_ip_whitelist():
    if not is_ip_allowed(request.remote_addr):
        return jsonify({"ok": False, "error": "Access denied"}), 403

# ------------------ GPT Analysis ------------------
try:
    from improved_gpt_agent import summarize_devices
except ImportError:
    def summarize_devices(devices):
        return f"Basic Analysis: Found {len(devices)} devices. {len([d for d in devices if d.get('status') == 'Online'])} online, {len([d for d in devices if d.get('status') == 'Offline'])} offline."

# ------------------ Network Scanner ------------------
class NetworkScanner:
    def __init__(self):
        self.is_windows = platform.system().lower().startswith("win")

    def ping_host(self, ip: str, timeout_ms: int = 800) -> bool:
        try:
            if self.is_windows:
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            else:
                sec = max(1, int(timeout_ms / 1000))
                cmd = ["ping", "-c", "1", "-W", str(sec), ip]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Ping failed for {ip}: {e}")
            return False

    def resolve_hostname(self, ip: str) -> str:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return ""

    def scan_ports(self, ip: str, ports: Optional[List[int]] = None, per_port_timeout: float = 0.5) -> List[int]:
        if ports is None:
            ports = COMMON_PORTS
        open_ports = []

        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(per_port_timeout)
                    if s.connect_ex((ip, int(port))) == 0:
                        return port
            except Exception:
                return None
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(ports))) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future.result()
                if port is not None:
                    open_ports.append(port)
        return sorted(open_ports)

    def get_network_hosts(self, cidr: str) -> List[str]:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 254:
                hosts = hosts[:254]
            return [str(ip) for ip in hosts]
        except ValueError as e:
            logger.error(f"Invalid CIDR {cidr}: {e}")
            net = ipaddress.ip_network(DEFAULT_CIDR, strict=False)
            return [str(ip) for ip in list(net.hosts())[:254]]

    def scan_network(self, cidr: str, limit: int = 0, timeout_ms: int = 800) -> Dict[str, Any]:
        start_time = time.time()
        hosts = self.get_network_hosts(cidr)
        if limit > 0:
            hosts = hosts[:limit]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(hosts))) as executor:
            future_to_ip = {executor.submit(self.ping_host, ip, timeout_ms): ip for ip in hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    alive = future.result()
                except Exception as e:
                    logger.error(f"Ping task failed for {ip}: {e}")
                    alive = False
                hostname = self.resolve_hostname(ip) if alive else ""
                results.append({"ip": ip, "hostname": hostname, "status": "Online" if alive else "Offline", "open_ports": []})

        results.sort(key=lambda d: (d["status"] != "Online", tuple(int(x) for x in d["ip"].split("."))))
        return {
            "cidr": cidr,
            "count": len(results),
            "devices": results,
            "scan_time": round(time.time() - start_time, 2),
            "online_count": len([d for d in results if d["status"] == "Online"]),
            "offline_count": len([d for d in results if d["status"] == "Offline"])
        }

scanner = NetworkScanner()

# ------------------ Terminal Handler ------------------
class TerminalCommandHandler:
    def __init__(self):
        self.is_windows = platform.system().lower().startswith("win")

    def parse_and_validate_command(self, user_input: str) -> Tuple[Optional[List[str]], Optional[str]]:
        try:
            tokens = shlex.split(user_input, posix=not self.is_windows)
        except ValueError as e:
            return None, f"Invalid command syntax: {e}"
        if not tokens:
            return None, "Empty command"

        cmd = tokens[0].lower()
        if cmd == "ping":
            return self._build_ping_command(tokens)
        elif cmd in ("traceroute", "tracert"):
            return self._build_traceroute_command(tokens)
        elif cmd == "netstat":
            return self._build_netstat_command(tokens)
        elif cmd in ("ipconfig", "ifconfig"):
            return self._build_ifconfig_command(cmd)
        elif cmd == "help":
            return None, self._get_help_text()
        else:
            return None, f"Command '{cmd}' not allowed. Type 'help' for available commands."

    def _build_ping_command(self, tokens: List[str]) -> Tuple[Optional[List[str]], Optional[str]]:
        host = None
        count = 4
        i = 1
        while i < len(tokens):
            token = tokens[i]
            if token in ("-c", "-n") and i + 1 < len(tokens):
                try:
                    count = min(10, max(1, int(tokens[i + 1])))
                except ValueError:
                    count = 4
                i += 2
            elif not token.startswith("-") and host is None:
                host = token
                i += 1
            else:
                i += 1
        if host is None:
            return None, "Usage: ping <host> [-c count]"
        if self.is_windows:
            return ["ping", "-n", str(count), "-w", "1000", host], None
        else:
            return ["ping", "-c", str(count), "-W", "2", host], None

    def _build_traceroute_command(self, tokens: List[str]) -> Tuple[Optional[List[str]], Optional[str]]:
        if len(tokens) < 2:
            cmd_name = "tracert" if self.is_windows else "traceroute"
            return None, f"Usage: {cmd_name} <host>"
        host = tokens[1]
        if self.is_windows:
            return ["tracert", "-d", host], None
        else:
            return ["traceroute", "-n", host], None

    def _build_netstat_command(self, tokens: List[str]) -> Tuple[Optional[List[str]], Optional[str]]:
        allowed_flags = ["-a", "-n", "-an", "-r", "-s"]
        flags = [t for t in tokens[1:] if t in allowed_flags]
        return ["netstat"] + (flags or ["-an"]), None

    def _build_ifconfig_command(self, cmd: str) -> Tuple[Optional[List[str]], Optional[str]]:
        return [cmd], None

    def _get_help_text(self) -> str:
        commands = [
            "Available commands:",
            "  ping <host> [-c count]  - Ping a host",
            "  traceroute <host>       - Trace route to host" if not self.is_windows else "  tracert <host>          - Trace route to host",
            "  netstat [-a|-n|-r|-s]  - Show network connections",
            "  ifconfig                - Show network interfaces" if not self.is_windows else "  ipconfig                - Show network interfaces",
            "  help                    - Show this help message"
        ]
        return "\n".join(commands)

    def execute_command(self, command_args: List[str]) -> Tuple[bool, str]:
        try:
            result = subprocess.run(command_args, capture_output=True, text=True, timeout=30, check=False)
            output = result.stdout + result.stderr
            return True, output or "Command completed successfully."
        except subprocess.TimeoutExpired:
            return False, "Error: Command timed out (30 seconds)"
        except FileNotFoundError:
            return False, f"Error: Command '{command_args[0]}' not found"
        except Exception as e:
            return False, f"Error: {str(e)}"

terminal_handler = TerminalCommandHandler()

# ------------------ Routes ------------------
@app.route("/")
def serve_frontend():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return send_from_directory(FRONTEND_DIR, "index.html")
    return jsonify({"message": "Network Scanner API", "version": "2.0"})

@app.route("/api/scan")
def api_scan():
    cidr = request.args.get("cidr", DEFAULT_CIDR)
    limit = min(int(request.args.get("limit", "0") or 0), 1024)
    timeout_ms = int(request.args.get("timeout_ms", "800"))
    try:
        return jsonify(scanner.scan_network(cidr, limit, timeout_ms))
    except Exception as e:
        logger.error(f"Network scan failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/ports/<ip>")
def api_ports(ip):
    try:
        raw_ports = request.args.get("ports", "")
        ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()] if raw_ports else COMMON_PORTS
        timeout = float(request.args.get("timeout", "0.5"))
        return jsonify({"ip": ip, "open_ports": scanner.scan_ports(ip, ports, timeout), "scanned_ports": ports})
    except Exception as e:
        logger.error(f"Port scan failed for {ip}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/terminal", methods=["POST"])
def api_terminal():
    try:
        data = request.get_json()
        if not data or "command" not in data:
            return jsonify({"error": "Missing command parameter"}), 400
        
        user_input = data["command"].strip()
        if not user_input:
            return jsonify({"error": "Empty command"}), 400
        
        command_args, error_msg = terminal_handler.parse_and_validate_command(user_input)
        if error_msg:
            return jsonify({"success": False, "output": error_msg})
        
        if command_args:
            success, output = terminal_handler.execute_command(command_args)
            return jsonify({"success": success, "output": output})
        else:
            return jsonify({"success": False, "output": "Invalid command"})
    except Exception as e:
        logger.error(f"Terminal command failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        data = request.get_json()
        if not data or "devices" not in data:
            return jsonify({"error": "Missing devices data"}), 400
        
        devices = data["devices"]
        analysis = summarize_devices(devices)
        return jsonify({"analysis": analysis})
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "running",
        "version": "2.0",
        "platform": platform.system(),
        "default_cidr": DEFAULT_CIDR,
        "common_ports": COMMON_PORTS
    })

@app.route("/api/chart_image")
def api_chart_image():
    data = [10, 5]  # Example: online vs offline
    labels = ["Online", "Offline"]
    fig, ax = plt.subplots()
    ax.bar(labels, data, color=['green', 'red'])
    
    buf = BytesIO()
    fig.savefig(buf, format='png')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route("/<path:filename>")
def serve_static(filename):
    try:
        static_file = FRONTEND_DIR / filename
        if static_file.exists() and static_file.is_file():
            return send_from_directory(FRONTEND_DIR, filename)
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        logger.error(f"Static file serve failed: {e}")
        return jsonify({"error": "File serve error"}), 500

# ------------------ Error Handlers ------------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Access forbidden"}), 403

# ------------------ Main ------------------
if __name__ == "__main__":
    print(f"Starting Network Scanner API v2.0")
    print(f"Platform: {platform.system()}")
    print(f"Default CIDR: {DEFAULT_CIDR}")
    print(f"Frontend directory: {FRONTEND_DIR}")
    print(f"Allowed IPs: {ALLOWED_IPS}")
    
    FRONTEND_DIR.mkdir(exist_ok=True)
    
    app.run(host="0.0.0.0", port=5000, debug=True)
