#!/usr/bin/env python3
"""
AutoRecon - Automated Reconnaissance Tool for VAPT
"""

import argparse
import subprocess
import json
import os
import sys
import logging
import datetime
import time
import ipaddress
import shutil
import re
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from jinja2 import Template
import requests
from pathlib import Path


class Logger:
    INFO_COLOR = "\033[92m"     # Green
    WARNING_COLOR = "\033[93m"  # Yellow
    ERROR_COLOR = "\033[91m"    # Red
    RESET_COLOR = "\033[0m"     # Reset to default
    
    @staticmethod
    def info(message):
        print(f"{Logger.INFO_COLOR}[+] {message}{Logger.RESET_COLOR}")
        logging.info(message)
    
    @staticmethod
    def warning(message):
        print(f"{Logger.WARNING_COLOR}[!] {message}{Logger.RESET_COLOR}")
        logging.warning(message)
    
    @staticmethod
    def error(message):
        print(f"{Logger.ERROR_COLOR}[-] {message}{Logger.RESET_COLOR}")
        logging.error(message)


def progress_bar(current, total, bar_length=40, prefix='Progress:', suffix=''):
    """Enhanced progress bar with percentage, elapsed time and estimated time remaining."""
    percent = (current / total) * 100
    filled_len = int(bar_length * current // total)
    bar = '█' * filled_len + '░' * (bar_length - filled_len)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% Complete {suffix}')
    sys.stdout.flush()


class ToolProgress:
    """Track the progress of running tools."""
    def __init__(self, tool_name, total_steps=100):
        self.tool_name = tool_name
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time = time.time()
        self.status = "Running"
        self.display_progress()
    
    def update(self, step=None, status=None, increment=1):
        if step is not None:
            self.current_step = min(step, self.total_steps)
        else:
            self.current_step = min(self.current_step + increment, self.total_steps)
        
        if status:
            self.status = status
            
        self.display_progress()
    
    def complete(self, status="Completed"):
        self.current_step = self.total_steps
        self.status = status
        self.display_progress()
        print()  # Move to next line after completion
    
    def display_progress(self):
        elapsed = time.time() - self.start_time
        if self.current_step > 0:
            estimated_total = elapsed * self.total_steps / self.current_step
            remaining = estimated_total - elapsed
            suffix = f"{self.status} - {format_time(elapsed)} elapsed, {format_time(remaining)} remaining"
        else:
            suffix = f"{self.status} - Starting..."
            
        progress_bar(self.current_step, self.total_steps, prefix=f"{self.tool_name}:", suffix=suffix)


def format_time(seconds):
    """Format seconds into a human-readable time string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("autorecon.log"),
    ]
)
logger = logging.getLogger("AutoRecon")


class AutoRecon:
    """Main class for the AutoRecon tool"""

    def __init__(self, args):
        self.target = args.target
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = Path(args.output_dir) if args.output_dir else Path(f"recon_{self.target}_{timestamp}")
        self.verbose = args.verbose
        self.ports = args.ports if args.ports else "1-1000"
        self.subdomains = args.subdomains
        self.protocols = args.protocols or ["tcp"]
        self.threads = args.threads
        self.tools_option = args.tools  # option for specifying which tools to run
        self.tool_status = {}  # Track status of each tool
        
        self._create_directories()

        # Store results; Nmap results come from parsed grepable output.
        self.results = {
            "metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "target": self.target,
                "command_line": " ".join(sys.argv),
            },
            "nmap": {},
            "subfinder": [],
            "httpx": [],
            "gobuster": {},
            "spiderfoot": {}
        }

        self._check_prerequisites()

    def _create_directories(self):
        for subdir in ["nmap", "subfinder", "httpx", "gobuster", "spiderfoot"]:
            (self.output_dir / subdir).mkdir(exist_ok=True, parents=True)
        Logger.info(f"Output directories created at {self.output_dir}")

    def _check_prerequisites(self):
        required_tools = ["nmap", "subfinder", "httpx-toolkit", "gobuster", "sf"]
        missing = []
        
        Logger.info("Checking required tools...")
        progress = ToolProgress("Tool check", len(required_tools))
        
        for i, tool in enumerate(required_tools):
            tool_path = shutil.which(tool)
            progress.update(i+1, status=f"Checking {tool}..." + ("✓" if tool_path else "✗"))
            if not tool_path:
                missing.append(tool)
            time.sleep(0.2)  # Small delay for visual effect
        
        progress.complete()
        
        if missing:
            Logger.error(f"Missing required tools: {', '.join(missing)}")
            print("\nInstallation instructions:")
            print("- Nmap: https://nmap.org/download.html")
            print("- Subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            print("- Httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            print("- Gobuster: go install github.com/OJ/gobuster/v3@latest")
            print("- Spiderfoot: https://github.com/smicallef/spiderfoot")
            sys.exit(1)
        else:
            Logger.info("All required tools are installed!")
            
        self.has_spiderfoot = shutil.which("sf") is not None
        if not self.has_spiderfoot:
            Logger.warning("Spiderfoot (sf) not found. OSINT scanning will be skipped.")

    def _is_valid_target(self):
        try:
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            return re.match(domain_pattern, self.target) is not None

    def _run_command(self, command, output_file=None, tool_name=None, total_steps=100):
        if self.verbose:
            Logger.info(f"Running command: {' '.join(command)}")
        
        progress = None
        if tool_name:
            progress = ToolProgress(tool_name, total_steps)
            self.tool_status[tool_name] = {"progress": progress, "status": "Running"}
        
        try:
            if output_file:
                with open(output_file, 'w') as f:
                    process = subprocess.Popen(
                        command, 
                        stdout=f, 
                        stderr=subprocess.PIPE, 
                        text=True
                    )
                    
                    # Monitor process and update progress
                    if progress:
                        while process.poll() is None:
                            progress.update(increment=1, status="Running")
                            time.sleep(1)
                    
                    process.wait()
                    if process.returncode != 0:
                        if progress:
                            progress.complete(status="Failed")
                        return False
                    else:
                        if progress:
                            progress.complete()
                        return True
            else:
                process = subprocess.Popen(
                    command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
                
                # Monitor process and capture output
                output = []
                for line in process.stdout:
                    output.append(line)
                    if progress:
                        progress.update(increment=1, status="Processing")
                
                process.wait()
                if process.returncode != 0:
                    if progress:
                        progress.complete(status="Failed")
                    return False
                else:
                    if progress:
                        progress.complete()
                    return ''.join(output)
        except subprocess.SubprocessError as e:
            Logger.error(f"Command failed: {' '.join(command)}")
            Logger.error(f"Error message: {str(e)}")
            if progress:
                progress.complete(status="Error")
            return False

    def get_selected_tasks(self):
        """Return a dict of tasks to run based on the --tools option."""
        all_tasks = {
            "nmap": self.run_nmap,
            "subfinder": self.run_subfinder,
            "httpx": self.run_httpx,
            "gobuster": self.run_gobuster,
            "spiderfoot": self.run_spiderfoot if self.has_spiderfoot else None
        }
        if self.tools_option.lower() == "all":
            return {k: v for k, v in all_tasks.items() if v is not None}
        selected = [tool.strip().lower() for tool in self.tools_option.split(',')]
        tasks = {k: v for k, v in all_tasks.items() if k in selected and v is not None}
        return tasks

    def parse_nmap_grepable(self, filename):
        """Parse Nmap's grepable (-oG) output to extract port information."""
        ports = []
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
                total_lines = len(lines)
                Logger.info(f"Parsing {total_lines} lines from Nmap output...")
                progress = ToolProgress("Parsing Nmap", total_lines)
                
                for i, line in enumerate(lines):
                    progress.update(i+1)
                    
                    if line.startswith("#") or not line.strip():
                        continue
                    m = re.search(r"Ports:\s*(.*)", line)
                    if m:
                        port_str = m.group(1)
                        port_entries = port_str.split(',')
                        for entry in port_entries:
                            parts = entry.split('/')
                            if len(parts) >= 3:
                                ports.append({
                                    "port": parts[0],
                                    "state": parts[1],
                                    "protocol": parts[2],
                                    "service": parts[4] if len(parts) > 4 else "",
                                    "version": " ".join(parts[5:]).strip() if len(parts) > 5 else ""
                                })
                
                progress.complete()
        except Exception as e:
            Logger.error(f"Error parsing grepable Nmap output: {e}")
        return ports

    def run_nmap(self):
        Logger.info("Starting Nmap scan with grepable output...")
        nmap_grep = self.output_dir / "nmap" / "nmap_scan.grepable"
        cmd = ["nmap", "-sV", "-sC", "-oG", str(nmap_grep)]
        for proto in self.protocols:
            if proto.lower() == "udp":
                cmd.append("-sU")
        cmd.extend(["-p", self.ports, self.target])
        
        # Estimate total steps based on number of ports and protocols
        port_count = 0
        if "-" in self.ports:
            start, end = self.ports.split("-")
            port_count = int(end) - int(start) + 1
        elif "," in self.ports:
            port_count = len(self.ports.split(","))
        else:
            try:
                port_count = 1 if int(self.ports) > 0 else 1000
            except ValueError:
                port_count = 1000
        
        total_steps = port_count * len(self.protocols) * 2  # multiply by 2 for discovery and analysis phases
        
        if not self._run_command(cmd, output_file=nmap_grep, tool_name="Nmap Scan", total_steps=total_steps):
            Logger.error("Nmap scan failed")
            return

        ports = self.parse_nmap_grepable(nmap_grep)
        self.results["nmap"] = {"ports": ports}
        Logger.info(f"Nmap scan completed with {len(ports)} ports found.")

    def run_subfinder(self):
        if not self._is_domain():
            Logger.info("Skipping Subfinder as target is not a domain")
            return
        Logger.info("Starting Subfinder scan...")
        output_file = self.output_dir / "subfinder" / "subdomains.txt"
        cmd = ["subfinder", "-d", self.target, "-all", "-o", str(output_file)]
        
        if self._run_command(cmd, output_file=output_file, tool_name="Subfinder", total_steps=100):
            try:
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    self.results["subfinder"] = subdomains
                    
                Logger.info(f"Discovered {len(self.results['subfinder'])} subdomains")
            except Exception as e:
                Logger.error(f"Failed to read Subfinder output: {e}")
        else:
            Logger.error("Subfinder scan failed")

    def _is_domain(self):
        try:
            ipaddress.ip_address(self.target)
            return False
        except ValueError:
            return True

    def run_httpx(self):
        Logger.info("Starting Httpx scan...")
        # Use subfinder results if available and target is a domain.
        if self._is_domain() and self.results["subfinder"]:
            Logger.info("Subfinder results available; using subdomains for Httpx scan.")
            input_targets = self.results["subfinder"]
        else:
            Logger.info("No subdomains found; using target domain for Httpx scan.")
            input_targets = [self.target]

        temp_file = self.output_dir / "httpx" / "targets.txt"
        with open(temp_file, 'w') as f:
            for t in input_targets:
                f.write(f"{t}\n")
        output_file = self.output_dir / "httpx" / "httpx_results.json"
        cmd = [
            "httpx-toolkit", "-l", str(temp_file),
            "-json", "-o", str(output_file),
            "-title", "-status-code", "-tech-detect", "-server",
            "-follow-redirects", "-ip"
        ]
        
        # Run the command with progress tracking
        if self._run_command(cmd, output_file=output_file, tool_name="Httpx", total_steps=len(input_targets)*2):
            try:
                with open(output_file, 'r') as f:
                    lines = f.readlines()
                    total_lines = len(lines)
                    results = []
                    
                    Logger.info(f"Processing {total_lines} Httpx results...")
                    progress = ToolProgress("Processing Httpx", total_lines)
                    
                    for i, line in enumerate(lines):
                        progress.update(i+1)
                        if line.strip():
                            results.append(json.loads(line))
                    
                    progress.complete()
                    self.results["httpx"] = results
                Logger.info(f"Discovered {len(self.results['httpx'])} active web endpoints")
            except Exception as e:
                Logger.error(f"Failed to read Httpx output: {e}")
        else:
            Logger.error("Httpx scan failed")

    def run_gobuster(self):
        Logger.info("Starting Gobuster scan...")
        if self.results["httpx"]:
            web_targets = [res["url"] for res in self.results["httpx"] if "url" in res]
        else:
            web_targets = [f"http://{self.target}", f"https://{self.target}"] if self._is_domain() else [f"http://{self.target}"]

        wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        if not os.path.exists(wordlist):
            wordlist = str(self.output_dir / "gobuster" / "wordlist.txt")
            with open(wordlist, 'w') as f:
                for d in ["admin", "login", "wp-admin", "wp-content", "assets", "images",
                          "js", "css", "api", "uploads", "backup", "config", "docs"]:
                    f.write(f"{d}\n")
        self.results["gobuster"] = {}
        # Regex pattern to capture gobuster output with redirect link.
        pattern = re.compile(
            r'^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\]\s+\[\-\-\>\s*(?P<redirect>.*?)\]'
        )
        
        total_targets = len(web_targets[:3])
        overall_progress = ToolProgress("Gobuster Overall", total_targets)
        
        for idx, target in enumerate(web_targets[:3], 1):
            Logger.info(f"Running Gobuster on target {idx}/{total_targets}: {target}")
            safe_target = target.replace("://", "_").replace(".", "_").replace("/", "_")
            output_file = self.output_dir / "gobuster" / f"gobuster_{safe_target}.txt"
            cmd = [
                "gobuster", "dir",
                "-u", target,
                "-w", wordlist,
                "-o", str(output_file),
                "-q"
            ]
            
            tool_name = f"Gobuster ({idx}/{total_targets})"
            if self._run_command(cmd, output_file=output_file, tool_name=tool_name, total_steps=100):
                try:
                    self.results["gobuster"][target] = []
                    with open(output_file, 'r') as f:
                        for line in f:
                            match = pattern.search(line)
                            if match:
                                self.results["gobuster"][target].append(match.groupdict())
                except Exception as e:
                    Logger.error(f"Failed to read Gobuster output for {target}: {e}")
            else:
                Logger.error(f"Gobuster scan failed for {target}")
            
            # Update overall progress
            overall_progress.update(idx, status=f"Completed {idx}/{total_targets} targets")
            
        overall_progress.complete()
        Logger.info("Gobuster scan completed")

    def run_spiderfoot(self):
        if not self.has_spiderfoot:
            Logger.info("Skipping Spiderfoot scan as it's not installed")
            return
        Logger.info("Starting Spiderfoot scan...")
        try:
            resp = requests.get("http://127.0.0.1:5001")
            if resp.status_code != 200:
                Logger.warning("Spiderfoot UI not running. Proceeding in CLI mode.")
        except requests.exceptions.ConnectionError:
            Logger.warning("Spiderfoot UI not running. Proceeding in CLI mode.")
        output_file = self.output_dir / "spiderfoot" / "sf_results.json"
        modules = "sfp_dnsresolve,sfp_dnscommonsrv,sfp_dnsneighbor,sfp_whois,sfp_ssl"
        cmd = ["sf", "-m", modules, "-s", self.target, "-o", "JSON", "-q"]
        
        sf_output = self._run_command(cmd, tool_name="Spiderfoot", total_steps=100)
        if sf_output:
            try:
                with open(output_file, 'w') as f:
                    f.write(sf_output)
                self.results["spiderfoot"] = json.loads(sf_output) if sf_output.strip() else {}
                Logger.info("Spiderfoot scan completed")
            except Exception as e:
                Logger.error(f"Failed to process Spiderfoot output: {e}")
        else:
            Logger.error("Spiderfoot scan failed")

    def generate_html_report(self):
        Logger.info("Generating HTML report...")
        progress = ToolProgress("Generating HTML Report", 100)
        
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AutoRecon Report - {{ target }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
                header { background: #2c3e50; color: #fff; padding: 20px; }
                .summary { background: #f5f5f5; padding: 15px; margin-bottom: 20px; }
                .section { border: 1px solid #ddd; padding: 15px; margin-bottom: 30px; }
                table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }
                th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                th { background: #f2f2f2; }
                .footer { text-align: center; margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px; color: #777; }
                .dashboard { display: flex; justify-content: space-between; flex-wrap: wrap; margin-bottom: 20px; }
                .dashboard-item { background: #e9f7ef; border: 1px solid #ddd; padding: 15px; width: 22%; text-align: center; margin-bottom: 10px; }
                .dashboard-item h3 { margin-top: 0; color: #2c3e50; }
                .dashboard-item p { font-size: 24px; font-weight: bold; margin: 10px 0; }
                .vulnerability-summary { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; margin-bottom: 20px; }
                .severity-high { color: #721c24; }
                .severity-medium { color: #856404; }
                .severity-low { color: #155724; }
            </style>
        </head>
        <body>
            <header>
                <h1>AutoRecon Vulnerability Assessment Report</h1>
                <p>Target: {{ target }}</p>
                <p>Scan Date: {{ timestamp }}</p>
            </header>
            
            <div class="dashboard">
                <div class="dashboard-item">
                    <h3>Open Ports</h3>
                    <p>{{ nmap.ports|length if nmap.ports else 0 }}</p>
                </div>
                <div class="dashboard-item">
                    <h3>Subdomains</h3>
                    <p>{{ subfinder|length }}</p>
                </div>
                <div class="dashboard-item">
                    <h3>Web Endpoints</h3>
                    <p>{{ httpx|length }}</p>
                </div>
                <div class="dashboard-item">
                    <h3>Directories</h3>
                    <p>{{ gobuster_count }}</p>
                </div>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>This report presents the results of an automated reconnaissance scan performed on {{ target }} 
                on {{ timestamp }}. The scan included port scanning, subdomain enumeration, web endpoint discovery, 
                and directory/file enumeration to identify potential security vulnerabilities.</p>
                
                <p>Key findings:</p>
                <ul>
                    <li><strong>{{ nmap.ports|length if nmap.ports else 0 }}</strong> open ports discovered</li>
                    <li><strong>{{ subfinder|length }}</strong> subdomains identified</li>
                    <li><strong>{{ httpx|length }}</strong> active web endpoints found</li>
                    <li><strong>{{ gobuster_count }}</strong> directories/files enumerated</li>
                </ul>
            </div>
            
            {% if nmap %}
            <div class="section">
                <h2>Nmap Scan Results</h2>
                <table>
                    <thead>
                        <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
                    </thead>
                    <tbody>
                        {% for port in nmap.ports %}
                        <tr>
                            <td>{{ port.port }}</td>
                            <td>{{ port.state }}</td>
                            <td>{{ port.service }}</td>
                            <td>{{ port.version }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if subfinder %}
            <div class="section">
                <h2>Subdomain Discovery</h2>
                <table>
                    <thead><tr><th>#</th><th>Subdomain</th></tr></thead>
                    <tbody>
                        {% for sub in subfinder %}
                        <tr><td>{{ loop.index }}</td><td>{{ sub }}</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if httpx %}
            <div class="section">
                <h2>Web Endpoints (Httpx)</h2>
                <table>
                    <thead>
                        <tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technologies</th></tr>
                    </thead>
                    <tbody>
                        {% for ep in httpx %}
                        <tr>
                            <td>{{ ep.url }}</td>
                            <td>{{ ep.status_code }}</td>
                            <td>{{ ep.title }}</td>
                            <td>{{ ep.server }}</td>
                            <td>{{ ep.tech|join(', ') if ep.tech else '' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if gobuster %}
            <div class="section">
                <h2>Gobuster Results</h2>
                {% for tgt, paths in gobuster.items() %}
                <h3>Target: {{ tgt }}</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Size</th>
                            <th>Redirect</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for p in paths %}
                        <tr>
                            <td>{{ p.path }}</td>
                            <td>{{ p.status }}</td>
                            <td>{{ p.size }}</td>
                            <td>
                                {% if p.redirect %}
                                <a href="{{ p.redirect }}" target="_blank">{{ p.redirect }}</a>
                                {% else %}
                                N/A
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if spiderfoot %}
            <div class="section">
                <h2>Spiderfoot (OSINT) Data</h2>
                <table>
                    <thead><tr><th>Type</th><th>Data</th><th>Source</th></tr></thead>
                    <tbody>
                        {% for item in spiderfoot_data %}
                        <tr>
                            <td>{{ item.type }}</td>
                            <td>{{ item.data }}</td>
                            <td>{{ item.source }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            <div class="footer">
                <p>Report generated by AutoRecon on {{ timestamp }}</p>
            </div>
        </body>
        </html>
        """
        
        progress.update(20, status="Preparing data")
        nmap_ports = self.results["nmap"].get("ports", [])
        spiderfoot_data = []
        if self.results["spiderfoot"]:
            for key, value in self.results["spiderfoot"].items():
                if isinstance(value, list):
                    for item in value[:20]:
                        if isinstance(item, dict):
                            spiderfoot_data.append({
                                "type": item.get("type", "N/A"),
                                "data": item.get("data", "N/A"),
                                "source": item.get("source", "N/A")
                            })
        
        progress.update(40, status="Counting results")
        gobuster_count = sum(len(v) for v in self.results["gobuster"].values())
        
        progress.update(60, status="Rendering template")
        template = Template(html_template)
        html_content = template.render(
            target=self.target,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            nmap={"ports": nmap_ports},
            subfinder=self.results["subfinder"],
            httpx=self.results["httpx"],
            gobuster=self.results["gobuster"],
            gobuster_count=gobuster_count,
            spiderfoot_data=spiderfoot_data,
            spiderfoot=bool(self.results["spiderfoot"])
        )
        
        progress.update(80, status="Writing HTML file")
        report_file = self.output_dir / "report.html"
        with open(report_file, 'w') as f:
            f.write(html_content)
        
        progress.update(100, status="Complete")
        Logger.info(f"HTML report generated at {report_file}")
        return report_file

    def save_json_results(self):
        progress = ToolProgress("Saving JSON Results", 100)
        progress.update(50, status="Writing JSON data")
        
        json_file = self.output_dir / "results.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        progress.complete()
        Logger.info(f"JSON results saved to {json_file}")
        return json_file

    def display_tool_status_dashboard(self):
        """Display a dashboard showing the status of all tools."""
        print("\n" + "="*50)
        print(" TOOL STATUS DASHBOARD ".center(50, "="))
        print("="*50)
        
        for tool, status in self.tool_status.items():
            progress = status["progress"]
            percent = (progress.current_step / progress.total_steps) * 100
            status_text = status.get("status", "Unknown")
            bar_length = 25
            filled_len = int(bar_length * progress.current_step // progress.total_steps)
            bar = '█' * filled_len + '░' * (bar_length - filled_len)
            
            print(f"{tool:<15} [{bar}] {percent:5.1f}% - {status_text}")
        
        print("="*50 + "\n")

    def run(self):
        try:
            if not self._is_valid_target():
                Logger.error(f"Invalid target: {self.target}")
                return False

            Logger.info(f"Starting reconnaissance on {self.target}")
            tasks = self.get_selected_tasks()

            # If subfinder is selected, run it first to gather subdomains for Httpx.
            if "subfinder" in tasks:
                Logger.info("Running subfinder scan first to gather subdomains for Httpx.")
                self.run_subfinder()
                del tasks["subfinder"]

            # Show tool execution plan
            Logger.info(f"Will execute the following tools: {', '.join(tasks.keys())}")
            
            # Create a progress tracker for overall scan progress
            overall_progress = ToolProgress("Overall Scan", len(tasks) + 2)  # +2 for report generation
            overall_progress.update(0, status="Starting scans")
            
            completed_tasks = 0
            # Run remaining tasks concurrently with controlled execution
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all tasks
                futures = {executor.submit(func): name for name, func in tasks.items()}
                
                # Process results as they complete
                for future in as_completed(futures):
                    tool_name = futures[future]
                    try:
                        future.result()
                        completed_tasks += 1
                        overall_progress.update(completed_tasks, status=f"Running - {completed_tasks}/{len(tasks)} tools completed")
                        Logger.info(f"{tool_name} completed successfully.")
                        
                        # Optionally display the dashboard after each tool completes
                        if self.verbose:
                            self.display_tool_status_dashboard()
                            
                    except KeyboardInterrupt:
                        Logger.info(f"{tool_name} scan interrupted by user.")
                        executor.shutdown(cancel_futures=True)
                        raise
                    except Exception as e:
                        completed_tasks += 1
                        overall_progress.update(completed_tasks, status=f"Running - {completed_tasks}/{len(tasks)} tools completed (with errors)")
                        Logger.error(f"{tool_name} encountered an error: {e}")

            # Generate reports
            overall_progress.update(len(tasks) + 1, status="Generating reports")
            html_report = self.generate_html_report()
            json_report = self.save_json_results()
            
            # Complete the overall progress
            overall_progress.complete(status="Scan completed")
            
            # Final summary
            Logger.info("Reconnaissance completed")
            Logger.info(f"HTML Report: {html_report}")
            Logger.info(f"JSON Report: {json_report}")
            
            # Print a nice summary box
            print("\n" + "="*60)
            print(" SCAN SUMMARY ".center(60, "="))
            print("="*60)
            print(f"Target: {self.target}")
            print(f"Open Ports: {len(self.results['nmap'].get('ports', []))}")
            print(f"Subdomains: {len(self.results['subfinder'])}")
            print(f"Web Endpoints: {len(self.results['httpx'])}")
            gobuster_count = sum(len(v) for v in self.results["gobuster"].values())
            print(f"Discovered Directories: {gobuster_count}")
            print(f"Output Directory: {self.output_dir}")
            print(f"HTML Report: {html_report.name}")
            print("="*60)
            
            return True
        except KeyboardInterrupt:
            Logger.info("Scan interrupted by user (Ctrl+C). Exiting gracefully.")
            return False


def is_admin():
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def countdown_timer(seconds):
    """Display a countdown timer with spinner animation."""
    spinner = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
    spinner_idx = 0
    
    for remaining in range(seconds, 0, -1):
        mins, secs = divmod(remaining, 60)
        hours, mins = divmod(mins, 60)
        
        if hours > 0:
            time_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
        else:
            time_str = f"{mins:02d}:{secs:02d}"
            
        spinner_char = spinner[spinner_idx]
        spinner_idx = (spinner_idx + 1) % len(spinner)
        
        sys.stdout.write(f"\r{spinner_char} Starting scan in {time_str}...")
        sys.stdout.flush()
        time.sleep(1)
    
    sys.stdout.write("\rStarting scan now!                \n")


def main():
    try:
        parser = argparse.ArgumentParser(description="AutoRecon - Automated Reconnaissance Tool for VAPT")
        parser.add_argument("target", help="Target domain or IP address")
        parser.add_argument("-o", "--output-dir", help="Output directory for results")
        parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '80,443,8080' or '1-1000')")
        parser.add_argument("-s", "--subdomains", help="Specify subdomains to scan (comma-separated)")
        parser.add_argument("-P", "--protocols", nargs="+", choices=["tcp", "udp"], help="Protocols to scan")
        parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
        parser.add_argument("--schedule", help="Schedule the scan (format: YYYY-MM-DD HH:MM)")
        parser.add_argument("--notify", help="Email address to notify upon completion")
        parser.add_argument("--tools", default="all", help="Comma-separated list of tools to run (available: nmap, subfinder, httpx, gobuster, spiderfoot; default: all)")
        parser.add_argument("--dashboard", action="store_true", help="Display real-time dashboard during scanning")
        
        args = parser.parse_args()

        # Print ASCII banner with color
        banner = r"""
 _______  __   __  _______  _______  ______    _______  _______  _______  __    _ 
|   _   ||  | |  ||       ||       ||    _ |  |       ||       ||       ||  |  | |
|  |_|  ||  | |  ||_     _||   _   ||   | ||  |    ___||       ||   _   ||   |_| |
|       ||  |_|  |  |   |  |  | |  ||   |_||_ |   |___ |       ||  | |  ||       |
|       ||       |  |   |  |  |_|  ||    __  ||    ___||      _||  |_|  ||  _    |
|   _   ||       |  |   |  |       ||   |  | ||   |___ |     |_ |       || | |   |
|__| |__||_______|  |___|  |_______||___|  |_||_______||_______||_______||_|  |__|
        """
        
        # ANSI color codes
        colors = ["\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[94m", "\033[95m"]
        color_idx = 0
        colored_banner = ""
        
        for line in banner.split('\n'):
            colored_banner += f"{colors[color_idx]}{line}\033[0m\n"
            color_idx = (color_idx + 1) % len(colors)
        
        print(colored_banner)
        print("\033[1mAutomated Reconnaissance Tool for VAPT\033[0m\n")

        if not is_admin() and any(proto == "udp" for proto in (args.protocols or [])):
            Logger.warning("UDP scans may require administrative privileges")

        if args.schedule:
            try:
                schedule_time = datetime.datetime.strptime(args.schedule, "%Y-%m-%d %H:%M")
                now = datetime.datetime.now()
                if schedule_time > now:
                    wait_seconds = int((schedule_time - now).total_seconds())
                    Logger.info(f"Scan scheduled for {args.schedule}.")
                    
                    # Show fancy countdown timer
                    countdown_timer(wait_seconds)
                else:
                    Logger.warning("Scheduled time is in the past; running immediately.")
            except ValueError:
                Logger.error("Invalid schedule format. Use YYYY-MM-DD HH:MM")
                return

        # Initialize and run the AutoRecon tool
        recon = AutoRecon(args)
        success = recon.run()

        if success and args.notify:
            try:
                Logger.info(f"Scan completed. Notification would be sent to {args.notify}")
                # TODO: Implement actual email notification
            except Exception as e:
                Logger.error(f"Failed to send notification: {e}")

        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        Logger.info("Scan interrupted by user (Ctrl+C) in main. Exiting gracefully.")
        sys.exit(1)


if __name__ == "__main__":
    main()
