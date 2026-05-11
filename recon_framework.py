#!/usr/bin/env python3
"""
Recon Automation Framework v1.0
Author: Umair Majeed
Description: Complete reconnaissance automation tool for bug bounty and penetration testing
"""

import os
import sys
import json
import time
import subprocess
import argparse
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import concurrent.futures

# Try to import optional modules
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ReconFramework:
    """Advanced reconnaissance automation framework"""
    
    def __init__(self, target: str, output_dir: str = None):
        self.target = target.lower().strip()
        self.start_time = datetime.now()
        
        # Colors for output (MUST be defined BEFORE setup_directories)
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m'
        }
        
        # Setup directories
        if output_dir:
            self.base_dir = Path(output_dir)
        else:
            self.base_dir = Path(f"recon_{self.target}_{self.start_time.strftime('%Y%m%d_%H%M%S')}")
        
        self.setup_directories()
        
        # Results storage
        self.subdomains = set()
        self.alive_hosts = set()
        self.technologies = {}
        self.nuclei_results = []
        self.screenshots = []
        
        # Tool paths (customize as needed)
        self.tools = {
            'subfinder': 'subfinder',
            'assetfinder': 'assetfinder',
            'amass': 'amass',
            'findomain': 'findomain',
            'httpx': 'httpx',
            'nuclei': 'nuclei',
            'gowitness': 'gowitness',
            'webanalyze': 'webanalyze',
            'naabu': 'naabu'
        }
    
    def setup_directories(self):
        """Create directory structure"""
        directories = [
            self.base_dir,
            self.base_dir / "subdomains",
            self.base_dir / "alive_hosts",
            self.base_dir / "screenshots",
            self.base_dir / "nuclei_results",
            self.base_dir / "tech_detect",
            self.base_dir / "ports",
            self.base_dir / "reports",
            self.base_dir / "logs"
        ]
        
        for dir_path in directories:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        print(f"{self.colors['green']}[+]{self.colors['reset']} Output directory: {self.base_dir}")
    
    def log(self, message: str, level: str = "INFO"):
        """Print colored log messages"""
        prefix = {
            "INFO": f"{self.colors['blue']}[*]{self.colors['reset']}",
            "SUCCESS": f"{self.colors['green']}[+]{self.colors['reset']}",
            "ERROR": f"{self.colors['red']}[-]{self.colors['reset']}",
            "WARNING": f"{self.colors['yellow']}[!]{self.colors['reset']}"
        }.get(level, "[*]")
        
        print(f"{prefix} {message}")
    
    def check_dependencies(self):
        """Check if required tools are installed"""
        self.log("Checking dependencies...", "INFO")
        
        missing_tools = []
        required_tools = ['subfinder', 'assetfinder', 'httpx', 'nuclei']
        
        for tool in required_tools:
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                missing_tools.append(tool)
        
        if missing_tools:
            self.log(f"Missing tools: {', '.join(missing_tools)}", "WARNING")
            self.log("Install with: go install -v github.com/tomnomnom/assetfinder@latest", "INFO")
            return False
        
        self.log("All dependencies found!", "SUCCESS")
        return True
    
    def run_command(self, cmd: List[str], description: str = None) -> tuple:
        """Execute a command and return output"""
        if description:
            self.log(description, "INFO")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {' '.join(cmd)}", "ERROR")
            return "", "Timeout", 1
        except Exception as e:
            self.log(f"Command failed: {e}", "ERROR")
            return "", str(e), 1
    
    # ================================================================
    # PHASE 1: Subdomain Enumeration
    # ================================================================
    
    def enumerate_subdomains(self):
        """Run multiple subdomain enumeration tools"""
        self.log("Starting subdomain enumeration...", "INFO")
        
        subdomain_file = self.base_dir / "subdomains" / "all_subdomains.txt"
        
        # Tool configurations
        tools_config = [
            {
                'name': 'Subfinder',
                'cmd': [self.tools['subfinder'], '-d', self.target, '-all', '-silent']
            },
            {
                'name': 'Assetfinder',
                'cmd': [self.tools['assetfinder'], '--subs-only', self.target]
            }
        ]
        
        # Run each tool
        for tool in tools_config:
            try:
                self.log(f"Running {tool['name']}...", "INFO")
                stdout, stderr, code = self.run_command(tool['cmd'])
                
                if stdout:
                    for line in stdout.splitlines():
                        line = line.strip()
                        if line and not line.startswith('['):
                            self.subdomains.add(line.lower())
                
            except FileNotFoundError:
                self.log(f"{tool['name']} not found. Skipping...", "WARNING")
        
        # Save results
        with open(subdomain_file, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        self.log(f"Found {len(self.subdomains)} subdomains", "SUCCESS")
        return self.subdomains
    
    # ================================================================
    # PHASE 2: Alive Host Discovery
    # ================================================================
    
    def discover_alive_hosts(self):
        """Find alive hosts using httpx"""
        self.log("Discovering alive hosts...", "INFO")
        
        subdomain_file = self.base_dir / "subdomains" / "all_subdomains.txt"
        alive_file = self.base_dir / "alive_hosts" / "alive_hosts.txt"
        alive_json = self.base_dir / "alive_hosts" / "alive_hosts.json"
        
        if not subdomain_file.exists() or subdomain_file.stat().st_size == 0:
            self.log("No subdomains found to probe", "ERROR")
            return set()
        
        # Run httpx
        try:
            httpx_cmd = [
                self.tools['httpx'],
                '-l', str(subdomain_file),
                '-silent',
                '-status-code',
                '-title',
                '-tech-detect',
                '-content-length',
                '-response-time',
                '-follow-redirects',
                '-threads', '50',
                '-timeout', '10',
                '-o', str(alive_file)
            ]
            
            stdout, stderr, code = self.run_command(httpx_cmd, "Probing hosts with httpx...")
            
            # Parse alive hosts
            if alive_file.exists():
                with open(alive_file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and 'http' in url:
                            self.alive_hosts.add(url)
            
        except FileNotFoundError:
            self.log("httpx not found. Install it first.", "ERROR")
            return set()
        
        self.log(f"Found {len(self.alive_hosts)} alive hosts", "SUCCESS")
        return self.alive_hosts
    
    # ================================================================
    # PHASE 3: Port Scanning (Optional)
    # ================================================================
    
    def port_scan(self, ports: str = "top-100"):
        """Scan for open ports using naabu"""
        self.log(f"Scanning ports ({ports})...", "INFO")
        
        port_file = self.base_dir / "ports" / "open_ports.txt"
        subdomain_file = self.base_dir / "subdomains" / "all_subdomains.txt"
        
        if not subdomain_file.exists() or subdomain_file.stat().st_size == 0:
            self.log("No subdomains to scan", "WARNING")
            return
        
        try:
            # Run naabu
            naabu_cmd = [
                self.tools['naabu'],
                '-list', str(subdomain_file),
                '-ports', ports,
                '-silent',
                '-o', str(port_file)
            ]
            
            stdout, stderr, code = self.run_command(naabu_cmd, "Scanning ports with naabu...")
            
        except FileNotFoundError:
            self.log("naabu not found. Skipping port scan.", "WARNING")
        except Exception as e:
            self.log(f"Port scan failed: {e}", "ERROR")
    
    # ================================================================
    # PHASE 4: Screenshots
    # ================================================================
    
    def take_screenshots(self):
        """Take screenshots of alive hosts using gowitness"""
        self.log("Taking screenshots...", "INFO")
        
        alive_file = self.base_dir / "alive_hosts" / "alive_hosts.txt"
        screenshot_dir = self.base_dir / "screenshots"
        
        if not alive_file.exists() or alive_file.stat().st_size == 0:
            self.log("No alive hosts to screenshot", "WARNING")
            return
        
        try:
            gowitness_cmd = [
                self.tools['gowitness'],
                'file',
                '-f', str(alive_file),
                '-P', str(screenshot_dir),
                '--timeout', '10',
                '--threads', '5'
            ]
            
            stdout, stderr, code = self.run_command(gowitness_cmd, "Capturing screenshots with gowitness...")
            
            # Find screenshot files
            self.screenshots = list(screenshot_dir.glob("*.png"))
            self.log(f"Captured {len(self.screenshots)} screenshots", "SUCCESS")
            
        except FileNotFoundError:
            self.log("gowitness not found. Skipping screenshots.", "WARNING")
    
    # ================================================================
    # PHASE 5: Technology Detection
    # ================================================================
    
    def detect_technologies(self):
        """Detect technologies using webanalyze"""
        self.log("Detecting technologies...", "INFO")
        
        alive_file = self.base_dir / "alive_hosts" / "alive_hosts.txt"
        tech_file = self.base_dir / "tech_detect" / "technologies.json"
        
        if not alive_file.exists() or alive_file.stat().st_size == 0:
            self.log("No alive hosts to analyze", "WARNING")
            return
        
        try:
            webanalyze_cmd = [
                self.tools['webanalyze'],
                '-hosts', str(alive_file),
                '-crawl', '1',
                '-output', 'json'
            ]
            
            stdout, stderr, code = self.run_command(webanalyze_cmd, "Detecting technologies with webanalyze...")
            
            if stdout:
                with open(tech_file, 'w') as f:
                    f.write(stdout)
                
                # Parse results
                try:
                    data = json.loads(stdout)
                    for entry in data:
                        url = entry.get('host', 'unknown')
                        techs = [t.get('name', '') for t in entry.get('technologies', [])]
                        if techs:
                            self.technologies[url] = techs
                except json.JSONDecodeError:
                    pass
            
        except FileNotFoundError:
            self.log("webanalyze not found. Skipping tech detection.", "WARNING")
        
        self.log(f"Detected technologies on {len(self.technologies)} hosts", "SUCCESS")
        return self.technologies
    
    # ================================================================
    # PHASE 6: Nuclei Vulnerability Scanning
    # ================================================================
    
    def run_nuclei_scan(self, severity: str = "critical,high,medium"):
        """Run nuclei vulnerability scanner"""
        self.log(f"Running nuclei scan (severity: {severity})...", "INFO")
        
        alive_file = self.base_dir / "alive_hosts" / "alive_hosts.txt"
        nuclei_dir = self.base_dir / "nuclei_results"
        
        if not alive_file.exists() or alive_file.stat().st_size == 0:
            self.log("No alive hosts to scan", "WARNING")
            return
        
        try:
            nuclei_cmd = [
                self.tools['nuclei'],
                '-l', str(alive_file),
                '-severity', severity,
                '-silent',
                '-json',
                '-o', str(nuclei_dir / "nuclei_results.json"),
                '-stats',
                '-si', '10'
            ]
            
            stdout, stderr, code = self.run_command(nuclei_cmd, "Scanning with nuclei...")
            
            # Parse results
            results_file = nuclei_dir / "nuclei_results.json"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line.strip())
                            self.nuclei_results.append(result)
                        except:
                            pass
            
            # Create summary
            self.generate_nuclei_summary()
            
        except FileNotFoundError:
            self.log("nuclei not found. Install it first.", "ERROR")
        
        self.log(f"Found {len(self.nuclei_results)} vulnerabilities", "SUCCESS")
        return self.nuclei_results
    
    def generate_nuclei_summary(self):
        """Generate nuclei findings summary"""
        summary_file = self.base_dir / "nuclei_results" / "summary.txt"
        
        with open(summary_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("NUCLEI SCAN SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            
            severity_counts = {}
            for result in self.nuclei_results:
                severity = result.get('info', {}).get('severity', 'unknown').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            f.write("Severity Distribution:\n")
            for sev, count in sorted(severity_counts.items()):
                f.write(f"  {sev.upper()}: {count}\n")
            
            f.write("\nDetailed Findings:\n")
            f.write("-" * 50 + "\n")
            
            for result in self.nuclei_results[:50]:
                info = result.get('info', {})
                template = info.get('name', 'unknown')
                severity = info.get('severity', 'unknown')
                host = result.get('host', 'unknown')
                
                f.write(f"[{severity.upper()}] {template}\n")
                f.write(f"  Host: {host}\n\n")
    
    # ================================================================
    # PHASE 7: Report Generation (Simplified)
    # ================================================================
    
    def generate_report(self):
        """Generate comprehensive HTML report"""
        self.log("Generating final report...", "INFO")
        
        report_file = self.base_dir / "reports" / "recon_report.html"
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Count vulnerabilities by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in self.nuclei_results:
            severity = result.get('info', {}).get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Technology summary
        tech_summary = {}
        for techs in self.technologies.values():
            for tech in techs:
                tech_summary[tech] = tech_summary.get(tech, 0) + 1
        
        # Generate simple HTML report
        html_content = f'''<!DOCTYPE html>
<html>
<head><title>Recon Report - {self.target}</title>
<style>
body {{ font-family: monospace; background: #0a0a0f; color: #0f0; margin: 20px; }}
h1 {{ color: #0f0; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #0f0; padding: 8px; text-align: left; }}
th {{ background: #1a1a2e; }}
.stat {{ display: inline-block; margin: 10px; padding: 10px; border: 1px solid #0f0; }}
</style>
</head>
<body>
<h1>🔍 Reconnaissance Report: {self.target}</h1>
<p>Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Duration: {elapsed:.2f} seconds</p>

<h2>Statistics</h2>
<div class="stat">Subdomains: {len(self.subdomains)}</div>
<div class="stat">Alive Hosts: {len(self.alive_hosts)}</div>
<div class="stat">Screenshots: {len(self.screenshots)}</div>
<div class="stat">Vulnerabilities: {len(self.nuclei_results)}</div>

<h2>Vulnerability Summary</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
<tr><td style="color:#ff0055">Critical</td><td>{severity_counts.get('critical', 0)}</td></tr>
<tr><td style="color:#ff5500">High</td><td>{severity_counts.get('high', 0)}</td></tr>
<tr><td style="color:#ffaa00">Medium</td><td>{severity_counts.get('medium', 0)}</td></tr>
<tr><td style="color:#0f0">Low</td><td>{severity_counts.get('low', 0)}</td></tr>
</table>

<h2>Top Subdomains</h2>
<table>
<tr><th>#</th><th>Subdomain</th></tr>
'''
        
        for i, sub in enumerate(sorted(self.subdomains)[:50], 1):
            html_content += f'<tr><td>{i}</td><td>{sub}</td></tr>\n'
        
        html_content += '''
</table>
<p>Generated by Recon Automation Framework</p>
</body>
</html>
'''
        
        with open(report_file, 'w') as f:
            f.write(html_content)
        
        self.log(f"Report generated: {report_file}", "SUCCESS")
        return report_file
    
    # ================================================================
    # MAIN EXECUTION
    # ================================================================
    
    def run(self, options: dict):
        """Run complete reconnaissance workflow"""
        self.log(f"Starting reconnaissance on {self.target}", "INFO")
        print("=" * 60)
        
        # Phase 1: Subdomain Enumeration
        if options.get('subdomains', True):
            self.enumerate_subdomains()
        
        # Phase 2: Alive Host Discovery
        if options.get('alive', True) and self.subdomains:
            self.discover_alive_hosts()
        
        # Phase 3: Port Scanning (optional)
        if options.get('ports'):
            self.port_scan(options.get('ports', 'top-100'))
        
        # Phase 4: Screenshots
        if options.get('screenshots', True) and self.alive_hosts:
            self.take_screenshots()
        
        # Phase 5: Technology Detection
        if options.get('tech_detect', True) and self.alive_hosts:
            self.detect_technologies()
        
        # Phase 6: Nuclei Scanning
        if options.get('nuclei', True) and self.alive_hosts:
            self.run_nuclei_scan(options.get('severity', 'critical,high,medium'))
        
        # Phase 7: Report Generation
        if options.get('report', True):
            self.generate_report()
        
        # Final summary
        print("\n" + "=" * 60)
        self.log("RECONNAISSANCE COMPLETE", "SUCCESS")
        print(f"{'=' * 60}")
        print(f"  📁 Output: {self.base_dir}")
        print(f"  🌐 Subdomains: {len(self.subdomains)}")
        print(f"  ✅ Alive Hosts: {len(self.alive_hosts)}")
        print(f"  📸 Screenshots: {len(self.screenshots)}")
        print(f"  🛡️ Vulnerabilities: {len(self.nuclei_results)}")
        print(f"  📄 Report: {self.base_dir / 'reports' / 'recon_report.html'}")
        print(f"{'=' * 60}")
        
        return True


def install_missing_tools():
    """Install missing tools automatically"""
    print("\033[93m[!] Installing missing tools...\033[0m")
    
    # Install assetfinder
    subprocess.run(['go', 'install', '-v', 'github.com/tomnomnom/assetfinder@latest'], capture_output=True)
    
    print("\033[92m[+] Tools installed! Please restart the script.\033[0m")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Reconnaissance Automation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_framework.py example.com
  python recon_framework.py example.com -o ./recon_output
  python recon_framework.py example.com --quick
        """
    )
    
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip port scans)')
    parser.add_argument('--no-nuclei', action='store_true', help='Skip nuclei scanning')
    parser.add_argument('--severity', default='critical,high,medium', help='Nuclei severity')
    
    args = parser.parse_args()
    
    # Create framework instance
    framework = ReconFramework(args.target, args.output)
    
    # Check dependencies
    if not framework.check_dependencies():
        print("\033[93m[!] Install missing tools and re-run.\033[0m")
        install = input("Install missing tools automatically? (y/n): ").strip().lower()
        if install == 'y':
            install_missing_tools()
        return
    
    # Setup options
    options = {
        'subdomains': True,
        'alive': True,
        'screenshots': not args.quick,
        'tech_detect': not args.quick,
        'nuclei': not args.no_nuclei,
        'report': True,
        'ports': None if args.quick else 'top-100',
        'severity': args.severity
    }
    
    if args.quick:
        framework.log("Quick scan mode enabled", "WARNING")
    
    # Run framework
    framework.run(options)


if __name__ == "__main__":
    main()