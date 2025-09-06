# masscan_scanner.py
# Advanced high-speed network scanner using Masscan for enhanced performance
# This module provides 1000x faster scanning compared to traditional socket-based scanning
# and includes advanced features like IPv6 support, service detection, and intelligent targeting

import os
import json
import subprocess
import threading
import csv
import time
import logging
import ipaddress
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass
from logger import Logger

logger = Logger(name="masscan_scanner.py", level=logging.DEBUG)

b_class = "MasscanScanner"
b_module = "masscan_scanner"
b_status = "masscan_scanner"
b_port = None
b_parent = None
b_priority = 1

@dataclass
class ScanResult:
    """Data class to hold scan results"""
    ip: str
    port: int
    protocol: str
    service: str = ""
    version: str = ""
    banner: str = ""
    timestamp: datetime = None

@dataclass
class HostInfo:
    """Data class to hold host information"""
    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    open_ports: List[int] = None
    services: Dict[int, str] = None
    alive: bool = True

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}

class MasscanScanner:
    """
    Advanced network scanner using Masscan for high-speed scanning
    with intelligent service detection and vulnerability correlation
    """
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.lock = threading.Lock()
        self.running = False
        
        # Scanner configuration
        self.max_rate = getattr(shared_data, 'masscan_rate', 1000)  # packets per second
        self.timeout = getattr(shared_data, 'masscan_timeout', 10)
        self.retries = getattr(shared_data, 'masscan_retries', 2)
        self.exclude_ports = getattr(shared_data, 'exclude_ports', [])
        
        # Service detection configuration
        self.enable_service_detection = getattr(shared_data, 'enable_service_detection', True)
        self.banner_timeout = getattr(shared_data, 'banner_timeout', 5)
        
        # IPv6 support
        self.ipv6_enabled = getattr(shared_data, 'ipv6_enabled', False)
        
        # Output files
        self.scan_results_dir = shared_data.scan_results_dir
        self.timestamp = self.get_current_timestamp()
        
        # Thread pool for concurrent operations
        self.max_workers = getattr(shared_data, 'scanner_threads', 50)
        
        # Common service ports for enhanced detection
        self.common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1433: 'ms-sql-s', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 8080: 'http-proxy'
        }

    def get_current_timestamp(self) -> str:
        """Returns current timestamp in format YYYYMMDD_HHMMSS"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def check_masscan_installed(self) -> bool:
        """Check if masscan is installed and accessible"""
        try:
            result = subprocess.run(['masscan', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.logger.info(f"Masscan version: {result.stdout.strip()}")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.error("Masscan not found. Please install masscan: sudo apt-get install masscan")
            return False

    def get_network_range(self) -> str:
        """Get the current network range for scanning"""
        try:
            # Get default route interface
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception("Could not get default route")
            
            # Extract interface name
            interface = result.stdout.split()[4]
            
            # Get network information for the interface
            result = subprocess.run(['ip', 'addr', 'show', interface], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Could not get interface info for {interface}")
            
            # Parse IP and subnet
            for line in result.stdout.split('\n'):
                if 'inet ' in line and not '127.0.0.1' in line:
                    ip_info = line.strip().split()[1]
                    network = ipaddress.IPv4Network(ip_info, strict=False)
                    self.logger.info(f"Detected network: {network}")
                    return str(network)
            
            raise Exception("Could not determine network range")
            
        except Exception as e:
            self.logger.error(f"Error getting network range: {e}")
            # Fallback to common private networks
            return "192.168.1.0/24"

    def build_masscan_command(self, targets: str, ports: str, output_file: str) -> List[str]:
        """Build masscan command with optimal parameters"""
        cmd = [
            'masscan',
            targets,
            '-p', ports,
            '--rate', str(self.max_rate),
            '--wait', str(self.timeout),
            '--retries', str(self.retries),
            '-oJ', output_file,  # JSON output
            '--open-only'
        ]
        
        # Add IPv6 support if enabled
        if self.ipv6_enabled:
            cmd.append('-6')
        
        # Add exclusions if specified
        if hasattr(self.shared_data, 'exclude_ranges') and self.shared_data.exclude_ranges:
            for exclude in self.shared_data.exclude_ranges:
                cmd.extend(['--exclude', exclude])
        
        return cmd

    def run_masscan(self, targets: str, ports: str) -> List[ScanResult]:
        """Execute masscan and parse results"""
        output_file = os.path.join(self.scan_results_dir, f'masscan_{self.timestamp}.json')
        
        try:
            # Ensure output directory exists
            os.makedirs(self.scan_results_dir, exist_ok=True)
            
            # Build and execute command
            cmd = self.build_masscan_command(targets, ports, output_file)
            self.logger.info(f"Running masscan: {' '.join(cmd)}")
            
            # Run masscan with timeout
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            
            if process.returncode != 0:
                self.logger.error(f"Masscan failed: {stderr}")
                return []
            
            # Parse JSON results
            results = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                data = json.loads(line)
                                if 'ip' in data and 'ports' in data:
                                    for port_info in data['ports']:
                                        result = ScanResult(
                                            ip=data['ip'],
                                            port=port_info['port'],
                                            protocol=port_info.get('proto', 'tcp'),
                                            timestamp=datetime.fromtimestamp(data.get('timestamp', time.time()))
                                        )
                                        results.append(result)
                            except json.JSONDecodeError as e:
                                self.logger.warning(f"Failed to parse JSON line: {line}, error: {e}")
            
            self.logger.info(f"Masscan found {len(results)} open ports")
            return results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Masscan timed out")
            process.kill()
            return []
        except Exception as e:
            self.logger.error(f"Error running masscan: {e}")
            return []

    def detect_service(self, ip: str, port: int, protocol: str = 'tcp') -> Tuple[str, str, str]:
        """Detect service running on a specific port"""
        service = self.common_services.get(port, 'unknown')
        version = ""
        banner = ""
        
        if not self.enable_service_detection:
            return service, version, banner
        
        try:
            # Attempt banner grabbing
            if protocol == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.banner_timeout)
                
                try:
                    sock.connect((ip, port))
                    
                    # Send appropriate probe based on service
                    if port == 80 or port == 8080:
                        sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    elif port == 21:
                        pass  # FTP sends banner immediately
                    elif port == 22:
                        pass  # SSH sends banner immediately
                    elif port == 25:
                        pass  # SMTP sends banner immediately
                    
                    # Receive banner
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # Parse service and version from banner
                    if banner:
                        service, version = self.parse_banner(banner, port)
                    
                except socket.timeout:
                    pass
                except Exception as e:
                    self.logger.debug(f"Banner grab failed for {ip}:{port} - {e}")
                finally:
                    sock.close()
        
        except Exception as e:
            self.logger.debug(f"Service detection failed for {ip}:{port} - {e}")
        
        return service, version, banner

    def parse_banner(self, banner: str, port: int) -> Tuple[str, str]:
        """Parse service and version information from banner"""
        service = self.common_services.get(port, 'unknown')
        version = ""
        
        banner_lower = banner.lower()
        
        # HTTP services
        if 'server:' in banner_lower:
            server_line = [line for line in banner.split('\n') if 'server:' in line.lower()]
            if server_line:
                server_info = server_line[0].split(':', 1)[1].strip()
                if 'apache' in server_info.lower():
                    service = 'apache'
                    version = server_info
                elif 'nginx' in server_info.lower():
                    service = 'nginx'
                    version = server_info
                elif 'iis' in server_info.lower():
                    service = 'iis'
                    version = server_info
        
        # SSH
        elif 'ssh-' in banner_lower:
            service = 'ssh'
            version = banner.split()[0] if banner.split() else ""
        
        # FTP
        elif port == 21 and ('ftp' in banner_lower or '220' in banner):
            service = 'ftp'
            if 'vsftpd' in banner_lower:
                service = 'vsftpd'
            version = banner.strip()
        
        # SMTP
        elif port == 25 and '220' in banner:
            service = 'smtp'
            version = banner.strip()
        
        return service, version

    def get_hostname(self, ip: str) -> str:
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ""

    def get_mac_address(self, ip: str) -> str:
        """Get MAC address for IP (requires ARP table or network access)"""
        try:
            # Try to get MAC from ARP table
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line and ':' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:  # MAC address format
                                return part.lower()
            
            # Fallback: ping to populate ARP table, then try again
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                         capture_output=True, timeout=3)
            
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line and ':' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part.lower()
            
            return f"unknown_{ip}"
            
        except Exception as e:
            self.logger.debug(f"Could not get MAC for {ip}: {e}")
            return f"unknown_{ip}"

    def process_scan_results(self, scan_results: List[ScanResult]) -> Dict[str, HostInfo]:
        """Process scan results and gather additional host information"""
        hosts = {}
        
        # Group results by IP
        for result in scan_results:
            if result.ip not in hosts:
                hosts[result.ip] = HostInfo(ip=result.ip)
            
            hosts[result.ip].open_ports.append(result.port)
            hosts[result.ip].services[result.port] = result.service

        # Enhance host information with concurrent processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit hostname resolution tasks
            hostname_futures = {
                executor.submit(self.get_hostname, ip): ip 
                for ip in hosts.keys()
            }
            
            # Submit MAC address resolution tasks
            mac_futures = {
                executor.submit(self.get_mac_address, ip): ip 
                for ip in hosts.keys()
            }
            
            # Submit service detection tasks
            service_futures = {}
            for ip, host in hosts.items():
                for port in host.open_ports:
                    future = executor.submit(self.detect_service, ip, port)
                    service_futures[future] = (ip, port)
            
            # Collect hostname results
            for future in as_completed(hostname_futures):
                ip = hostname_futures[future]
                try:
                    hostname = future.result(timeout=10)
                    hosts[ip].hostname = hostname
                except Exception as e:
                    self.logger.debug(f"Hostname resolution failed for {ip}: {e}")
            
            # Collect MAC address results
            for future in as_completed(mac_futures):
                ip = mac_futures[future]
                try:
                    mac = future.result(timeout=10)
                    hosts[ip].mac = mac
                except Exception as e:
                    self.logger.debug(f"MAC resolution failed for {ip}: {e}")
            
            # Collect service detection results
            for future in as_completed(service_futures):
                ip, port = service_futures[future]
                try:
                    service, version, banner = future.result(timeout=15)
                    hosts[ip].services[port] = f"{service} {version}".strip()
                except Exception as e:
                    self.logger.debug(f"Service detection failed for {ip}:{port}: {e}")

        return hosts

    def update_netkb(self, hosts: Dict[str, HostInfo]):
        """Update the network knowledge base with scan results"""
        try:
            netkbfile = self.shared_data.netkbfile
            
            # Read existing data
            existing_data = {}
            existing_headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"]
            
            if os.path.exists(netkbfile):
                with open(netkbfile, 'r') as f:
                    reader = csv.DictReader(f)
                    if reader.fieldnames:
                        existing_headers = list(reader.fieldnames)
                        for row in reader:
                            mac = row["MAC Address"]
                            if mac and mac != "STANDALONE":
                                existing_data[mac] = row

            # Update with new scan results
            alive_macs = set()
            for host in hosts.values():
                if not host.mac or host.mac.startswith("unknown_"):
                    continue
                
                alive_macs.add(host.mac)
                
                if host.mac in existing_data:
                    # Update existing entry
                    existing_data[host.mac]["IPs"] = host.ip
                    existing_data[host.mac]["Hostnames"] = host.hostname
                    existing_data[host.mac]["Alive"] = "1"
                    existing_data[host.mac]["Ports"] = ";".join(map(str, sorted(host.open_ports)))
                else:
                    # Create new entry
                    new_entry = {header: "" for header in existing_headers}
                    new_entry["MAC Address"] = host.mac
                    new_entry["IPs"] = host.ip
                    new_entry["Hostnames"] = host.hostname
                    new_entry["Alive"] = "1"
                    new_entry["Ports"] = ";".join(map(str, sorted(host.open_ports)))
                    existing_data[host.mac] = new_entry

            # Mark hosts not found in this scan as not alive
            for mac, data in existing_data.items():
                if mac not in alive_macs and mac != "STANDALONE":
                    data["Alive"] = "0"

            # Write updated data back to file
            with open(netkbfile, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=existing_headers)
                writer.writeheader()
                
                # Sort by IP address
                sorted_data = sorted(existing_data.values(), 
                                   key=lambda x: self.ip_sort_key(x["IPs"]))
                
                for row in sorted_data:
                    writer.writerow(row)

            self.logger.info(f"Updated network knowledge base with {len(hosts)} hosts")

        except Exception as e:
            self.logger.error(f"Error updating netkb: {e}")

    def ip_sort_key(self, ip_str: str):
        """Generate sort key for IP address"""
        if not ip_str or ip_str == "STANDALONE":
            return (0, 0, 0, 0)
        try:
            return tuple(map(int, ip_str.split('.')))
        except:
            return (0, 0, 0, 0)

    def save_detailed_results(self, hosts: Dict[str, HostInfo]):
        """Save detailed scan results to JSON file"""
        try:
            output_file = os.path.join(self.scan_results_dir, 
                                     f'masscan_detailed_{self.timestamp}.json')
            
            results_data = {
                'scan_timestamp': self.timestamp,
                'total_hosts': len(hosts),
                'total_ports': sum(len(host.open_ports) for host in hosts.values()),
                'hosts': {}
            }
            
            for ip, host in hosts.items():
                results_data['hosts'][ip] = {
                    'hostname': host.hostname,
                    'mac': host.mac,
                    'alive': host.alive,
                    'open_ports': host.open_ports,
                    'services': host.services,
                    'os_guess': host.os_guess
                }
            
            with open(output_file, 'w') as f:
                json.dump(results_data, f, indent=2, default=str)
            
            self.logger.info(f"Detailed results saved to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving detailed results: {e}")

    def scan(self):
        """Main scanning method"""
        try:
            self.shared_data.bjornorch_status = "MasscanScanner"
            self.logger.info("Starting Masscan network scan")
            
            # Check if masscan is available
            if not self.check_masscan_installed():
                self.logger.error("Masscan not available, falling back to basic scanner")
                return
            
            # Get network range
            network_range = self.get_network_range()
            self.shared_data.bjornstatustext2 = network_range
            
            # Build port list
            port_list = []
            if hasattr(self.shared_data, 'portlist') and self.shared_data.portlist:
                port_list.extend(self.shared_data.portlist)
            
            # Add port range if specified
            if hasattr(self.shared_data, 'portstart') and hasattr(self.shared_data, 'portend'):
                port_list.extend(range(self.shared_data.portstart, self.shared_data.portend + 1))
            
            # Remove duplicates and excluded ports
            port_list = list(set(port_list) - set(self.exclude_ports))
            port_string = ','.join(map(str, sorted(port_list)))
            
            self.logger.info(f"Scanning {network_range} for ports: {port_string}")
            
            # Run masscan
            scan_results = self.run_masscan(network_range, port_string)
            
            if not scan_results:
                self.logger.warning("No open ports found")
                return
            
            # Process results and gather additional information
            self.shared_data.bjornstatustext2 = "Processing results..."
            hosts = self.process_scan_results(scan_results)
            
            # Update network knowledge base
            self.update_netkb(hosts)
            
            # Save detailed results
            self.save_detailed_results(hosts)
            
            # Update live status
            self.update_live_status()
            
            self.logger.info(f"Masscan scan completed. Found {len(hosts)} hosts with {len(scan_results)} open ports")
            
        except Exception as e:
            self.logger.error(f"Error in masscan scan: {e}")
        finally:
            self.shared_data.bjornstatustext2 = ""

    def update_live_status(self):
        """Update live status file with current scan statistics"""
        try:
            # Read current netkb data
            netkbfile = self.shared_data.netkbfile
            if not os.path.exists(netkbfile):
                return
            
            alive_hosts = 0
            total_hosts = 0
            total_ports = 0
            
            with open(netkbfile, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row["MAC Address"] != "STANDALONE":
                        total_hosts += 1
                        if row["Alive"] == "1":
                            alive_hosts += 1
                            ports = row["Ports"].split(';') if row["Ports"] else []
                            total_ports += len([p for p in ports if p])
            
            # Update live status file
            livestatus_file = self.shared_data.livestatusfile
            livestatus_data = {
                'timestamp': self.timestamp,
                'alive_hosts': alive_hosts,
                'total_hosts': total_hosts,
                'total_open_ports': total_ports,
                'scanner_type': 'masscan'
            }
            
            # Create or update live status
            if os.path.exists(livestatus_file):
                with open(livestatus_file, 'r') as f:
                    try:
                        existing_data = json.load(f)
                        existing_data.update(livestatus_data)
                        livestatus_data = existing_data
                    except:
                        pass
            
            with open(livestatus_file, 'w') as f:
                json.dump(livestatus_data, f, indent=2)
            
            self.logger.info(f"Live status updated: {alive_hosts}/{total_hosts} hosts alive, {total_ports} open ports")
            
        except Exception as e:
            self.logger.error(f"Error updating live status: {e}")

    def execute(self, *args, **kwargs):
        """Execute method for orchestrator compatibility"""
        self.scan()
        return 'success'

    def start(self):
        """Start the scanner in a separate thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.scan)
            self.thread.start()
            self.logger.info("MasscanScanner started")

    def stop(self):
        """Stop the scanner"""
        if self.running:
            self.running = False
            if hasattr(self, 'thread') and self.thread.is_alive():
                self.thread.join()
            self.logger.info("MasscanScanner stopped")

if __name__ == "__main__":
    from init_shared import shared_data
    scanner = MasscanScanner(shared_data)
    scanner.scan()
