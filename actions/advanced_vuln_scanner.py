# advanced_vuln_scanner.py
# Advanced vulnerability scanner with real-time CVE database integration
# Provides intelligent vulnerability correlation, EPSS scoring, and automated exploit detection

import os
import json
import requests
import subprocess
import threading
import csv
import time
import logging
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin
import xml.etree.ElementTree as ET
from logger import Logger

logger = Logger(name="advanced_vuln_scanner.py", level=logging.DEBUG)

b_class = "AdvancedVulnScanner"
b_module = "advanced_vuln_scanner"
b_status = "advanced_vuln_scanner"
b_port = None
b_parent = None
b_priority = 2

@dataclass
class Vulnerability:
    """Data class to hold vulnerability information"""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    service: str = ""
    port: int = 0
    exploit_available: bool = False
    epss_score: float = 0.0
    references: List[str] = field(default_factory=list)
    solution: str = ""
    published_date: str = ""
    modified_date: str = ""

@dataclass
class ServiceInfo:
    """Data class to hold service information"""
    name: str
    version: str
    port: int
    protocol: str = "tcp"
    banner: str = ""
    cpe: str = ""  # Common Platform Enumeration

@dataclass
class HostVulnerabilities:
    """Data class to hold host vulnerability assessment results"""
    ip: str
    hostname: str = ""
    mac: str = ""
    services: List[ServiceInfo] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_score: float = 0.0
    scan_timestamp: datetime = field(default_factory=datetime.now)

class AdvancedVulnScanner:
    """
    Advanced vulnerability scanner with real-time CVE database integration,
    intelligent vulnerability correlation, and exploit prediction scoring
    """
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.lock = threading.Lock()
        self.running = False
        
        # CVE Database configuration
        self.nvd_api_key = getattr(shared_data, 'nvd_api_key', None)
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_api_url = "https://api.first.org/data/v1/epss"
        
        # Exploit database configuration
        self.exploit_db_enabled = getattr(shared_data, 'exploit_db_enabled', True)
        self.metasploit_enabled = getattr(shared_data, 'metasploit_enabled', False)
        
        # Scanner configuration
        self.max_workers = getattr(shared_data, 'vuln_scanner_threads', 20)
        self.scan_timeout = getattr(shared_data, 'vuln_scan_timeout', 300)
        self.cache_duration = getattr(shared_data, 'cve_cache_duration', 24)  # hours
        
        # Output configuration
        self.vuln_results_dir = shared_data.vulnerabilities_dir
        self.timestamp = self.get_current_timestamp()
        
        # Cache for CVE data
        self.cve_cache = {}
        self.cache_file = os.path.join(self.vuln_results_dir, 'cve_cache.json')
        self.load_cve_cache()
        
        # NSE script categories for comprehensive scanning
        self.nse_categories = [
            'vuln', 'exploit', 'malware', 'backdoor', 'dos',
            'fuzzer', 'intrusive', 'brute', 'auth'
        ]
        
        # Common service version patterns
        self.version_patterns = {
            'apache': r'Apache/(\d+\.\d+\.\d+)',
            'nginx': r'nginx/(\d+\.\d+\.\d+)',
            'openssh': r'OpenSSH_(\d+\.\d+)',
            'mysql': r'MySQL (\d+\.\d+\.\d+)',
            'postgresql': r'PostgreSQL (\d+\.\d+)',
            'vsftpd': r'vsftpd (\d+\.\d+\.\d+)',
            'proftpd': r'ProFTPD (\d+\.\d+\.\d+)',
            'iis': r'Microsoft-IIS/(\d+\.\d+)',
            'tomcat': r'Apache Tomcat/(\d+\.\d+\.\d+)'
        }

    def get_current_timestamp(self) -> str:
        """Returns current timestamp in format YYYYMMDD_HHMMSS"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def load_cve_cache(self):
        """Load CVE cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    # Check if cache is still valid
                    cache_time = datetime.fromisoformat(cache_data.get('timestamp', '1970-01-01'))
                    if datetime.now() - cache_time < timedelta(hours=self.cache_duration):
                        self.cve_cache = cache_data.get('data', {})
                        self.logger.info(f"Loaded {len(self.cve_cache)} CVEs from cache")
        except Exception as e:
            self.logger.warning(f"Could not load CVE cache: {e}")

    def save_cve_cache(self):
        """Save CVE cache to file"""
        try:
            os.makedirs(self.vuln_results_dir, exist_ok=True)
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'data': self.cve_cache
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            self.logger.info(f"Saved {len(self.cve_cache)} CVEs to cache")
        except Exception as e:
            self.logger.error(f"Could not save CVE cache: {e}")

    def get_hosts_from_netkb(self) -> List[Dict]:
        """Get alive hosts from network knowledge base"""
        hosts = []
        try:
            netkbfile = self.shared_data.netkbfile
            if os.path.exists(netkbfile):
                with open(netkbfile, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get("Alive") == "1" and row.get("MAC Address") != "STANDALONE":
                            hosts.append(row)
            self.logger.info(f"Found {len(hosts)} alive hosts for vulnerability scanning")
        except Exception as e:
            self.logger.error(f"Error reading network knowledge base: {e}")
        return hosts

    def run_nmap_vuln_scan(self, ip: str, ports: List[int]) -> Dict:
        """Run comprehensive Nmap vulnerability scan"""
        try:
            # Build port list
            port_list = ','.join(map(str, ports)) if ports else '1-65535'
            
            # Build Nmap command with vulnerability scripts
            nmap_cmd = [
                'nmap', '-sV', '-sC',
                '--script', 'vuln,exploit,malware,backdoor',
                '--script-args', 'unsafe=1',
                '-p', port_list,
                '--open',
                '-oX', '-',  # XML output to stdout
                ip
            ]
            
            self.logger.info(f"Running Nmap vulnerability scan on {ip}:{port_list}")
            
            # Execute Nmap with timeout
            result = subprocess.run(nmap_cmd, capture_output=True, text=True, 
                                  timeout=self.scan_timeout)
            
            if result.returncode != 0:
                self.logger.warning(f"Nmap scan failed for {ip}: {result.stderr}")
                return {}
            
            # Parse XML output
            return self.parse_nmap_xml(result.stdout, ip)
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timed out for {ip}")
            return {}
        except Exception as e:
            self.logger.error(f"Error running Nmap scan for {ip}: {e}")
            return {}

    def parse_nmap_xml(self, xml_output: str, ip: str) -> Dict:
        """Parse Nmap XML output to extract service and vulnerability information"""
        try:
            root = ET.fromstring(xml_output)
            host_info = {
                'ip': ip,
                'hostname': '',
                'services': [],
                'vulnerabilities': []
            }
            
            # Find host element
            host = root.find('.//host')
            if host is None:
                return host_info
            
            # Extract hostname
            hostname_elem = host.find('.//hostname')
            if hostname_elem is not None:
                host_info['hostname'] = hostname_elem.get('name', '')
            
            # Extract service information
            for port in host.findall('.//port'):
                port_id = int(port.get('portid', 0))
                protocol = port.get('protocol', 'tcp')
                
                service = port.find('service')
                if service is not None:
                    service_info = ServiceInfo(
                        name=service.get('name', 'unknown'),
                        version=service.get('version', ''),
                        port=port_id,
                        protocol=protocol,
                        banner=service.get('product', '') + ' ' + service.get('version', ''),
                        cpe=service.get('cpe', '')
                    )
                    host_info['services'].append(service_info)
                
                # Extract vulnerability information from scripts
                for script in port.findall('.//script'):
                    script_id = script.get('id', '')
                    script_output = script.get('output', '')
                    
                    if 'vuln' in script_id or 'cve' in script_output.lower():
                        vulns = self.parse_nmap_vuln_script(script_id, script_output, port_id)
                        host_info['vulnerabilities'].extend(vulns)
            
            return host_info
            
        except ET.ParseError as e:
            self.logger.error(f"Error parsing Nmap XML: {e}")
            return {'ip': ip, 'hostname': '', 'services': [], 'vulnerabilities': []}

    def parse_nmap_vuln_script(self, script_id: str, output: str, port: int) -> List[Vulnerability]:
        """Parse Nmap vulnerability script output"""
        vulnerabilities = []
        
        try:
            # Extract CVE IDs from script output
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cve_matches = re.findall(cve_pattern, output)
            
            for cve_id in cve_matches:
                # Check if we already have this CVE
                existing_vuln = next((v for v in vulnerabilities if v.cve_id == cve_id), None)
                if existing_vuln:
                    continue
                
                # Create vulnerability object
                vuln = Vulnerability(
                    cve_id=cve_id,
                    cvss_score=0.0,
                    severity='Unknown',
                    description=f"Detected by Nmap script: {script_id}",
                    port=port,
                    service=script_id
                )
                
                # Try to extract CVSS score from output
                cvss_pattern = r'CVSS:\s*(\d+\.\d+)'
                cvss_match = re.search(cvss_pattern, output)
                if cvss_match:
                    vuln.cvss_score = float(cvss_match.group(1))
                    vuln.severity = self.get_severity_from_cvss(vuln.cvss_score)
                
                vulnerabilities.append(vuln)
            
            # Handle non-CVE vulnerabilities
            if not cve_matches and ('vulnerable' in output.lower() or 'exploit' in output.lower()):
                vuln = Vulnerability(
                    cve_id=f"NMAP-{script_id}-{port}",
                    cvss_score=5.0,  # Default medium severity
                    severity='Medium',
                    description=output[:200] + "..." if len(output) > 200 else output,
                    port=port,
                    service=script_id
                )
                vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.error(f"Error parsing vulnerability script output: {e}")
        
        return vulnerabilities

    def get_severity_from_cvss(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        elif cvss_score > 0.0:
            return 'Low'
        else:
            return 'Informational'

    def enrich_vulnerabilities_with_nvd(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Enrich vulnerabilities with NVD database information"""
        enriched_vulns = []
        
        for vuln in vulnerabilities:
            if not vuln.cve_id.startswith('CVE-'):
                enriched_vulns.append(vuln)
                continue
            
            # Check cache first
            if vuln.cve_id in self.cve_cache:
                cached_data = self.cve_cache[vuln.cve_id]
                vuln.cvss_score = cached_data.get('cvss_score', vuln.cvss_score)
                vuln.severity = cached_data.get('severity', vuln.severity)
                vuln.description = cached_data.get('description', vuln.description)
                vuln.references = cached_data.get('references', [])
                vuln.solution = cached_data.get('solution', '')
                vuln.published_date = cached_data.get('published_date', '')
                vuln.modified_date = cached_data.get('modified_date', '')
                enriched_vulns.append(vuln)
                continue
            
            # Fetch from NVD API
            try:
                headers = {}
                if self.nvd_api_key:
                    headers['apiKey'] = self.nvd_api_key
                
                params = {
                    'cveId': vuln.cve_id
                }
                
                response = requests.get(self.nvd_base_url, params=params, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('vulnerabilities'):
                        cve_data = data['vulnerabilities'][0]['cve']
                        
                        # Extract CVSS score
                        metrics = cve_data.get('metrics', {})
                        if 'cvssMetricV31' in metrics:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            vuln.cvss_score = cvss_data.get('baseScore', vuln.cvss_score)
                        elif 'cvssMetricV30' in metrics:
                            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                            vuln.cvss_score = cvss_data.get('baseScore', vuln.cvss_score)
                        elif 'cvssMetricV2' in metrics:
                            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                            vuln.cvss_score = cvss_data.get('baseScore', vuln.cvss_score)
                        
                        vuln.severity = self.get_severity_from_cvss(vuln.cvss_score)
                        
                        # Extract description
                        descriptions = cve_data.get('descriptions', [])
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                vuln.description = desc.get('value', vuln.description)
                                break
                        
                        # Extract references
                        references = cve_data.get('references', [])
                        vuln.references = [ref.get('url', '') for ref in references[:5]]  # Limit to 5 refs
                        
                        # Extract dates
                        vuln.published_date = cve_data.get('published', '')
                        vuln.modified_date = cve_data.get('lastModified', '')
                        
                        # Cache the data
                        self.cve_cache[vuln.cve_id] = {
                            'cvss_score': vuln.cvss_score,
                            'severity': vuln.severity,
                            'description': vuln.description,
                            'references': vuln.references,
                            'solution': vuln.solution,
                            'published_date': vuln.published_date,
                            'modified_date': vuln.modified_date
                        }
                
                # Add small delay to respect API rate limits
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.warning(f"Could not enrich CVE {vuln.cve_id}: {e}")
            
            enriched_vulns.append(vuln)
        
        return enriched_vulns

    def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        """Get EPSS (Exploit Prediction Scoring System) scores for CVEs"""
        epss_scores = {}
        
        try:
            # EPSS API supports batch queries
            cve_list = ','.join(cve_ids[:100])  # Limit to 100 CVEs per request
            
            params = {
                'cve': cve_list
            }
            
            response = requests.get(self.epss_api_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    cve_id = item.get('cve', '')
                    epss_score = float(item.get('epss', 0.0))
                    epss_scores[cve_id] = epss_score
            
        except Exception as e:
            self.logger.warning(f"Could not fetch EPSS scores: {e}")
        
        return epss_scores

    def check_exploit_availability(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Check for available exploits for vulnerabilities"""
        for vuln in vulnerabilities:
            if not vuln.cve_id.startswith('CVE-'):
                continue
            
            try:
                # Check Exploit-DB
                if self.exploit_db_enabled:
                    vuln.exploit_available = self.check_exploit_db(vuln.cve_id)
                
                # Check Metasploit modules if enabled
                if self.metasploit_enabled and not vuln.exploit_available:
                    vuln.exploit_available = self.check_metasploit_modules(vuln.cve_id)
                
            except Exception as e:
                self.logger.debug(f"Error checking exploits for {vuln.cve_id}: {e}")
        
        return vulnerabilities

    def check_exploit_db(self, cve_id: str) -> bool:
        """Check if exploit exists in Exploit-DB"""
        try:
            # Use searchsploit if available
            result = subprocess.run(['searchsploit', '--cve', cve_id], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                # If searchsploit returns results, exploit likely exists
                return len(result.stdout.strip().split('\n')) > 2  # More than header lines
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return False

    def check_metasploit_modules(self, cve_id: str) -> bool:
        """Check if Metasploit module exists for CVE"""
        try:
            # Search Metasploit database
            result = subprocess.run(['msfconsole', '-q', '-x', f'search cve:{cve_id}; exit'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and 'exploit/' in result.stdout:
                return True
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return False

    def calculate_risk_score(self, host_vulns: HostVulnerabilities) -> float:
        """Calculate overall risk score for a host"""
        if not host_vulns.vulnerabilities:
            return 0.0
        
        total_score = 0.0
        exploit_multiplier = 1.0
        
        for vuln in host_vulns.vulnerabilities:
            # Base score from CVSS
            base_score = vuln.cvss_score
            
            # Apply EPSS multiplier (exploit probability)
            epss_multiplier = 1.0 + (vuln.epss_score * 2)  # Up to 3x multiplier
            
            # Apply exploit availability multiplier
            if vuln.exploit_available:
                exploit_multiplier = 1.5
            
            # Calculate weighted score
            weighted_score = base_score * epss_multiplier * exploit_multiplier
            total_score += weighted_score
        
        # Normalize to 0-10 scale
        risk_score = min(total_score / len(host_vulns.vulnerabilities), 10.0)
        
        return round(risk_score, 2)

    def scan_host(self, host_data: Dict) -> HostVulnerabilities:
        """Perform comprehensive vulnerability scan on a single host"""
        ip = host_data.get('IPs', '')
        hostname = host_data.get('Hostnames', '')
        mac = host_data.get('MAC Address', '')
        ports_str = host_data.get('Ports', '')
        
        self.logger.info(f"Scanning host {ip} for vulnerabilities")
        
        # Parse ports
        ports = []
        if ports_str:
            try:
                ports = [int(p) for p in ports_str.split(';') if p.isdigit()]
            except:
                pass
        
        # Initialize host vulnerability object
        host_vulns = HostVulnerabilities(
            ip=ip,
            hostname=hostname,
            mac=mac
        )
        
        # Run Nmap vulnerability scan
        nmap_results = self.run_nmap_vuln_scan(ip, ports)
        
        if nmap_results:
            # Convert service info
            for service_data in nmap_results.get('services', []):
                host_vulns.services.append(service_data)
            
            # Process vulnerabilities
            vulnerabilities = nmap_results.get('vulnerabilities', [])
            
            if vulnerabilities:
                # Enrich with NVD data
                vulnerabilities = self.enrich_vulnerabilities_with_nvd(vulnerabilities)
                
                # Get EPSS scores
                cve_ids = [v.cve_id for v in vulnerabilities if v.cve_id.startswith('CVE-')]
                if cve_ids:
                    epss_scores = self.get_epss_scores(cve_ids)
                    for vuln in vulnerabilities:
                        vuln.epss_score = epss_scores.get(vuln.cve_id, 0.0)
                
                # Check exploit availability
                vulnerabilities = self.check_exploit_availability(vulnerabilities)
                
                host_vulns.vulnerabilities = vulnerabilities
        
        # Calculate risk score
        host_vulns.risk_score = self.calculate_risk_score(host_vulns)
        
        self.logger.info(f"Found {len(host_vulns.vulnerabilities)} vulnerabilities on {ip} (Risk Score: {host_vulns.risk_score})")
        
        return host_vulns

    def save_results(self, all_host_vulns: List[HostVulnerabilities]):
        """Save vulnerability scan results to files"""
        try:
            os.makedirs(self.vuln_results_dir, exist_ok=True)
            
            # Save detailed JSON results
            json_file = os.path.join(self.vuln_results_dir, f'vuln_scan_{self.timestamp}.json')
            json_data = {
                'scan_timestamp': self.timestamp,
                'total_hosts_scanned': len(all_host_vulns),
                'total_vulnerabilities': sum(len(h.vulnerabilities) for h in all_host_vulns),
                'hosts': []
            }
            
            for host_vulns in all_host_vulns:
                host_data = {
                    'ip': host_vulns.ip,
                    'hostname': host_vulns.hostname,
                    'mac': host_vulns.mac,
                    'risk_score': host_vulns.risk_score,
                    'services': [
                        {
                            'name': s.name,
                            'version': s.version,
                            'port': s.port,
                            'protocol': s.protocol,
                            'banner': s.banner,
                            'cpe': s.cpe
                        } for s in host_vulns.services
                    ],
                    'vulnerabilities': [
                        {
                            'cve_id': v.cve_id,
                            'cvss_score': v.cvss_score,
                            'severity': v.severity,
                            'description': v.description,
                            'service': v.service,
                            'port': v.port,
                            'exploit_available': v.exploit_available,
                            'epss_score': v.epss_score,
                            'references': v.references,
                            'solution': v.solution,
                            'published_date': v.published_date,
                            'modified_date': v.modified_date
                        } for v in host_vulns.vulnerabilities
                    ]
                }
                json_data['hosts'].append(host_data)
            
            with open(json_file, 'w') as f:
                json.dump(json_data, f, indent=2, default=str)
            
            # Save CSV summary
            csv_file = os.path.join(self.vuln_results_dir, f'vuln_summary_{self.timestamp}.csv')
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Hostname', 'MAC', 'Risk Score', 'Critical', 'High', 'Medium', 'Low', 'Total Vulns'])
                
                for host_vulns in all_host_vulns:
                    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
                    for vuln in host_vulns.vulnerabilities:
                        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
                    
                    writer.writerow([
                        host_vulns.ip,
                        host_vulns.hostname,
                        host_vulns.mac,
                        host_vulns.risk_score,
                        severity_counts['Critical'],
                        severity_counts['High'],
                        severity_counts['Medium'],
                        severity_counts['Low'],
                        len(host_vulns.vulnerabilities)
                    ])
            
            self.logger.info(f"Vulnerability scan results saved to {json_file} and {csv_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving vulnerability results: {e}")

    def update_netkb_with_vulns(self, all_host_vulns: List[HostVulnerabilities]):
        """Update network knowledge base with vulnerability information"""
        try:
            netkbfile = self.shared_data.netkbfile
            if not os.path.exists(netkbfile):
                return
            
            # Read existing data
            existing_data = {}
            with open(netkbfile, 'r') as f:
                reader = csv.DictReader(f)
                headers = list(reader.fieldnames)
                for row in reader:
                    mac = row["MAC Address"]
                    existing_data[mac] = row
            
            # Add vulnerability columns if they don't exist
            vuln_columns = ['Risk_Score', 'Critical_Vulns', 'High_Vulns', 'Medium_Vulns', 'Low_Vulns', 'Total_Vulns', 'Last_Vuln_Scan']
            for col in vuln_columns:
                if col not in headers:
                    headers.append(col)
            
            # Update with vulnerability data
            for host_vulns in all_host_vulns:
                if host_vulns.mac in existing_data:
                    row = existing_data[host_vulns.mac]
                    
                    # Count vulnerabilities by severity
                    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
                    for vuln in host_vulns.vulnerabilities:
                        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
                    
                    # Update vulnerability information
                    row['Risk_Score'] = str(host_vulns.risk_score)
                    row['Critical_Vulns'] = str(severity_counts['Critical'])
                    row['High_Vulns'] = str(severity_counts['High'])
                    row['Medium_Vulns'] = str(severity_counts['Medium'])
                    row['Low_Vulns'] = str(severity_counts['Low'])
                    row['Total_Vulns'] = str(len(host_vulns.vulnerabilities))
                    row['Last_Vuln_Scan'] = self.timestamp
            
            # Write updated data back
            with open(netkbfile, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for row in existing_data.values():
                    writer.writerow(row)
            
            self.logger.info("Updated network knowledge base with vulnerability information")
            
        except Exception as e:
            self.logger.error(f"Error updating netkb with vulnerabilities: {e}")

    def scan(self):
        """Main vulnerability scanning method"""
        try:
            self.shared_data.bjornorch_status = "AdvancedVulnScanner"
            self.logger.info("Starting advanced vulnerability scan")
            
            # Get hosts to scan
            hosts = self.get_hosts_from_netkb()
            if not hosts:
                self.logger.warning("No alive hosts found for vulnerability scanning")
                return
            
            self.shared_data.bjornstatustext2 = f"Scanning {len(hosts)} hosts"
            
            # Scan hosts concurrently
            all_host_vulns = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit scan tasks
                future_to_host = {
                    executor.submit(self.scan_host, host): host 
                    for host in hosts
                }
                
                # Collect results
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        host_vulns = future.result(timeout=self.scan_timeout)
                        all_host_vulns.append(host_vulns)
                        self.shared_data.bjornstatustext2 = f"Scanned {host_vulns.ip}"
                    except Exception as e:
                        self.logger.error(f"Error scanning host {host.get('IPs', 'unknown')}: {e}")
            
            # Save results
            if all_host_vulns:
                self.save_results(all_host_vulns)
                self.update_netkb_with_vulns(all_host_vulns)
                
                # Save CVE cache
                self.save_cve_cache()
                
                # Log summary
                total_vulns = sum(len(h.vulnerabilities) for h in all_host_vulns)
                high_risk_hosts = len([h for h in all_host_vulns if h.risk_score >= 7.0])
                
                self.logger.info(f"Vulnerability scan completed: {len(all_host_vulns)} hosts, "
                               f"{total_vulns} vulnerabilities, {high_risk_hosts} high-risk hosts")
            else:
                self.logger.warning("No vulnerability scan results to save")
                
        except Exception as e:
            self.logger.error(f"Error in vulnerability scan: {e}")
        finally:
            self.shared_data.bjornstatustext2 = ""

    def execute(self, ip: str, row: Dict, status_key: str) -> str:
        """Execute method for orchestrator compatibility"""
        try:
            # Scan single host for orchestrator integration
            host_data = {
                'IPs': ip,
                'Hostnames': row.get('Hostnames', ''),
                'MAC Address': row.get('MAC Address', ''),
                'Ports': row.get('Ports', '')
            }
            
            host_vulns = self.scan_host(host_data)
            
            if host_vulns.vulnerabilities:
                # Save individual host results
                self.save_results([host_vulns])
                self.update_netkb_with_vulns([host_vulns])
                return 'success'
            else:
                return 'failed'
                
        except Exception as e:
            self.logger.error(f"Error in vulnerability scan execution: {e}")
            return 'failed'

    def start(self):
        """Start the scanner in a separate thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.scan)
            self.thread.start()
            self.logger.info("AdvancedVulnScanner started")

    def stop(self):
        """Stop the scanner"""
        if self.running:
            self.running = False
            if hasattr(self, 'thread') and self.thread.is_alive():
                self.thread.join()
            self.logger.info("AdvancedVulnScanner stopped")

if __name__ == "__main__":
    from init_shared import shared_data
    scanner = AdvancedVulnScanner(shared_data)
    scanner.scan()
