#!/usr/bin/env python3
"""
Enhanced Bjorn Dependencies Checker
Validates system requirements and provides resolution recommendations
"""

import sys
import os
import subprocess
import importlib
import platform
import shutil
from pathlib import Path

class DependencyChecker:
    def __init__(self):
        self.issues = []
        self.warnings = []
        self.recommendations = []
        self.system_info = {
            'os': platform.system(),
            'os_version': platform.release(),
            'python_version': platform.python_version(),
            'architecture': platform.machine()
        }
    
    def check_python_version(self):
        """Check Python version compatibility"""
        print("🐍 Checking Python version...")
        
        major, minor = sys.version_info[:2]
        if major < 3 or (major == 3 and minor < 8):
            self.issues.append({
                'type': 'Python Version',
                'issue': f'Python {major}.{minor} detected, requires Python 3.8+',
                'resolution': 'Install Python 3.8 or higher:\n'
                            '  Ubuntu/Debian: sudo apt update && sudo apt install python3.8\n'
                            '  CentOS/RHEL: sudo yum install python38\n'
                            '  macOS: brew install python@3.8'
            })
            return False
        
        print(f"  ✓ Python {major}.{minor} - Compatible")
        return True
    
    def check_system_tools(self):
        """Check required system tools"""
        print("\n🔧 Checking system tools...")
        
        required_tools = {
            'masscan': {
                'description': 'Ultra-fast network scanner',
                'install': {
                    'Linux': 'sudo apt install masscan  # or build from source',
                    'Darwin': 'brew install masscan'
                }
            },
            'nmap': {
                'description': 'Network exploration and security auditing',
                'install': {
                    'Linux': 'sudo apt install nmap',
                    'Darwin': 'brew install nmap'
                }
            },
            'curl': {
                'description': 'HTTP client for API requests',
                'install': {
                    'Linux': 'sudo apt install curl',
                    'Darwin': 'curl is pre-installed'
                }
            }
        }
        
        for tool, info in required_tools.items():
            if shutil.which(tool):
                print(f"  ✓ {tool} - Available")
            else:
                install_cmd = info['install'].get(self.system_info['os'], 'Check documentation')
                self.issues.append({
                    'type': 'System Tool',
                    'issue': f'{tool} not found - {info["description"]}',
                    'resolution': f'Install {tool}:\n  {install_cmd}'
                })
    
    def check_python_packages(self):
        """Check required Python packages"""
        print("\n📦 Checking Python packages...")
        
        required_packages = {
            'requests': {
                'description': 'HTTP library for API requests',
                'install': 'pip3 install requests'
            },
            'numpy': {
                'description': 'Numerical computing for ML operations',
                'install': 'pip3 install numpy'
            },
            'pandas': {
                'description': 'Data analysis and manipulation',
                'install': 'pip3 install pandas'
            },
            'lxml': {
                'description': 'XML/HTML processing',
                'install': 'pip3 install lxml'
            },
            'python-nmap': {
                'description': 'Python wrapper for Nmap',
                'install': 'pip3 install python-nmap',
                'import_name': 'nmap'
            },
            'xmltodict': {
                'description': 'XML to dictionary conversion',
                'install': 'pip3 install xmltodict'
            },
            'beautifulsoup4': {
                'description': 'HTML/XML parsing',
                'install': 'pip3 install beautifulsoup4',
                'import_name': 'bs4'
            }
        }
        
        optional_packages = {
            'Pillow': {
                'description': 'Image processing (for EPD display)',
                'install': 'pip3 install Pillow',
                'import_name': 'PIL'
            },
            'paramiko': {
                'description': 'SSH client library',
                'install': 'pip3 install paramiko'
            },
            'pymysql': {
                'description': 'MySQL database connector',
                'install': 'pip3 install pymysql'
            },
            'sqlalchemy': {
                'description': 'SQL toolkit and ORM',
                'install': 'pip3 install sqlalchemy'
            },
            'netifaces': {
                'description': 'Network interface information',
                'install': 'pip3 install netifaces'
            }
        }
        
        # Check required packages
        for package, info in required_packages.items():
            import_name = info.get('import_name', package.replace('-', '_'))
            try:
                importlib.import_module(import_name)
                print(f"  ✓ {package} - Available")
            except ImportError:
                self.issues.append({
                    'type': 'Python Package',
                    'issue': f'{package} not found - {info["description"]}',
                    'resolution': info['install']
                })
        
        # Check optional packages
        missing_optional = []
        for package, info in optional_packages.items():
            import_name = info.get('import_name', package.replace('-', '_'))
            try:
                importlib.import_module(import_name)
                print(f"  ✓ {package} - Available (optional)")
            except ImportError:
                missing_optional.append((package, info))
        
        if missing_optional:
            self.warnings.append({
                'type': 'Optional Packages',
                'issue': f'{len(missing_optional)} optional packages missing',
                'packages': missing_optional
            })
    
    def check_permissions(self):
        """Check file permissions and access"""
        print("\n🔐 Checking permissions...")
        
        # Check if running as root (needed for some network operations)
        if os.geteuid() != 0:
            self.warnings.append({
                'type': 'Permissions',
                'issue': 'Not running as root - some network operations may fail',
                'resolution': 'Run with sudo for full functionality:\n  sudo python3 Bjorn.py'
            })
        else:
            print("  ✓ Running with root privileges")
        
        # Check directory permissions
        required_dirs = [
            'data/output/scan_results',
            'data/output/vulnerabilities',
            'data/output/targeting',
            'config'
        ]
        
        for directory in required_dirs:
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory, exist_ok=True)
                    print(f"  ✓ Created directory: {directory}")
                except PermissionError:
                    self.issues.append({
                        'type': 'Directory Permission',
                        'issue': f'Cannot create directory: {directory}',
                        'resolution': f'Create directory manually:\n  sudo mkdir -p {directory}\n  sudo chown $USER:$USER {directory}'
                    })
            else:
                print(f"  ✓ Directory exists: {directory}")
    
    def check_network_connectivity(self):
        """Check network connectivity for CVE updates"""
        print("\n🌐 Checking network connectivity...")
        
        test_urls = [
            'https://services.nvd.nist.gov',
            'https://api.first.org',
            'https://cve.mitre.org'
        ]
        
        for url in test_urls:
            try:
                result = subprocess.run(['curl', '-s', '--connect-timeout', '5', url], 
                                      capture_output=True, timeout=10)
                if result.returncode == 0:
                    print(f"  ✓ {url} - Accessible")
                else:
                    self.warnings.append({
                        'type': 'Network Connectivity',
                        'issue': f'Cannot reach {url}',
                        'resolution': 'Check internet connection and firewall settings'
                    })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.warnings.append({
                    'type': 'Network Test',
                    'issue': f'Cannot test connectivity to {url}',
                    'resolution': 'Ensure curl is installed and network is available'
                })
    
    def generate_install_script(self):
        """Generate automated installation script for missing dependencies"""
        if not self.issues:
            return None
        
        script_lines = [
            '#!/bin/bash',
            '# Auto-generated dependency installation script',
            '# Generated by Enhanced Bjorn Dependencies Checker',
            '',
            'echo "🔧 Installing missing dependencies..."',
            ''
        ]
        
        # Group by type
        python_packages = []
        system_tools = []
        
        for issue in self.issues:
            if issue['type'] == 'Python Package':
                if 'pip3 install' in issue['resolution']:
                    package = issue['resolution'].split('pip3 install ')[-1]
                    python_packages.append(package)
            elif issue['type'] == 'System Tool':
                if 'sudo apt install' in issue['resolution']:
                    tool = issue['resolution'].split('sudo apt install ')[-1].split()[0]
                    system_tools.append(tool)
        
        if system_tools:
            script_lines.extend([
                '# System tools',
                'echo "Installing system tools..."',
                'sudo apt update',
                f'sudo apt install -y {" ".join(system_tools)}',
                ''
            ])
        
        if python_packages:
            script_lines.extend([
                '# Python packages',
                'echo "Installing Python packages..."',
                f'pip3 install --user {" ".join(python_packages)}',
                ''
            ])
        
        script_lines.extend([
            'echo "✅ Dependency installation complete!"',
            'echo "Run the dependency checker again to verify installation."'
        ])
        
        return '\n'.join(script_lines)
    
    def print_report(self):
        """Print comprehensive dependency report"""
        print("\n" + "="*60)
        print("📋 ENHANCED BJORN DEPENDENCY REPORT")
        print("="*60)
        
        print(f"\n🖥️  System Information:")
        print(f"   OS: {self.system_info['os']} {self.system_info['os_version']}")
        print(f"   Python: {self.system_info['python_version']}")
        print(f"   Architecture: {self.system_info['architecture']}")
        
        if not self.issues and not self.warnings:
            print("\n🎉 ALL DEPENDENCIES SATISFIED!")
            print("   Enhanced Bjorn is ready to run.")
            return True
        
        if self.issues:
            print(f"\n❌ CRITICAL ISSUES ({len(self.issues)}):")
            for i, issue in enumerate(self.issues, 1):
                print(f"\n   {i}. {issue['type']}: {issue['issue']}")
                print(f"      Resolution: {issue['resolution']}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                if warning['type'] == 'Optional Packages':
                    print(f"\n   {i}. {warning['issue']}:")
                    for package, info in warning['packages']:
                        print(f"      - {package}: {info['description']}")
                        print(f"        Install: {info['install']}")
                else:
                    print(f"\n   {i}. {warning['type']}: {warning['issue']}")
                    if 'resolution' in warning:
                        print(f"      Resolution: {warning['resolution']}")
        
        # Generate installation script
        install_script = self.generate_install_script()
        if install_script:
            script_path = 'install_dependencies.sh'
            with open(script_path, 'w') as f:
                f.write(install_script)
            os.chmod(script_path, 0o755)
            
            print(f"\n🚀 QUICK FIX:")
            print(f"   Auto-generated installation script: {script_path}")
            print(f"   Run: chmod +x {script_path} && ./{script_path}")
        
        print(f"\n📊 SUMMARY:")
        print(f"   Critical Issues: {len(self.issues)}")
        print(f"   Warnings: {len(self.warnings)}")
        
        if self.issues:
            print(f"   Status: ❌ DEPENDENCIES MISSING")
            print(f"   Action: Resolve critical issues before running Enhanced Bjorn")
        else:
            print(f"   Status: ⚠️  READY WITH WARNINGS")
            print(f"   Action: Enhanced Bjorn can run, but some features may be limited")
        
        print("\n" + "="*60)
        return len(self.issues) == 0

def main():
    """Main dependency checking function"""
    print("🔍 Enhanced Bjorn Dependencies Checker")
    print("Validating system requirements and dependencies...\n")
    
    checker = DependencyChecker()
    
    # Run all checks
    checker.check_python_version()
    checker.check_system_tools()
    checker.check_python_packages()
    checker.check_permissions()
    checker.check_network_connectivity()
    
    # Generate and print report
    success = checker.print_report()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
