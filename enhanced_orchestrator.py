# enhanced_orchestrator.py
# Enhanced orchestrator with support for advanced AI-driven modules
# Integrates intelligent targeting, high-speed scanning, and advanced vulnerability assessment

import json
import importlib
import time
import logging
import sys
import threading
from datetime import datetime, timedelta
from actions.nmap_vuln_scanner import NmapVulnScanner
from init_shared import shared_data
from logger import Logger

logger = Logger(name="enhanced_orchestrator.py", level=logging.DEBUG)

class EnhancedOrchestrator:
    def __init__(self):
        """Initialize the enhanced orchestrator with advanced capabilities"""
        self.shared_data = shared_data
        self.actions = []  # List of standard actions
        self.standalone_actions = []  # List of standalone actions
        self.advanced_modules = {}  # Dictionary of advanced modules
        self.failed_scans_count = 0
        self.network_scanner = None
        self.last_vuln_scan_time = datetime.min
        self.load_actions()
        self.load_advanced_modules()
        
        actions_loaded = [action.__class__.__name__ for action in self.actions + self.standalone_actions]
        advanced_loaded = list(self.advanced_modules.keys())
        logger.info(f"Standard actions loaded: {actions_loaded}")
        logger.info(f"Advanced modules loaded: {advanced_loaded}")
        
        self.semaphore = threading.Semaphore(10)

    def load_actions(self):
        """Load standard actions from the original actions file"""
        self.actions_dir = self.shared_data.actions_dir
        with open(self.shared_data.actions_file, 'r') as file:
            actions_config = json.load(file)
        
        for action in actions_config:
            module_name = action["b_module"]
            if module_name == 'scanning':
                self.load_scanner(module_name)
            elif module_name == 'nmap_vuln_scanner':
                self.load_nmap_vuln_scanner(module_name)
            else:
                self.load_action(module_name, action)

    def load_advanced_modules(self):
        """Load advanced AI-driven modules"""
        try:
            advanced_config_file = 'config/advanced_actions.json'
            with open(advanced_config_file, 'r') as file:
                advanced_config = json.load(file)
            
            for module_config in advanced_config:
                if not module_config.get('b_enabled', True):
                    continue
                
                module_name = module_config['b_module']
                class_name = module_config['b_class']
                
                try:
                    # Import the module
                    module = importlib.import_module(f'actions.{module_name}')
                    module_class = getattr(module, class_name)
                    
                    # Create instance
                    instance = module_class(self.shared_data)
                    instance.priority = module_config.get('b_priority', 5)
                    instance.parent = module_config.get('b_parent')
                    instance.standalone = module_config.get('b_standalone', False)
                    
                    self.advanced_modules[class_name] = instance
                    logger.info(f"Loaded advanced module: {class_name}")
                    
                except Exception as e:
                    logger.error(f"Failed to load advanced module {module_name}: {e}")
                    
        except FileNotFoundError:
            logger.warning("Advanced actions configuration file not found")
        except Exception as e:
            logger.error(f"Error loading advanced modules: {e}")

    def load_scanner(self, module_name):
        """Load the network scanner (enhanced or standard)"""
        if self.shared_data.config.get('use_masscan', False):
            # Use Masscan scanner if enabled
            try:
                module = importlib.import_module('actions.masscan_scanner')
                scanner_class = getattr(module, 'MasscanScanner')
                self.network_scanner = scanner_class(self.shared_data)
                logger.info("Using Masscan for network scanning")
            except Exception as e:
                logger.warning(f"Failed to load Masscan scanner, falling back to standard: {e}")
                # Fall back to standard scanner
                module = importlib.import_module(f'actions.{module_name}')
                b_class = getattr(module, 'b_class')
                self.network_scanner = getattr(module, b_class)(self.shared_data)
        else:
            # Use standard scanner
            module = importlib.import_module(f'actions.{module_name}')
            b_class = getattr(module, 'b_class')
            self.network_scanner = getattr(module, b_class)(self.shared_data)

    def load_nmap_vuln_scanner(self, module_name):
        """Load vulnerability scanner (enhanced or standard)"""
        if self.shared_data.config.get('use_advanced_vuln_scanner', False):
            # Advanced vulnerability scanner is loaded as an advanced module
            logger.info("Advanced vulnerability scanner will be loaded as advanced module")
        else:
            # Use standard Nmap vulnerability scanner
            self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)

    def load_action(self, module_name, action):
        """Load a standard action from the actions file"""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.port = action.get("b_port")
            action_instance.b_parent_action = action.get("b_parent")
            if action_instance.port == 0:
                self.standalone_actions.append(action_instance)
            else:
                self.actions.append(action_instance)
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")

    def execute_advanced_modules(self):
        """Execute advanced modules in priority order"""
        try:
            # Sort advanced modules by priority
            sorted_modules = sorted(self.advanced_modules.items(), 
                                  key=lambda x: getattr(x[1], 'priority', 5))
            
            for module_name, module_instance in sorted_modules:
                try:
                    logger.info(f"Executing advanced module: {module_name}")
                    self.shared_data.bjornorch_status = module_name
                    
                    # Execute the module
                    result = module_instance.execute()
                    
                    if result == 'success':
                        logger.info(f"Advanced module {module_name} completed successfully")
                    else:
                        logger.warning(f"Advanced module {module_name} reported failure")
                        
                except Exception as e:
                    logger.error(f"Error executing advanced module {module_name}: {e}")
                    
        except Exception as e:
            logger.error(f"Error in advanced modules execution: {e}")

    def process_alive_ips(self, current_data):
        """Process all IPs with alive status set to 1 (enhanced with AI targeting)"""
        any_action_executed = False
        action_executed_status = None

        # Check if intelligent targeting is available
        intelligent_targeting = self.advanced_modules.get('IntelligentTargeting')
        if intelligent_targeting:
            try:
                # Get AI-prioritized attack plan
                attack_plan = intelligent_targeting.generate_attack_plan()
                
                if attack_plan:
                    logger.info(f"Executing AI-generated attack plan with {len(attack_plan)} targets")
                    
                    for plan_item in attack_plan[:3]:  # Execute top 3 targets
                        target_ip = plan_item['target_ip']
                        vector_name = plan_item['attack_vector']
                        
                        # Find the corresponding action
                        target_action = None
                        for action in self.actions:
                            if action.action_name == vector_name:
                                target_action = action
                                break
                        
                        if target_action:
                            # Find the target row in current_data
                            target_row = None
                            for row in current_data:
                                if row["IPs"] == target_ip and row["Alive"] == '1':
                                    target_row = row
                                    break
                            
                            if target_row:
                                ports = target_row["Ports"].split(';')
                                if str(target_action.port) in ports:
                                    start_time = time.time()
                                    
                                    with self.semaphore:
                                        if self.execute_action(target_action, target_ip, ports, 
                                                             target_row, vector_name, current_data):
                                            execution_time = int(time.time() - start_time)
                                            
                                            # Learn from success
                                            intelligent_targeting.learn_from_attack_result(
                                                target_ip, vector_name, 'success', execution_time)
                                            
                                            action_executed_status = vector_name
                                            any_action_executed = True
                                            self.shared_data.bjornorch_status = action_executed_status
                                        else:
                                            execution_time = int(time.time() - start_time)
                                            
                                            # Learn from failure
                                            intelligent_targeting.learn_from_attack_result(
                                                target_ip, vector_name, 'failed', execution_time)
                    
                    # Save learned patterns
                    intelligent_targeting.save_targeting_data()
                    
                    if any_action_executed:
                        return any_action_executed
            
            except Exception as e:
                logger.error(f"Error in AI-driven targeting: {e}")

        # Fall back to standard processing if AI targeting fails or is not available
        for action in self.actions:
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip, ports = row["IPs"], row["Ports"].split(';')
                action_key = action.action_name

                if action.b_parent_action is None:
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            action_executed_status = action_key
                            any_action_executed = True
                            self.shared_data.bjornorch_status = action_executed_status

                            for child_action in self.actions:
                                if child_action.b_parent_action == action_key:
                                    with self.semaphore:
                                        if self.execute_action(child_action, ip, ports, row, 
                                                             child_action.action_name, current_data):
                                            action_executed_status = child_action.action_name
                                            self.shared_data.bjornorch_status = action_executed_status
                                            break
                            break

        return any_action_executed

    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """Execute an action on a target (same as original orchestrator)"""
        if hasattr(action, 'port') and str(action.port) not in ports:
            return False

        # Check parent action status
        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, "")
            if 'success' not in parent_status:
                return False

        # Check if the action is already successful and if retries are disabled
        if 'success' in row[action_key]:
            if not self.shared_data.retry_success_actions:
                return False
            else:
                try:
                    last_success_time = datetime.strptime(
                        row[action_key].split('_')[1] + "_" + row[action_key].split('_')[2], 
                        "%Y%m%d_%H%M%S")
                    if datetime.now() < last_success_time + timedelta(seconds=self.shared_data.success_retry_delay):
                        return False
                except ValueError as ve:
                    logger.error(f"Error parsing last success time for {action.action_name}: {ve}")

        # Check failed retry delay
        last_failed_time_str = row.get(action_key, "")
        if 'failed' in last_failed_time_str:
            try:
                last_failed_time = datetime.strptime(
                    last_failed_time_str.split('_')[1] + "_" + last_failed_time_str.split('_')[2], 
                    "%Y%m%d_%H%M%S")
                if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                    return False
            except ValueError as ve:
                logger.error(f"Error parsing last failed time for {action.action_name}: {ve}")

        try:
            logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
            self.shared_data.bjornstatustext2 = ip
            result = action.execute(ip, str(action.port), row, action_key)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
            else:
                row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action (same as original orchestrator)"""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {
                "MAC Address": "STANDALONE",
                "IPs": "STANDALONE",
                "Hostnames": "STANDALONE",
                "Ports": "0",
                "Alive": "0"
            }
            current_data.append(row)

        action_key = action.action_name
        if action_key not in row:
            row[action_key] = ""

        # Check retry logic (same as original)
        if 'success' in row[action_key]:
            if not self.shared_data.retry_success_actions:
                return False
            else:
                try:
                    last_success_time = datetime.strptime(
                        row[action_key].split('_')[1] + "_" + row[action_key].split('_')[2], 
                        "%Y%m%d_%H%M%S")
                    if datetime.now() < last_success_time + timedelta(seconds=self.shared_data.success_retry_delay):
                        return False
                except ValueError as ve:
                    logger.error(f"Error parsing last success time for {action.action_name}: {ve}")

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            result = action.execute()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                logger.info(f"Standalone action {action.action_name} executed successfully")
            else:
                row[action_key] = f'failed_{timestamp}'
                logger.error(f"Standalone action {action.action_name} failed")
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def run(self):
        """Enhanced orchestrator main loop"""
        # Execute advanced modules first (if enabled)
        if self.shared_data.config.get('use_intelligent_targeting', False) or \
           self.shared_data.config.get('use_masscan', False) or \
           self.shared_data.config.get('use_advanced_vuln_scanner', False):
            logger.info("Executing advanced modules...")
            self.execute_advanced_modules()

        # Run initial network scan
        self.shared_data.bjornorch_status = "NetworkScanner"
        self.shared_data.bjornstatustext2 = "Initial scan..."
        if self.network_scanner:
            self.network_scanner.scan()
        self.shared_data.bjornstatustext2 = ""

        # Main orchestrator loop
        while not self.shared_data.orchestrator_should_exit:
            current_data = self.shared_data.read_data()
            any_action_executed = False

            # Process targets with enhanced AI targeting
            any_action_executed = self.process_alive_ips(current_data)

            self.shared_data.write_data(current_data)

            if not any_action_executed:
                self.shared_data.bjornorch_status = "IDLE"
                self.shared_data.bjornstatustext2 = ""
                logger.info("No available targets. Running network scan...")
                
                if self.network_scanner:
                    self.shared_data.bjornorch_status = "NetworkScanner"
                    self.network_scanner.scan()
                    current_data = self.shared_data.read_data()
                    any_action_executed = self.process_alive_ips(current_data)
                    
                    # Enhanced vulnerability scanning
                    if self.shared_data.scan_vuln_running:
                        current_time = datetime.now()
                        if current_time >= self.last_vuln_scan_time + timedelta(seconds=self.shared_data.scan_vuln_interval):
                            
                            # Use advanced vulnerability scanner if available
                            advanced_vuln_scanner = self.advanced_modules.get('AdvancedVulnScanner')
                            if advanced_vuln_scanner and self.shared_data.config.get('use_advanced_vuln_scanner', False):
                                try:
                                    logger.info("Starting advanced vulnerability scan...")
                                    self.shared_data.bjornorch_status = "AdvancedVulnScanner"
                                    result = advanced_vuln_scanner.scan()
                                    self.last_vuln_scan_time = current_time
                                except Exception as e:
                                    logger.error(f"Error during advanced vulnerability scan: {e}")
                            else:
                                # Fall back to standard vulnerability scanning
                                try:
                                    logger.info("Starting standard vulnerability scans...")
                                    for row in current_data:
                                        if row["Alive"] == '1':
                                            ip = row["IPs"]
                                            scan_status = row.get("NmapVulnScanner", "")

                                            # Standard retry logic
                                            if 'success' in scan_status:
                                                last_success_time = datetime.strptime(
                                                    scan_status.split('_')[1] + "_" + scan_status.split('_')[2], 
                                                    "%Y%m%d_%H%M%S")
                                                if not self.shared_data.retry_success_actions:
                                                    continue
                                                if datetime.now() < last_success_time + timedelta(seconds=self.shared_data.success_retry_delay):
                                                    continue

                                            if 'failed' in scan_status:
                                                last_failed_time = datetime.strptime(
                                                    scan_status.split('_')[1] + "_" + scan_status.split('_')[2], 
                                                    "%Y%m%d_%H%M%S")
                                                if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                                                    continue

                                            with self.semaphore:
                                                if hasattr(self, 'nmap_vuln_scanner'):
                                                    result = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                                    if result == 'success':
                                                        row["NmapVulnScanner"] = f'success_{timestamp}'
                                                    else:
                                                        row["NmapVulnScanner"] = f'failed_{timestamp}'
                                                    self.shared_data.write_data(current_data)
                                    self.last_vuln_scan_time = current_time
                                except Exception as e:
                                    logger.error(f"Error during standard vulnerability scan: {e}")

                else:
                    logger.warning("No network scanner available.")
                
                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    for action in self.standalone_actions:
                        with self.semaphore:
                            if self.execute_standalone_action(action, current_data):
                                self.failed_scans_count = 0
                                break
                    
                    # Idle period with countdown
                    idle_start_time = datetime.now()
                    idle_end_time = idle_start_time + timedelta(seconds=self.shared_data.scan_interval)
                    while datetime.now() < idle_end_time:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        remaining_time = (idle_end_time - datetime.now()).seconds
                        self.shared_data.bjornorch_status = "IDLE"
                        self.shared_data.bjornstatustext2 = ""
                        sys.stdout.write('\x1b[1A\x1b[2K')
                        logger.warning(f"Scanner did not find any new targets. Next scan in: {remaining_time} seconds")
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                self.failed_scans_count = 0

if __name__ == "__main__":
    orchestrator = EnhancedOrchestrator()
    orchestrator.run()
