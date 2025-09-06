# intelligent_targeting.py
# AI-driven target prioritization and autonomous decision making engine
# Provides intelligent attack sequencing, risk assessment, and adaptive targeting

import os
import json
import csv
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
import numpy as np
from logger import Logger

logger = Logger(name="intelligent_targeting.py", level=logging.DEBUG)

b_class = "IntelligentTargeting"
b_module = "intelligent_targeting"
b_status = "intelligent_targeting"
b_port = None
b_parent = None
b_priority = 0  # Highest priority - runs first

@dataclass
class TargetProfile:
    """Data class to hold target profile information"""
    ip: str
    hostname: str = ""
    mac: str = ""
    ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    success_history: List[str] = field(default_factory=list)
    failure_history: List[str] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    attack_priority: float = 0.0
    exploitation_difficulty: float = 5.0  # 1-10 scale
    value_score: float = 0.0  # Potential value of compromising this target
    stealth_requirement: float = 5.0  # 1-10 scale (10 = maximum stealth)

@dataclass
class AttackVector:
    """Data class to hold attack vector information"""
    name: str
    target_port: int
    success_rate: float = 0.0
    detection_risk: float = 5.0  # 1-10 scale
    time_to_execute: int = 60  # seconds
    prerequisites: List[str] = field(default_factory=list)
    post_exploitation_value: float = 5.0
    stealth_level: float = 5.0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None

class IntelligentTargeting:
    """
    AI-driven target prioritization and attack orchestration engine
    that learns from success/failure patterns and optimizes attack sequences
    """
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.lock = threading.Lock()
        self.running = False
        
        # Learning and adaptation parameters
        self.learning_rate = getattr(shared_data, 'learning_rate', 0.1)
        self.success_weight = getattr(shared_data, 'success_weight', 2.0)
        self.failure_penalty = getattr(shared_data, 'failure_penalty', 0.5)
        self.time_decay_factor = getattr(shared_data, 'time_decay_factor', 0.95)
        
        # Targeting configuration
        self.max_concurrent_targets = getattr(shared_data, 'max_concurrent_targets', 3)
        self.min_attack_interval = getattr(shared_data, 'min_attack_interval', 300)  # seconds
        self.stealth_mode = getattr(shared_data, 'stealth_mode', False)
        
        # Output configuration
        self.targeting_dir = os.path.join(shared_data.currentdir, 'data', 'output', 'targeting')
        self.timestamp = self.get_current_timestamp()
        
        # Target profiles and attack vectors
        self.target_profiles: Dict[str, TargetProfile] = {}
        self.attack_vectors: Dict[str, AttackVector] = {}
        self.attack_history: List[Dict] = []
        
        # Load historical data
        self.load_targeting_data()
        self.initialize_attack_vectors()
        
        # Network topology understanding
        self.network_segments: Dict[str, List[str]] = {}
        self.high_value_targets: Set[str] = set()
        self.compromised_hosts: Set[str] = set()
        
        # Time-based patterns
        self.optimal_attack_times: Dict[str, List[int]] = defaultdict(list)  # hour of day
        self.network_activity_patterns: Dict[str, float] = {}

    def get_current_timestamp(self) -> str:
        """Returns current timestamp in format YYYYMMDD_HHMMSS"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def load_targeting_data(self):
        """Load historical targeting data and learned patterns"""
        try:
            os.makedirs(self.targeting_dir, exist_ok=True)
            
            # Load target profiles
            profiles_file = os.path.join(self.targeting_dir, 'target_profiles.json')
            if os.path.exists(profiles_file):
                with open(profiles_file, 'r') as f:
                    data = json.load(f)
                    for ip, profile_data in data.items():
                        profile = TargetProfile(
                            ip=ip,
                            hostname=profile_data.get('hostname', ''),
                            mac=profile_data.get('mac', ''),
                            ports=profile_data.get('ports', []),
                            services=profile_data.get('services', {}),
                            vulnerabilities=profile_data.get('vulnerabilities', []),
                            risk_score=profile_data.get('risk_score', 0.0),
                            success_history=profile_data.get('success_history', []),
                            failure_history=profile_data.get('failure_history', []),
                            attack_priority=profile_data.get('attack_priority', 0.0),
                            exploitation_difficulty=profile_data.get('exploitation_difficulty', 5.0),
                            value_score=profile_data.get('value_score', 0.0),
                            stealth_requirement=profile_data.get('stealth_requirement', 5.0)
                        )
                        if profile_data.get('last_seen'):
                            profile.last_seen = datetime.fromisoformat(profile_data['last_seen'])
                        self.target_profiles[ip] = profile
                
                self.logger.info(f"Loaded {len(self.target_profiles)} target profiles")
            
            # Load attack history
            history_file = os.path.join(self.targeting_dir, 'attack_history.json')
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    self.attack_history = json.load(f)
                self.logger.info(f"Loaded {len(self.attack_history)} attack history records")
                
        except Exception as e:
            self.logger.error(f"Error loading targeting data: {e}")

    def save_targeting_data(self):
        """Save targeting data and learned patterns"""
        try:
            os.makedirs(self.targeting_dir, exist_ok=True)
            
            # Save target profiles
            profiles_file = os.path.join(self.targeting_dir, 'target_profiles.json')
            profiles_data = {}
            for ip, profile in self.target_profiles.items():
                profiles_data[ip] = {
                    'hostname': profile.hostname,
                    'mac': profile.mac,
                    'ports': profile.ports,
                    'services': profile.services,
                    'vulnerabilities': profile.vulnerabilities,
                    'risk_score': profile.risk_score,
                    'success_history': profile.success_history,
                    'failure_history': profile.failure_history,
                    'last_seen': profile.last_seen.isoformat(),
                    'attack_priority': profile.attack_priority,
                    'exploitation_difficulty': profile.exploitation_difficulty,
                    'value_score': profile.value_score,
                    'stealth_requirement': profile.stealth_requirement
                }
            
            with open(profiles_file, 'w') as f:
                json.dump(profiles_data, f, indent=2)
            
            # Save attack history
            history_file = os.path.join(self.targeting_dir, 'attack_history.json')
            with open(history_file, 'w') as f:
                json.dump(self.attack_history[-1000:], f, indent=2)  # Keep last 1000 records
            
            self.logger.info("Saved targeting data and attack history")
            
        except Exception as e:
            self.logger.error(f"Error saving targeting data: {e}")

    def initialize_attack_vectors(self):
        """Initialize attack vectors with default parameters"""
        self.attack_vectors = {
            'SSHBruteforce': AttackVector(
                name='SSHBruteforce',
                target_port=22,
                success_rate=0.3,
                detection_risk=6.0,
                time_to_execute=300,
                post_exploitation_value=8.0,
                stealth_level=4.0
            ),
            'FTPBruteforce': AttackVector(
                name='FTPBruteforce',
                target_port=21,
                success_rate=0.4,
                detection_risk=5.0,
                time_to_execute=180,
                post_exploitation_value=6.0,
                stealth_level=5.0
            ),
            'SMBBruteforce': AttackVector(
                name='SMBBruteforce',
                target_port=445,
                success_rate=0.35,
                detection_risk=7.0,
                time_to_execute=240,
                post_exploitation_value=9.0,
                stealth_level=3.0
            ),
            'RDPBruteforce': AttackVector(
                name='RDPBruteforce',
                target_port=3389,
                success_rate=0.25,
                detection_risk=8.0,
                time_to_execute=360,
                post_exploitation_value=9.5,
                stealth_level=2.0
            ),
            'TelnetBruteforce': AttackVector(
                name='TelnetBruteforce',
                target_port=23,
                success_rate=0.6,
                detection_risk=4.0,
                time_to_execute=120,
                post_exploitation_value=7.0,
                stealth_level=6.0
            ),
            'SQLBruteforce': AttackVector(
                name='SQLBruteforce',
                target_port=3306,
                success_rate=0.3,
                detection_risk=6.0,
                time_to_execute=200,
                post_exploitation_value=8.5,
                stealth_level=4.0
            )
        }

    def update_target_profiles_from_netkb(self):
        """Update target profiles from network knowledge base"""
        try:
            netkbfile = self.shared_data.netkbfile
            if not os.path.exists(netkbfile):
                return
            
            with open(netkbfile, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("Alive") != "1" or row.get("MAC Address") == "STANDALONE":
                        continue
                    
                    ip = row.get("IPs", "")
                    if not ip:
                        continue
                    
                    # Create or update target profile
                    if ip not in self.target_profiles:
                        self.target_profiles[ip] = TargetProfile(ip=ip)
                    
                    profile = self.target_profiles[ip]
                    profile.hostname = row.get("Hostnames", "")
                    profile.mac = row.get("MAC Address", "")
                    profile.last_seen = datetime.now()
                    
                    # Parse ports
                    ports_str = row.get("Ports", "")
                    if ports_str:
                        try:
                            profile.ports = [int(p) for p in ports_str.split(';') if p.isdigit()]
                        except:
                            profile.ports = []
                    
                    # Update vulnerability information if available
                    profile.risk_score = float(row.get("Risk_Score", 0.0))
                    
                    # Calculate value score based on services and vulnerabilities
                    profile.value_score = self.calculate_target_value(profile)
                    
                    # Update exploitation difficulty based on services
                    profile.exploitation_difficulty = self.calculate_exploitation_difficulty(profile)
            
            self.logger.info(f"Updated {len(self.target_profiles)} target profiles from network KB")
            
        except Exception as e:
            self.logger.error(f"Error updating target profiles: {e}")

    def calculate_target_value(self, profile: TargetProfile) -> float:
        """Calculate the potential value of compromising a target"""
        value = 0.0
        
        # Base value from vulnerability risk score
        value += profile.risk_score * 0.5
        
        # Value based on services
        service_values = {
            22: 8.0,    # SSH - high value for lateral movement
            21: 6.0,    # FTP - file access
            445: 9.0,   # SMB - file shares, potential domain access
            3389: 9.5,  # RDP - full desktop access
            3306: 8.5,  # MySQL - database access
            1433: 8.5,  # MSSQL - database access
            5432: 8.0,  # PostgreSQL - database access
            80: 7.0,    # HTTP - web applications
            443: 7.5,   # HTTPS - secure web applications
            25: 6.0,    # SMTP - email server
            53: 5.0,    # DNS - network infrastructure
            135: 7.0,   # RPC - Windows services
            139: 6.0,   # NetBIOS - Windows networking
        }
        
        for port in profile.ports:
            value += service_values.get(port, 2.0)
        
        # Bonus for multiple services (indicates server/workstation)
        if len(profile.ports) > 5:
            value += 3.0
        elif len(profile.ports) > 3:
            value += 1.5
        
        # Hostname-based value assessment
        hostname_lower = profile.hostname.lower()
        if any(keyword in hostname_lower for keyword in ['server', 'srv', 'dc', 'domain', 'ad']):
            value += 5.0
        elif any(keyword in hostname_lower for keyword in ['db', 'database', 'sql']):
            value += 4.0
        elif any(keyword in hostname_lower for keyword in ['web', 'www', 'http']):
            value += 3.0
        
        return min(value, 10.0)  # Cap at 10.0

    def calculate_exploitation_difficulty(self, profile: TargetProfile) -> float:
        """Calculate the difficulty of exploiting a target"""
        difficulty = 5.0  # Base difficulty
        
        # Adjust based on number of services (more services = easier)
        if len(profile.ports) > 10:
            difficulty -= 2.0
        elif len(profile.ports) > 5:
            difficulty -= 1.0
        elif len(profile.ports) < 3:
            difficulty += 1.0
        
        # Adjust based on service types
        easy_services = [21, 23, 80]  # FTP, Telnet, HTTP
        hard_services = [22, 443, 3389]  # SSH, HTTPS, RDP
        
        easy_count = sum(1 for port in profile.ports if port in easy_services)
        hard_count = sum(1 for port in profile.ports if port in hard_services)
        
        difficulty -= easy_count * 0.5
        difficulty += hard_count * 0.3
        
        # Adjust based on historical success/failure
        if profile.success_history:
            recent_successes = len([s for s in profile.success_history[-10:]])
            difficulty -= recent_successes * 0.2
        
        if profile.failure_history:
            recent_failures = len([f for f in profile.failure_history[-10:]])
            difficulty += recent_failures * 0.1
        
        return max(1.0, min(difficulty, 10.0))  # Clamp between 1.0 and 10.0

    def calculate_attack_priority(self, profile: TargetProfile) -> float:
        """Calculate attack priority using multi-factor scoring"""
        priority = 0.0
        
        # Factor 1: Target value (40% weight)
        priority += profile.value_score * 0.4
        
        # Factor 2: Vulnerability risk score (30% weight)
        priority += profile.risk_score * 0.3
        
        # Factor 3: Exploitation ease (20% weight) - inverse of difficulty
        ease_score = 11.0 - profile.exploitation_difficulty
        priority += ease_score * 0.2
        
        # Factor 4: Recency (10% weight) - prefer recently seen targets
        time_since_seen = (datetime.now() - profile.last_seen).total_seconds()
        recency_score = max(0, 10.0 - (time_since_seen / 3600))  # Decay over hours
        priority += recency_score * 0.1
        
        # Bonus factors
        
        # Success history bonus
        if profile.success_history:
            recent_successes = len([s for s in profile.success_history[-5:]])
            priority += recent_successes * 0.5
        
        # Failure penalty
        if profile.failure_history:
            recent_failures = len([f for f in profile.failure_history[-5:]])
            priority -= recent_failures * 0.3
        
        # Stealth consideration
        if self.stealth_mode:
            stealth_penalty = (10.0 - profile.stealth_requirement) * 0.2
            priority -= stealth_penalty
        
        # Network position bonus (if we know topology)
        if profile.ip in self.high_value_targets:
            priority += 2.0
        
        # Lateral movement bonus (if we have compromised nearby hosts)
        network_prefix = '.'.join(profile.ip.split('.')[:3])
        nearby_compromised = len([ip for ip in self.compromised_hosts 
                                if ip.startswith(network_prefix)])
        if nearby_compromised > 0:
            priority += nearby_compromised * 0.5
        
        profile.attack_priority = max(0.0, priority)
        return profile.attack_priority

    def select_optimal_attack_vector(self, profile: TargetProfile) -> Optional[AttackVector]:
        """Select the best attack vector for a target based on AI scoring"""
        available_vectors = []
        
        # Find applicable attack vectors
        for vector_name, vector in self.attack_vectors.items():
            if vector.target_port in profile.ports:
                available_vectors.append(vector)
        
        if not available_vectors:
            return None
        
        # Score each vector
        best_vector = None
        best_score = -1.0
        
        for vector in available_vectors:
            score = self.calculate_vector_score(vector, profile)
            if score > best_score:
                best_score = score
                best_vector = vector
        
        return best_vector

    def calculate_vector_score(self, vector: AttackVector, profile: TargetProfile) -> float:
        """Calculate attack vector score for a specific target"""
        score = 0.0
        
        # Base success rate (40% weight)
        score += vector.success_rate * 4.0
        
        # Post-exploitation value (30% weight)
        score += vector.post_exploitation_value * 0.3
        
        # Time efficiency (20% weight) - prefer faster attacks
        time_score = max(0, 10.0 - (vector.time_to_execute / 60))
        score += time_score * 0.2
        
        # Stealth consideration (10% weight)
        if self.stealth_mode:
            stealth_score = vector.stealth_level
            score += stealth_score * 0.1
        else:
            # In non-stealth mode, detection risk is less important
            detection_score = 10.0 - vector.detection_risk
            score += detection_score * 0.1
        
        # Historical performance adjustment
        if vector.last_success:
            days_since_success = (datetime.now() - vector.last_success).days
            if days_since_success < 7:
                score += 1.0  # Recent success bonus
        
        if vector.last_failure:
            days_since_failure = (datetime.now() - vector.last_failure).days
            if days_since_failure < 1:
                score -= 2.0  # Recent failure penalty
        
        return max(0.0, score)

    def learn_from_attack_result(self, target_ip: str, vector_name: str, 
                               result: str, execution_time: int):
        """Update AI models based on attack results"""
        try:
            # Update target profile
            if target_ip in self.target_profiles:
                profile = self.target_profiles[target_ip]
                
                if result == 'success':
                    profile.success_history.append(f"{vector_name}_{datetime.now().isoformat()}")
                    # Reduce exploitation difficulty based on success
                    profile.exploitation_difficulty *= (1.0 - self.learning_rate)
                else:
                    profile.failure_history.append(f"{vector_name}_{datetime.now().isoformat()}")
                    # Increase exploitation difficulty based on failure
                    profile.exploitation_difficulty *= (1.0 + self.learning_rate * 0.5)
                
                # Keep history manageable
                profile.success_history = profile.success_history[-20:]
                profile.failure_history = profile.failure_history[-20:]
            
            # Update attack vector performance
            if vector_name in self.attack_vectors:
                vector = self.attack_vectors[vector_name]
                
                if result == 'success':
                    vector.last_success = datetime.now()
                    # Improve success rate
                    vector.success_rate = min(1.0, 
                        vector.success_rate + (self.learning_rate * self.success_weight))
                else:
                    vector.last_failure = datetime.now()
                    # Decrease success rate
                    vector.success_rate = max(0.0, 
                        vector.success_rate - (self.learning_rate * self.failure_penalty))
                
                # Update time estimate based on actual execution time
                if execution_time > 0:
                    vector.time_to_execute = int(
                        vector.time_to_execute * 0.9 + execution_time * 0.1)
            
            # Record in attack history
            attack_record = {
                'timestamp': datetime.now().isoformat(),
                'target_ip': target_ip,
                'vector': vector_name,
                'result': result,
                'execution_time': execution_time
            }
            self.attack_history.append(attack_record)
            
            # Update compromised hosts list
            if result == 'success':
                self.compromised_hosts.add(target_ip)
            
            self.logger.info(f"Learned from attack: {target_ip} -> {vector_name} = {result}")
            
        except Exception as e:
            self.logger.error(f"Error learning from attack result: {e}")

    def get_prioritized_targets(self, max_targets: int = 10) -> List[TargetProfile]:
        """Get prioritized list of targets for attack"""
        try:
            # Update all target priorities
            for profile in self.target_profiles.values():
                self.calculate_attack_priority(profile)
            
            # Filter out recently attacked targets (if stealth mode)
            available_targets = []
            current_time = datetime.now()
            
            for profile in self.target_profiles.values():
                # Skip if no open ports
                if not profile.ports:
                    continue
                
                # Check if target was recently attacked
                if self.stealth_mode:
                    last_attack_time = self.get_last_attack_time(profile.ip)
                    if last_attack_time:
                        time_since_attack = (current_time - last_attack_time).total_seconds()
                        if time_since_attack < self.min_attack_interval:
                            continue
                
                available_targets.append(profile)
            
            # Sort by priority and return top targets
            available_targets.sort(key=lambda x: x.attack_priority, reverse=True)
            return available_targets[:max_targets]
            
        except Exception as e:
            self.logger.error(f"Error getting prioritized targets: {e}")
            return []

    def get_last_attack_time(self, target_ip: str) -> Optional[datetime]:
        """Get the last time a target was attacked"""
        try:
            for record in reversed(self.attack_history):
                if record['target_ip'] == target_ip:
                    return datetime.fromisoformat(record['timestamp'])
            return None
        except:
            return None

    def generate_attack_plan(self) -> List[Dict]:
        """Generate intelligent attack plan based on current targets"""
        try:
            attack_plan = []
            
            # Get prioritized targets
            targets = self.get_prioritized_targets(self.max_concurrent_targets)
            
            for profile in targets:
                # Select optimal attack vector
                vector = self.select_optimal_attack_vector(profile)
                if not vector:
                    continue
                
                attack_plan.append({
                    'target_ip': profile.ip,
                    'target_hostname': profile.hostname,
                    'attack_vector': vector.name,
                    'target_port': vector.target_port,
                    'priority_score': profile.attack_priority,
                    'estimated_success_rate': vector.success_rate,
                    'estimated_time': vector.time_to_execute,
                    'risk_level': vector.detection_risk,
                    'target_value': profile.value_score
                })
            
            # Sort by priority
            attack_plan.sort(key=lambda x: x['priority_score'], reverse=True)
            
            self.logger.info(f"Generated attack plan with {len(attack_plan)} targets")
            return attack_plan
            
        except Exception as e:
            self.logger.error(f"Error generating attack plan: {e}")
            return []

    def save_attack_plan(self, attack_plan: List[Dict]):
        """Save attack plan to file"""
        try:
            plan_file = os.path.join(self.targeting_dir, f'attack_plan_{self.timestamp}.json')
            with open(plan_file, 'w') as f:
                json.dump(attack_plan, f, indent=2)
            
            # Also save as current plan
            current_plan_file = os.path.join(self.targeting_dir, 'current_attack_plan.json')
            with open(current_plan_file, 'w') as f:
                json.dump(attack_plan, f, indent=2)
            
            self.logger.info(f"Saved attack plan to {plan_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving attack plan: {e}")

    def analyze_network_topology(self):
        """Analyze network topology to identify high-value targets"""
        try:
            # Group targets by network segments
            segments = defaultdict(list)
            for ip, profile in self.target_profiles.items():
                network_prefix = '.'.join(ip.split('.')[:3])
                segments[network_prefix].append(profile)
            
            self.network_segments = dict(segments)
            
            # Identify high-value targets based on services and position
            self.high_value_targets.clear()
            
            for segment, profiles in segments.items():
                # Look for domain controllers, servers, databases
                for profile in profiles:
                    hostname_lower = profile.hostname.lower()
                    
                    # Domain controllers and servers
                    if any(keyword in hostname_lower for keyword in 
                          ['dc', 'domain', 'controller', 'server', 'srv']):
                        self.high_value_targets.add(profile.ip)
                    
                    # Database servers
                    elif any(port in profile.ports for port in [3306, 1433, 5432]):
                        self.high_value_targets.add(profile.ip)
                    
                    # Web servers with multiple services
                    elif 80 in profile.ports or 443 in profile.ports:
                        if len(profile.ports) > 5:  # Likely a server
                            self.high_value_targets.add(profile.ip)
            
            self.logger.info(f"Identified {len(self.high_value_targets)} high-value targets "
                           f"across {len(segments)} network segments")
            
        except Exception as e:
            self.logger.error(f"Error analyzing network topology: {e}")

    def execute(self, *args, **kwargs) -> str:
        """Execute method for orchestrator compatibility"""
        try:
            # Update target profiles from network KB
            self.update_target_profiles_from_netkb()
            
            # Analyze network topology
            self.analyze_network_topology()
            
            # Generate attack plan
            attack_plan = self.generate_attack_plan()
            
            if attack_plan:
                self.save_attack_plan(attack_plan)
                return 'success'
            else:
                return 'failed'
                
        except Exception as e:
            self.logger.error(f"Error in intelligent targeting execution: {e}")
            return 'failed'

    def run(self):
        """Main targeting analysis loop"""
        try:
            self.shared_data.bjornorch_status = "IntelligentTargeting"
            self.logger.info("Starting intelligent targeting analysis")
            
            # Update target profiles
            self.update_target_profiles_from_netkb()
            
            # Analyze network topology
            self.analyze_network_topology()
            
            # Generate and save attack plan
            attack_plan = self.generate_attack_plan()
            if attack_plan:
                self.save_attack_plan(attack_plan)
            
            # Save learned data
            self.save_targeting_data()
            
            self.logger.info("Intelligent targeting analysis completed")
            
        except Exception as e:
            self.logger.error(f"Error in intelligent targeting: {e}")
        finally:
            self.shared_data.bjornstatustext2 = ""

    def start(self):
        """Start the targeting engine in a separate thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.run)
            self.thread.start()
            self.logger.info("IntelligentTargeting started")

    def stop(self):
        """Stop the targeting engine"""
        if self.running:
            self.running = False
            if hasattr(self, 'thread') and self.thread.is_alive():
                self.thread.join()
            self.logger.info("IntelligentTargeting stopped")

if __name__ == "__main__":
    from init_shared import shared_data
    targeting = IntelligentTargeting(shared_data)
    targeting.run()
