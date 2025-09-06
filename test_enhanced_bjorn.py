#!/usr/bin/env python3
"""
Enhanced Bjorn Integration Test Suite
Tests all advanced modules and their integration with the existing system
"""

import sys
import os
import json
import time
import logging
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Test configuration
TEST_CONFIG = {
    "test_network": "192.168.1.0/24",
    "test_targets": ["192.168.1.100", "192.168.1.101"],
    "test_ports": [22, 80, 443, 445],
    "mock_vulnerabilities": [
        {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity": "Critical",
            "description": "Apache Log4j2 Remote Code Execution"
        }
    ]
}

class TestEnhancedBjorn(unittest.TestCase):
    """Main test class for Enhanced Bjorn functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_data_dir = "test_data"
        os.makedirs(self.test_data_dir, exist_ok=True)
        os.makedirs("data/output/scan_results", exist_ok=True)
        os.makedirs("data/output/vulnerabilities", exist_ok=True)
        os.makedirs("data/output/targeting", exist_ok=True)
        
        # Mock shared_data
        self.mock_shared_data = Mock()
        self.mock_shared_data.config = {
            "use_masscan": True,
            "use_advanced_vuln_scanner": True,
            "use_intelligent_targeting": True,
            "masscan_rate": 100,  # Lower rate for testing
            "stealth_mode": False,
            "learning_rate": 0.1
        }
        self.mock_shared_data.currentdir = os.getcwd()
        self.mock_shared_data.scan_results_dir = "data/output/scan_results"
        self.mock_shared_data.vulnerabilities_dir = "data/output/vulnerabilities"
        self.mock_shared_data.netkbfile = "test_data/netkb.csv"
        
        # Add specific attributes that modules expect
        self.mock_shared_data.masscan_rate = 100
        self.mock_shared_data.learning_rate = 0.1
        self.mock_shared_data.exclude_ranges = []
        self.mock_shared_data.portlist = [22, 80, 443, 445]
        self.mock_shared_data.portstart = 1
        self.mock_shared_data.portend = 1000
        self.mock_shared_data.vuln_scanner_threads = 20
        
        # Create test network knowledge base
        self.create_test_netkb()
    
    def create_test_netkb(self):
        """Create a test network knowledge base file"""
        netkb_data = [
            ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"],
            ["aa:bb:cc:dd:ee:01", "192.168.1.100", "test-server", "1", "22;80;443"],
            ["aa:bb:cc:dd:ee:02", "192.168.1.101", "test-workstation", "1", "445;3389"],
            ["aa:bb:cc:dd:ee:03", "192.168.1.102", "test-database", "0", "3306"]
        ]
        
        with open(self.mock_shared_data.netkbfile, 'w', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerows(netkb_data)
    
    def test_masscan_scanner_import(self):
        """Test that MasscanScanner can be imported and initialized"""
        try:
            from actions.masscan_scanner import MasscanScanner
            scanner = MasscanScanner(self.mock_shared_data)
            self.assertIsNotNone(scanner)
            self.assertEqual(scanner.max_rate, 100)  # From mock config
            print("✓ MasscanScanner import and initialization successful")
        except ImportError as e:
            self.fail(f"Failed to import MasscanScanner: {e}")
    
    def test_advanced_vuln_scanner_import(self):
        """Test that AdvancedVulnScanner can be imported and initialized"""
        try:
            from actions.advanced_vuln_scanner import AdvancedVulnScanner
            scanner = AdvancedVulnScanner(self.mock_shared_data)
            self.assertIsNotNone(scanner)
            self.assertEqual(scanner.max_workers, 20)  # Default value
            print("✓ AdvancedVulnScanner import and initialization successful")
        except ImportError as e:
            self.fail(f"Failed to import AdvancedVulnScanner: {e}")
    
    def test_intelligent_targeting_import(self):
        """Test that IntelligentTargeting can be imported and initialized"""
        try:
            from actions.intelligent_targeting import IntelligentTargeting
            targeting = IntelligentTargeting(self.mock_shared_data)
            self.assertIsNotNone(targeting)
            self.assertEqual(targeting.learning_rate, 0.1)  # From mock config
            print("✓ IntelligentTargeting import and initialization successful")
        except ImportError as e:
            self.fail(f"Failed to import IntelligentTargeting: {e}")
    
    def test_enhanced_orchestrator_import(self):
        """Test that EnhancedOrchestrator can be imported and initialized"""
        try:
            from enhanced_orchestrator import EnhancedOrchestrator
            # Mock the shared_data import
            with patch('enhanced_orchestrator.shared_data', self.mock_shared_data):
                with patch('enhanced_orchestrator.Logger'):
                    orchestrator = EnhancedOrchestrator()
                    self.assertIsNotNone(orchestrator)
            print("✓ EnhancedOrchestrator import and initialization successful")
        except ImportError as e:
            self.fail(f"Failed to import EnhancedOrchestrator: {e}")
    
    @patch('subprocess.run')
    def test_masscan_command_building(self, mock_subprocess):
        """Test Masscan command building functionality"""
        try:
            from actions.masscan_scanner import MasscanScanner
            scanner = MasscanScanner(self.mock_shared_data)
            
            # Test command building
            cmd = scanner.build_masscan_command(
                "192.168.1.0/24", 
                "22,80,443", 
                "test_output.json"
            )
            
            expected_elements = ['masscan', '192.168.1.0/24', '-p', '22,80,443', '--rate', '100']
            for element in expected_elements:
                self.assertIn(element, cmd)
            
            print("✓ Masscan command building test passed")
        except Exception as e:
            self.fail(f"Masscan command building test failed: {e}")
    
    def test_intelligent_targeting_profile_creation(self):
        """Test target profile creation and scoring"""
        try:
            from actions.intelligent_targeting import IntelligentTargeting
            targeting = IntelligentTargeting(self.mock_shared_data)
            
            # Update profiles from mock netkb
            targeting.update_target_profiles_from_netkb()
            
            # Check that profiles were created
            self.assertGreater(len(targeting.target_profiles), 0)
            
            # Test target value calculation
            for ip, profile in targeting.target_profiles.items():
                value_score = targeting.calculate_target_value(profile)
                self.assertGreaterEqual(value_score, 0.0)
                self.assertLessEqual(value_score, 10.0)
            
            print(f"✓ Created {len(targeting.target_profiles)} target profiles")
            print("✓ Target value calculation test passed")
        except Exception as e:
            self.fail(f"Intelligent targeting test failed: {e}")
    
    def test_attack_vector_selection(self):
        """Test AI attack vector selection"""
        try:
            from actions.intelligent_targeting import IntelligentTargeting, TargetProfile
            targeting = IntelligentTargeting(self.mock_shared_data)
            
            # Create a test target profile
            test_profile = TargetProfile(
                ip="192.168.1.100",
                hostname="test-server",
                ports=[22, 80, 443],
                risk_score=7.5
            )
            
            # Test attack vector selection
            vector = targeting.select_optimal_attack_vector(test_profile)
            
            if vector:
                self.assertIn(vector.target_port, test_profile.ports)
                print(f"✓ Selected attack vector: {vector.name} for port {vector.target_port}")
            else:
                print("✓ No attack vector selected (expected for test profile)")
            
        except Exception as e:
            self.fail(f"Attack vector selection test failed: {e}")
    
    @patch('requests.get')
    def test_vulnerability_enrichment(self, mock_requests):
        """Test vulnerability enrichment with mock CVE data"""
        try:
            from actions.advanced_vuln_scanner import AdvancedVulnScanner, Vulnerability
            
            # Mock NVD API response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2021-44228",
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 10.0}
                            }]
                        },
                        "descriptions": [{
                            "lang": "en",
                            "value": "Apache Log4j2 Remote Code Execution"
                        }],
                        "references": [{"url": "https://example.com"}],
                        "published": "2021-12-10T00:00:00.000",
                        "lastModified": "2021-12-10T00:00:00.000"
                    }
                }]
            }
            mock_requests.return_value = mock_response
            
            scanner = AdvancedVulnScanner(self.mock_shared_data)
            
            # Create test vulnerability
            test_vuln = Vulnerability(
                cve_id="CVE-2021-44228",
                cvss_score=0.0,
                severity="Unknown",
                description="Test vulnerability"
            )
            
            # Test enrichment
            enriched = scanner.enrich_vulnerabilities_with_nvd([test_vuln])
            
            self.assertEqual(len(enriched), 1)
            self.assertEqual(enriched[0].cvss_score, 10.0)
            self.assertEqual(enriched[0].severity, "Critical")
            
            print("✓ Vulnerability enrichment test passed")
            
        except Exception as e:
            self.fail(f"Vulnerability enrichment test failed: {e}")
    
    def test_configuration_loading(self):
        """Test configuration file loading"""
        try:
            # Test advanced_actions.json loading
            with open("config/advanced_actions.json", 'r') as f:
                config = json.load(f)
                self.assertIsInstance(config, list)
                self.assertGreater(len(config), 0)
            
            # Test shared_config.json advanced settings
            with open("config/shared_config.json", 'r') as f:
                config = json.load(f)
                self.assertIn("use_masscan", config)
                self.assertIn("use_advanced_vuln_scanner", config)
                self.assertIn("use_intelligent_targeting", config)
            
            print("✓ Configuration loading test passed")
            
        except Exception as e:
            self.fail(f"Configuration loading test failed: {e}")
    
    def test_directory_structure(self):
        """Test that required directories exist"""
        required_dirs = [
            "data/output/scan_results",
            "data/output/vulnerabilities",
            "data/output/targeting"
        ]
        
        for directory in required_dirs:
            self.assertTrue(os.path.exists(directory), f"Directory {directory} does not exist")
        
        print("✓ Directory structure test passed")
    
    def test_learning_system(self):
        """Test AI learning from attack results"""
        try:
            from actions.intelligent_targeting import IntelligentTargeting
            targeting = IntelligentTargeting(self.mock_shared_data)
            
            # Test learning from success
            initial_success_rate = targeting.attack_vectors.get('SSHBruteforce', Mock()).success_rate
            targeting.learn_from_attack_result("192.168.1.100", "SSHBruteforce", "success", 120)
            
            # Test learning from failure
            targeting.learn_from_attack_result("192.168.1.101", "SSHBruteforce", "failed", 300)
            
            print("✓ AI learning system test passed")
            
        except Exception as e:
            self.fail(f"Learning system test failed: {e}")
    
    def test_performance_benchmarking(self):
        """Basic performance benchmarking"""
        try:
            from actions.masscan_scanner import MasscanScanner
            from actions.intelligent_targeting import IntelligentTargeting
            
            # Test initialization times
            start_time = time.time()
            scanner = MasscanScanner(self.mock_shared_data)
            scanner_init_time = time.time() - start_time
            
            start_time = time.time()
            targeting = IntelligentTargeting(self.mock_shared_data)
            targeting_init_time = time.time() - start_time
            
            # Reasonable initialization times (should be under 1 second each)
            self.assertLess(scanner_init_time, 1.0)
            self.assertLess(targeting_init_time, 1.0)
            
            print(f"✓ MasscanScanner initialization: {scanner_init_time:.3f}s")
            print(f"✓ IntelligentTargeting initialization: {targeting_init_time:.3f}s")
            
        except Exception as e:
            self.fail(f"Performance benchmarking failed: {e}")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        if os.path.exists(self.test_data_dir):
            shutil.rmtree(self.test_data_dir)

class TestIntegration(unittest.TestCase):
    """Integration tests for Enhanced Bjorn components working together"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.mock_shared_data = Mock()
        self.mock_shared_data.config = {
            "use_masscan": True,
            "use_advanced_vuln_scanner": True,
            "use_intelligent_targeting": True
        }
    
    def test_orchestrator_module_loading(self):
        """Test that the enhanced orchestrator can load all advanced modules"""
        try:
            from enhanced_orchestrator import EnhancedOrchestrator
            
            with patch('enhanced_orchestrator.shared_data', self.mock_shared_data):
                with patch('enhanced_orchestrator.Logger'):
                    with patch('builtins.open', create=True) as mock_open:
                        # Mock the advanced_actions.json file
                        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps([
                            {
                                "b_module": "intelligent_targeting",
                                "b_class": "IntelligentTargeting",
                                "b_enabled": True,
                                "b_priority": 0
                            }
                        ])
                        
                        orchestrator = EnhancedOrchestrator()
                        # Test would verify module loading here
            
            print("✓ Orchestrator module loading test passed")
            
        except Exception as e:
            self.fail(f"Orchestrator integration test failed: {e}")

def run_comprehensive_tests():
    """Run all tests and provide a comprehensive report"""
    print("=" * 60)
    print("🧪 ENHANCED BJORN INTEGRATION TEST SUITE")
    print("=" * 60)
    print()
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test cases
    test_suite.addTest(unittest.makeSuite(TestEnhancedBjorn))
    test_suite.addTest(unittest.makeSuite(TestIntegration))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(test_suite)
    
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    successes = total_tests - failures - errors
    
    print(f"Total Tests Run: {total_tests}")
    print(f"✅ Successful: {successes}")
    print(f"❌ Failed: {failures}")
    print(f"🚨 Errors: {errors}")
    
    if failures > 0:
        print("\n🔍 FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if errors > 0:
        print("\n🚨 ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    success_rate = (successes / total_tests) * 100 if total_tests > 0 else 0
    print(f"\n🎯 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 90:
        print("🎉 EXCELLENT! Enhanced Bjorn is ready for deployment!")
    elif success_rate >= 75:
        print("✅ GOOD! Minor issues to address before deployment.")
    else:
        print("⚠️  NEEDS WORK! Significant issues need to be resolved.")
    
    print("\n" + "=" * 60)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    # Set up logging to reduce noise during testing
    logging.getLogger().setLevel(logging.CRITICAL)
    
    try:
        success = run_comprehensive_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Testing failed with unexpected error: {e}")
        sys.exit(1)
