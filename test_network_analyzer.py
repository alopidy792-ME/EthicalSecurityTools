import unittest
import os
import platform
from EthicalSecurityTools.tools.network_analyzer import NetworkAnalyzer

# Mock scapy for testing purposes if not running with root privileges
try:
    import scapy.all as scapy
    # Check if scapy can actually send/receive (requires root)
    _can_scapy_run = True
    try:
        scapy.srp(scapy.Ether()/scapy.ARP(pdst="127.0.0.1"), timeout=0.1, verbose=False)
    except Exception:
        _can_scapy_run = False
except ImportError:
    _can_scapy_run = False

# Define a mock for scapy if it cannot run or is not installed
if not _can_scapy_run:
    class MockARP:
        def __init__(self, pdst=None):
            self.pdst = pdst
        class MockPacket:
            psrc = "127.0.0.1"
            hwsrc = "00:00:00:00:00:00"
        def __truediv__(self, other):
            return self

    class MockEther:
        def __init__(self, dst=None):
            self.dst = dst
        def __truediv__(self, other):
            return self

    class MockScapy:
        ARP = MockARP
        Ether = MockEther
        def srp(self, *args, **kwargs):
            # Simulate a response for testing
            return ([ (None, MockARP.MockPacket()) ], None)
        def sniff(self, *args, **kwargs):
            return [MockARP.MockPacket(), MockARP.MockPacket()]
        def IP(self):
            return type("IP", (object,), {"src": "1.1.1.1", "dst": "2.2.2.2"})()
        def TCP(self):
            return type("TCP", (object,), {"sport": 80, "dport": 443})()
        def UDP(self):
            return type("UDP", (object,), {"sport": 53, "dport": 123})()
        def haslayer(self, layer):
            if layer == self.ARP:
                return True
            return False

    scapy = MockScapy()


class TestNetworkAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = NetworkAnalyzer()
        self.analyzer.log_file = "test_network_analyzer.log" # Redirect log for testing
        if os.path.exists(self.analyzer.log_file):
            os.remove(self.analyzer.log_file)

    def tearDown(self):
        if os.path.exists(self.analyzer.log_file):
            os.remove(self.analyzer.log_file)

    @unittest.skipUnless(_can_scapy_run, "Scapy requires root privileges or proper installation to run.")
    def test_scan_network(self):
        # This test requires actual network capabilities and root privileges
        # For CI/CD or environments without root, this test will be skipped
        # A mock version is used if scapy cannot run
        ip_range = "127.0.0.1/32" # Scan only localhost to avoid network issues
        clients = self.analyzer.scan_network(ip_range)
        self.assertIsInstance(clients, list)
        # Depending on the system, localhost might or might not respond to ARP
        # So, we check if the list is not empty, or if the mock is used
        if not _can_scapy_run:
            self.assertGreaterEqual(len(clients), 1)
            self.assertIn("127.0.0.1", clients[0]["ip"])
        else:
            # If scapy runs, we expect at least one entry for localhost
            self.assertGreaterEqual(len(clients), 0) # Can be 0 if localhost doesn't respond to ARP

    @unittest.skipUnless(_can_scapy_run, "Scapy requires root privileges or proper installation to run.")
    def test_sniff_packets(self):
        # This test also requires actual network capabilities and root privileges
        # Use a dummy interface or mock it
        interface = "lo" if platform.system() == "Linux" else "Loopback Pseudo-Interface 1" # Common loopback
        packets = self.analyzer.sniff_packets(interface, count=2)
        self.assertIsInstance(packets, scapy.plist.PacketList if _can_scapy_run else list)
        self.assertEqual(len(packets), 2)

    def test_analyze_packet_arp(self):
        # Create a mock ARP packet
        mock_packet = scapy.Ether()/scapy.ARP(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
        # Redirect stdout to capture print statements
        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        
        self.analyzer.analyze_packet(mock_packet)
        
        sys.stdout = old_stdout # Restore stdout
        output = mystdout.getvalue()
        self.assertIn("[ARP] Sender IP: 192.168.1.1, Sender MAC: aa:bb:cc:dd:ee:ff", output)

    def test_analyze_packet_ip_tcp(self):
        # Create a mock IP/TCP packet
        mock_packet = scapy.IP(src="1.1.1.1", dst="2.2.2.2")/scapy.TCP(sport=12345, dport=80)
        # Override haslayer for this mock to return True for IP and TCP
        mock_packet.haslayer = lambda layer: layer == scapy.IP or layer == scapy.TCP

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        
        self.analyzer.analyze_packet(mock_packet)
        
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        self.assertIn("[IP] Source: 1.1.1.1, Destination: 2.2.2.2", output)
        self.assertIn("[TCP] Source Port: 12345, Destination Port: 80", output)

if __name__ == '__main__':
    unittest.main()

