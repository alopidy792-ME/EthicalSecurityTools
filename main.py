import argparse
import sys
from EthicalSecurityTools.tools.file_monitor import FileMonitor
from EthicalSecurityTools.tools.malware_detector import MalwareDetector
from EthicalSecurityTools.tools.network_analyzer import NetworkAnalyzer
from EthicalSecurityTools.tools.vulnerability_scanner import VulnerabilityScanner
from EthicalSecurityTools.tools.password_cracker import PasswordCracker

def main():
    parser = argparse.ArgumentParser(
        description="Ethical Security Tools Suite",
        epilog="Use 'python main.py <tool_name> --help' for specific tool options."
    )
    parser.add_argument("tool", help="Tool to run (filemon, malware, network, vuln, crack)")
    
    # Parse the main arguments first to determine which tool to run
    args, remaining_args = parser.parse_known_args()
    
    if args.tool == "filemon":
        filemon_parser = argparse.ArgumentParser(
            description="File Integrity Monitor - Track changes to critical files"
        )
        filemon_parser.add_argument("path", help="Path to file or directory to monitor")
        filemon_parser.add_argument("-i", "--interval", type=int, default=10,
                                  help="Monitoring interval in seconds (default: 10)")
        filemon_args = filemon_parser.parse_args(remaining_args)
        
        monitor = FileMonitor(filemon_args.path)
        if monitor.create_baseline():
            monitor.monitor(filemon_args.interval)
            
    elif args.tool == "malware":
        malware_parser = argparse.ArgumentParser(
            description="Malware Detector - Scan files for malware using YARA rules"
        )
        malware_parser.add_argument("path", help="Path to file or directory to scan")
        malware_parser.add_argument("--rules", required=True, help="Path to YARA rules file")
        malware_parser.add_argument("--output", default="json", choices=["json", "txt"],
                                  help="Output format for scan results (default: json)")
        malware_args = malware_parser.parse_args(remaining_args)
        
        try:
            detector = MalwareDetector(malware_args.rules)
            if Path(malware_args.path).is_file():
                is_infected, result = detector.scan_file(Path(malware_args.path))
                if is_infected:
                    detector.export_results([result], malware_args.output)
            elif Path(malware_args.path).is_dir():
                infected_files = detector.scan_directory(Path(malware_args.path))
                if infected_files:
                    detector.export_results(infected_files, malware_args.output)
            else:
                detector.log(f"Invalid path: {malware_args.path}", "ERROR")
            detector.generate_report()
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            
    elif args.tool == "network":
        network_parser = argparse.ArgumentParser(
            description="Network Analyzer - Scan network and sniff packets"
        )
        network_parser.add_argument("--scan", help="IP range to scan (e.g., 192.168.1.1/24)")
        network_parser.add_argument("--sniff", help="Network interface to sniff packets from (e.g., eth0)")
        network_parser.add_argument("--count", type=int, default=10, help="Number of packets to sniff (default: 10)")
        network_args = network_parser.parse_args(remaining_args)
        
        analyzer = NetworkAnalyzer()
        if network_args.scan:
            clients = analyzer.scan_network(network_args.scan)
            if clients:
                print("\nDetected Devices:")
                for client in clients:
                    print(f"IP: {client["ip"]}\tMAC: {client["mac"]}")
        if network_args.sniff:
            packets = analyzer.sniff_packets(network_args.sniff, network_args.count)
            if packets:
                print("\nAnalyzing Sniffed Packets:")
                for packet in packets:
                    analyzer.analyze_packet(packet)
                    
    elif args.tool == "vuln":
        vuln_parser = argparse.ArgumentParser(
            description="Vulnerability Scanner - Scan for common web vulnerabilities and open ports"
        )
        vuln_parser.add_argument("--target", required=True, help="Target host (IP or URL)")
        vuln_parser.add_argument("--scan-ports", action="store_true", help="Scan common ports")
        vuln_parser.add_argument("--check-xss", action="store_true", help="Check for XSS vulnerability")
        vuln_parser.add_argument("--check-sqli", action="store_true", help="Check for SQL Injection vulnerability")
        vuln_args = vuln_parser.parse_args(remaining_args)
        
        scanner = VulnerabilityScanner()
        if vuln_args.scan_ports:
            scanner.scan_common_ports(vuln_args.target)
        if vuln_args.check_xss:
            scanner.check_xss(vuln_args.target)
        if vuln_args.check_sqli:
            scanner.check_sql_injection(vuln_args.target)
            
    elif args.tool == "crack":
        crack_parser = argparse.ArgumentParser(
            description="Password Cracker - Perform brute-force or dictionary attacks"
        )
        crack_parser.add_argument("--hash", required=True, help="Hashed password to crack")
        crack_parser.add_argument("--type", default="sha256", choices=["md5", "sha1", "sha256", "sha512"], help="Hash type (default: sha256)")
        
        group = crack_parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--bruteforce", action="store_true", help="Perform brute-force attack")
        group.add_argument("--dictionary", help="Path to dictionary file for dictionary attack")
        
        crack_parser.add_argument("--charset", default="lower", choices=["lower", "upper", "digits", "all"],
                                  help="Character set for brute-force (lower, upper, digits, all)")
        crack_parser.add_argument("--max-length", type=int, default=4, help="Max length for brute-force (default: 4)")
        crack_args = crack_parser.parse_args(remaining_args)
        
        cracker = PasswordCracker()
        charset_map = {
            "lower": "abcdefghijklmnopqrstuvwxyz",
            "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "digits": "0123456789",
            "all": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        }
        
        if crack_args.bruteforce:
            cracker.crack_bruteforce(crack_args.hash, crack_args.type, charset_map[crack_args.charset], crack_args.max_length)
        elif crack_args.dictionary:
            cracker.crack_dictionary(crack_args.hash, crack_args.type, crack_args.dictionary)
            
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()


