#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
محلل الشبكة - Network Analyzer
إصدار: 2.0
"""

import scapy.all as scapy
import platform
import time
from colorama import init, Fore

init() # تهيئة colorama

class NetworkAnalyzer:
    def __init__(self):
        self.log_file = "network_analyzer.log"
        self.os_type = platform.system()
        self.log("Network Analyzer initialized", "INFO")

    def scan_network(self, ip_range):
        """
        مسح الشبكة لاكتشاف الأجهزة المتصلة
        :param ip_range: نطاق IP للمسح (مثال: "192.168.1.1/24")
        :return: قائمة بقواميس تحتوي على IP و MAC لكل جهاز
        """
        self.log(f"Scanning network range: {ip_range}", "INFO")
        try:
            # إنشاء حزمة ARP تطلب عنوان MAC لعنوان IP معين
            arp_request = scapy.ARP(pdst=ip_range)
            # إنشاء حزمة إيثرنت لبث حزمة ARP
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            # دمج الحزمتين
            arp_request_broadcast = broadcast / arp_request
            
            # إرسال الحزم واستقبال الردود
            # timeout: الانتظار لمدة ثانية واحدة لكل حزمة
            # verbose: عدم إظهار التفاصيل على الشاشة
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            clients_list = []
            for element in answered_list:
                client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                clients_list.append(client_dict)
            
            self.log(f"Found {len(clients_list)} devices in {ip_range}", "SUCCESS")
            return clients_list
        except PermissionError:
            self.log("Permission denied. Run with sudo/Administrator privileges.", "ERROR")
            return []
        except Exception as e:
            self.log(f"Error during network scan: {str(e)}", "ERROR")
            return []

    def sniff_packets(self, interface, count=10):
        """
        التقاط عدد محدد من الحزم من واجهة شبكة معينة
        :param interface: الواجهة الشبكية للمراقبة (مثال: "eth0", "Wi-Fi")
        :param count: عدد الحزم المراد التقاطها
        :return: قائمة بالحزم الملتقطة
        """
        self.log(f"Sniffing {count} packets on interface {interface}", "INFO")
        try:
            packets = scapy.sniff(iface=interface, store=True, count=count)
            self.log(f"Successfully sniffed {len(packets)} packets", "SUCCESS")
            return packets
        except Exception as e:
            self.log(f"Error sniffing packets: {str(e)}", "ERROR")
            return []

    def analyze_packet(self, packet):
        """
        تحليل حزمة شبكة واحدة وعرض معلوماتها
        :param packet: الحزمة المراد تحليلها
        """
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            self.log(f"[IP] Source: {ip_layer.src}, Destination: {ip_layer.dst}", "INFO")
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                self.log(f"[TCP] Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}", "INFO")
            elif packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]
                self.log(f"[UDP] Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}", "INFO")
        elif packet.haslayer(scapy.ARP):
            arp_layer = packet[scapy.ARP]
            self.log(f"[ARP] Sender IP: {arp_layer.psrc}, Sender MAC: {arp_layer.hwsrc}", "INFO")
        else:
            self.log("Unknown packet type", "INFO")

    def log(self, message, level="INFO"):
        """تسجيل الأحداث مع تصنيف مستوى الخطورة"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        colors = {
            "INFO": Fore.BLUE,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "SUCCESS": Fore.GREEN
        }
        
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        print(colors.get(level, Fore.WHITE) + log_entry + Fore.RESET)
        
        with open(self.log_file, "a", encoding=\'utf-8\') as f:
            f.write(log_entry + "\n")

def check_os_compatibility():
    """التحقق من توافق النظام"""
    system = platform.system()
    if system not in [\'Linux\', \'Windows\']:
        print(Fore.YELLOW + "Warning: This tool is primarily tested on Linux and Windows" + Fore.RESET)

if __name__ == "__main__":
    import argparse
    
    check_os_compatibility()
    
    parser = argparse.ArgumentParser(
        description="Network Analyzer - Scan network and sniff packets",
        epilog="Example: python network_analyzer.py --scan 192.168.1.1/24"
    )
    parser.add_argument("--scan", help="IP range to scan (e.g., 192.168.1.1/24)")
    parser.add_argument("--sniff", help="Network interface to sniff packets from (e.g., eth0)")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to sniff (default: 10)")
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer()
    
    if args.scan:
        clients = analyzer.scan_network(args.scan)
        if clients:
            print(Fore.GREEN + "\nDetected Devices:" + Fore.RESET)
            for client in clients:
                print(f"IP: {client[\'ip\']}\tMAC: {client[\'mac\']}")
    
    if args.sniff:
        packets = analyzer.sniff_packets(args.sniff, args.count)
        if packets:
            print(Fore.GREEN + "\nAnalyzing Sniffed Packets:" + Fore.RESET)
            for packet in packets:
                analyzer.analyze_packet(packet)



