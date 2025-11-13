"""
Packet Capture Module - Network Traffic Monitoring
Uses Scapy for packet capture and analysis
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from scapy.layers.http import HTTPRequest
import threading
from datetime import datetime
from collections import defaultdict


class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        self.is_capturing = False
        self.packets = []
        self.packet_stats = defaultdict(int)
        self.suspicious_ips = set()
        self.callbacks = []
        
    def start_capture(self, packet_count=0, timeout=None, filter_str=None):
        """Start capturing packets"""
        self.is_capturing = True
        print(f"[*] Starting packet capture on interface: {self.interface or 'default'}")
        
        try:
            # Start sniffing in a separate thread
            capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(packet_count, timeout, filter_str),
                daemon=True
            )
            capture_thread.start()
            return True
        except Exception as e:
            print(f"[✗] Error starting capture: {e}")
            self.is_capturing = False
            return False
    
    def _capture_packets(self, packet_count, timeout, filter_str):
        """Internal packet capture function"""
        try:
            sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                count=packet_count if packet_count > 0 else 0,
                timeout=timeout,
                filter=filter_str,
                store=False
            )
        except Exception as e:
            print(f"[✗] Capture error: {e}")
        finally:
            self.is_capturing = False
            print("[*] Packet capture stopped")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        print("[*] Stopping packet capture...")
    
    def analyze_packet(self, packet):
        """Analyze captured packet for security threats"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            packet_info = {
                'timestamp': timestamp,
                'size': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'threat_level': 'LOW',
                'details': []
            }
            
            # IP Layer Analysis
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                self.packet_stats['total'] += 1
            
            # TCP Analysis
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                self.packet_stats['tcp'] += 1
                
                # Check for common unsecured ports
                self._check_insecure_ports(packet_info, packet[TCP].dport)
            
            # UDP Analysis
            if UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                self.packet_stats['udp'] += 1
            
            # HTTP Analysis (Unsecured)
            if packet.haslayer(HTTPRequest):
                packet_info['protocol'] = 'HTTP'
                packet_info['threat_level'] = 'HIGH'
                packet_info['details'].append('UNSECURED HTTP TRAFFIC DETECTED')
                self.packet_stats['http'] += 1
                
                http_layer = packet[HTTPRequest]
                if http_layer.Host and http_layer.Path:
                    url = f"http://{http_layer.Host.decode()}{http_layer.Path.decode()}"
                    packet_info['details'].append(f'URL: {url}')
            
            # DNS Analysis
            if DNS in packet and packet.haslayer(DNSQR):
                packet_info['protocol'] = 'DNS'
                query = packet[DNSQR].qname.decode()
                packet_info['details'].append(f'DNS Query: {query}')
                self.packet_stats['dns'] += 1
            
            # Check for suspicious patterns
            self._detect_suspicious_activity(packet_info, packet)
            
            # Store packet info
            self.packets.append(packet_info)
            
            # Notify callbacks
            for callback in self.callbacks:
                callback(packet_info)
            
            # Print summary (optional, can be removed for performance)
            if packet_info['threat_level'] in ['MEDIUM', 'HIGH', 'CRITICAL']:
                self._print_packet_summary(packet_info)
                
        except Exception as e:
            print(f"[✗] Error analyzing packet: {e}")
    
    def _check_insecure_ports(self, packet_info, port):
        """Check for commonly insecured protocols"""
        insecure_ports = {
            21: 'FTP (Unsecured)',
            23: 'Telnet (Unsecured)',
            80: 'HTTP (Unsecured)',
            110: 'POP3 (Unsecured)',
            143: 'IMAP (Unsecured)',
            8080: 'HTTP Proxy (Unsecured)'
        }
        
        if port in insecure_ports:
            packet_info['threat_level'] = 'MEDIUM'
            packet_info['details'].append(f'Insecure Protocol: {insecure_ports[port]}')
    
    def _detect_suspicious_activity(self, packet_info, packet):
        """Detect suspicious patterns in packets"""
        
        # Check for port scanning (multiple connections to different ports)
        if packet_info['src_ip']:
            # This is a simplified check - in production, implement rate limiting
            pass
        
        # Check for unusual payload patterns
        if Raw in packet:
            payload = packet[Raw].load
            
            # Check for common attack patterns
            suspicious_patterns = [b'eval(', b'exec(', b'system(', b'SELECT', b'UNION']
            for pattern in suspicious_patterns:
                if pattern in payload:
                    packet_info['threat_level'] = 'HIGH'
                    packet_info['details'].append('Potential injection attack detected')
                    break
        
        # Flag high-threat packets
        if packet_info['threat_level'] == 'HIGH':
            if packet_info['src_ip']:
                self.suspicious_ips.add(packet_info['src_ip'])
    
    def _print_packet_summary(self, packet_info):
        """Print packet summary for high-threat packets"""
        print(f"\n[⚠] {packet_info['threat_level']} THREAT DETECTED")
        print(f"    Time: {packet_info['timestamp']}")
        print(f"    Protocol: {packet_info['protocol']}")
        print(f"    {packet_info['src_ip']}:{packet_info['src_port']} -> "
              f"{packet_info['dst_ip']}:{packet_info['dst_port']}")
        for detail in packet_info['details']:
            print(f"    • {detail}")
    
    def add_callback(self, callback):
        """Add callback function to be called for each packet"""
        self.callbacks.append(callback)
    
    def get_statistics(self):
        """Get capture statistics"""
        return dict(self.packet_stats)
    
    def get_suspicious_ips(self):
        """Get list of suspicious IP addresses"""
        return list(self.suspicious_ips)
    
    def get_recent_packets(self, count=10):
        """Get recent captured packets"""
        return self.packets[-count:]
    
    def clear_packets(self):
        """Clear stored packets"""
        self.packets = []
        self.packet_stats = defaultdict(int)
        self.suspicious_ips = set()
        print("[*] Packet history cleared")


# Testing function
if __name__ == "__main__":
    print("=== Testing Packet Capture Module ===\n")
    print("[!] Note: You may need administrator/root privileges")
    print("[!] This will capture real network traffic\n")
    
    def packet_callback(packet_info):
        """Callback for displaying packets"""
        if packet_info['threat_level'] != 'LOW':
            print(f"[{packet_info['threat_level']}] {packet_info['protocol']} "
                  f"{packet_info['src_ip']} -> {packet_info['dst_ip']}")
    
    capture = PacketCapture()
    capture.add_callback(packet_callback)
    
    print("Starting 30-second capture...")
    capture.start_capture(timeout=30)
    
    import time
    time.sleep(31)
    
    print("\n=== Capture Statistics ===")
    stats = capture.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\n=== Suspicious IPs ===")
    suspicious = capture.get_suspicious_ips()
    if suspicious:
        for ip in suspicious:
            print(f"• {ip}")
    else:
        print("No suspicious IPs detected")