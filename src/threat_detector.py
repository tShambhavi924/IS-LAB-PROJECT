"""
Threat Detector Module - Real-time Alert System
Analyzes network traffic patterns and generates alerts
"""

from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
import time


class ThreatDetector:
    def __init__(self):
        self.alerts = []
        self.alert_callbacks = []
        self.connection_tracker = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_threshold = 10  # ports per second
        self.syn_flood_threshold = 50  # SYN packets per second
        self.suspicious_domains = set()
        self.blocked_ips = set()
        self.alert_history = defaultdict(list)
        
        # Known malicious patterns
        self.malicious_patterns = {
            'sql_injection': [b'SELECT', b'UNION', b'DROP TABLE', b"' OR '1'='1"],
            'xss': [b'<script>', b'javascript:', b'onerror='],
            'command_injection': [b'eval(', b'exec(', b'system(', b'passthru'],
            'path_traversal': [b'../', b'..\\', b'%2e%2e%2f']
        }
        
        # Start monitoring thread
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_threats, daemon=True)
        self.monitor_thread.start()
    
    def analyze_packet(self, packet_info):
        """Analyze packet for security threats"""
        threats_detected = []
        
        # Check for unsecured protocols
        threat = self._check_unsecured_protocol(packet_info)
        if threat:
            threats_detected.append(threat)
        
        # Check for port scanning
        threat = self._check_port_scan(packet_info)
        if threat:
            threats_detected.append(threat)
        
        # Check for suspicious payloads
        threat = self._check_malicious_payload(packet_info)
        if threat:
            threats_detected.append(threat)
        
        # Check for DoS patterns
        threat = self._check_dos_pattern(packet_info)
        if threat:
            threats_detected.append(threat)
        
        # Generate alerts for detected threats
        for threat in threats_detected:
            self._generate_alert(threat, packet_info)
        
        return threats_detected
    
    def _check_unsecured_protocol(self, packet_info):
        """Detect unsecured protocol usage"""
        unsecured_protocols = {
            'HTTP': 'HIGH',
            'FTP': 'HIGH',
            'Telnet': 'CRITICAL',
            'SMTP': 'MEDIUM',
            'POP3': 'MEDIUM',
            'IMAP': 'MEDIUM'
        }
        
        protocol = packet_info.get('protocol', '')
        
        for unsecured, severity in unsecured_protocols.items():
            if unsecured in protocol.upper():
                return {
                    'type': 'UNSECURED_PROTOCOL',
                    'severity': severity,
                    'description': f'Unsecured {unsecured} protocol detected',
                    'recommendation': f'Use secured alternative (HTTPS, SFTP, SSH, etc.)'
                }
        
        # Check specific ports
        dst_port = packet_info.get('dst_port')
        if dst_port:
            if dst_port == 21:
                return {
                    'type': 'UNSECURED_PROTOCOL',
                    'severity': 'HIGH',
                    'description': 'FTP connection detected (port 21)',
                    'recommendation': 'Use SFTP (port 22) or FTPS (port 990)'
                }
            elif dst_port == 23:
                return {
                    'type': 'UNSECURED_PROTOCOL',
                    'severity': 'CRITICAL',
                    'description': 'Telnet connection detected (port 23)',
                    'recommendation': 'Use SSH (port 22) instead'
                }
        
        return None
    
    def _check_port_scan(self, packet_info):
        """Detect port scanning attempts"""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        
        if not src_ip or not dst_port:
            return None
        
        # Track connection attempts
        current_time = datetime.now()
        self.connection_tracker[src_ip].append({
            'port': dst_port,
            'time': current_time
        })
        
        # Check for port scan pattern
        recent_connections = [
            conn for conn in self.connection_tracker[src_ip]
            if current_time - conn['time'] < timedelta(seconds=5)
        ]
        
        unique_ports = len(set(conn['port'] for conn in recent_connections))
        
        if unique_ports > self.port_scan_threshold:
            return {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'description': f'Port scan detected from {src_ip} ({unique_ports} ports in 5 seconds)',
                'recommendation': 'Block source IP and investigate'
            }
        
        return None
    
    def _check_malicious_payload(self, packet_info):
        """Check for malicious patterns in packet payload"""
        details = packet_info.get('details', [])
        
        # This is simplified - in production, you'd inspect actual payload
        for detail in details:
            detail_lower = str(detail).lower()
            
            # Check for SQL injection
            if any(pattern.decode().lower() in detail_lower 
                   for pattern in self.malicious_patterns['sql_injection']):
                return {
                    'type': 'SQL_INJECTION',
                    'severity': 'CRITICAL',
                    'description': 'Potential SQL injection attempt detected',
                    'recommendation': 'Block connection and review application security'
                }
            
            # Check for XSS
            if any(pattern.decode().lower() in detail_lower 
                   for pattern in self.malicious_patterns['xss']):
                return {
                    'type': 'XSS_ATTEMPT',
                    'severity': 'HIGH',
                    'description': 'Potential XSS attack detected',
                    'recommendation': 'Sanitize input and implement CSP'
                }
            
            # Check for command injection
            if any(pattern.decode().lower() in detail_lower 
                   for pattern in self.malicious_patterns['command_injection']):
                return {
                    'type': 'COMMAND_INJECTION',
                    'severity': 'CRITICAL',
                    'description': 'Potential command injection attempt',
                    'recommendation': 'Block immediately and patch vulnerable code'
                }
        
        return None
    
    def _check_dos_pattern(self, packet_info):
        """Detect potential DoS/DDoS patterns"""
        src_ip = packet_info.get('src_ip')
        
        if not src_ip:
            return None
        
        # Track packet rate from source
        current_time = datetime.now()
        recent_packets = [
            conn for conn in self.connection_tracker[src_ip]
            if current_time - conn['time'] < timedelta(seconds=1)
        ]
        
        if len(recent_packets) > self.syn_flood_threshold:
            return {
                'type': 'DOS_ATTACK',
                'severity': 'CRITICAL',
                'description': f'Potential DoS attack from {src_ip} ({len(recent_packets)} packets/sec)',
                'recommendation': 'Enable rate limiting and block source'
            }
        
        return None
    
    def _generate_alert(self, threat, packet_info):
        """Generate and store security alert"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'type': threat['type'],
            'severity': threat['severity'],
            'description': threat['description'],
            'recommendation': threat['recommendation'],
            'source_ip': packet_info.get('src_ip', 'Unknown'),
            'destination_ip': packet_info.get('dst_ip', 'Unknown'),
            'protocol': packet_info.get('protocol', 'Unknown'),
            'acknowledged': False
        }
        
        # Avoid duplicate alerts
        if not self._is_duplicate_alert(alert):
            self.alerts.append(alert)
            self.alert_history[threat['type']].append(datetime.now())
            
            # Print alert
            self._print_alert(alert)
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                callback(alert)
    
    def _is_duplicate_alert(self, new_alert):
        """Check if similar alert was recently generated"""
        recent_time = datetime.now() - timedelta(seconds=10)
        
        for alert in self.alerts[-10:]:  # Check last 10 alerts
            if (alert['type'] == new_alert['type'] and
                alert['source_ip'] == new_alert['source_ip'] and
                alert['severity'] == new_alert['severity']):
                alert_time = datetime.strptime(alert['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
                if alert_time > recent_time:
                    return True
        
        return False
    
    def _print_alert(self, alert):
        """Print formatted alert"""
        severity_colors = {
            'LOW': '🟢',
            'MEDIUM': '🟡',
            'HIGH': '🟠',
            'CRITICAL': '🔴'
        }
        
        icon = severity_colors.get(alert['severity'], '⚪')
        
        print(f"\n{'='*70}")
        print(f"{icon} SECURITY ALERT #{alert['id']} - {alert['severity']}")
        print(f"{'='*70}")
        print(f"Time: {alert['timestamp']}")
        print(f"Type: {alert['type']}")
        print(f"Description: {alert['description']}")
        print(f"Source: {alert['source_ip']} → {alert['destination_ip']}")
        print(f"Protocol: {alert['protocol']}")
        print(f"\n💡 Recommendation: {alert['recommendation']}")
        print(f"{'='*70}\n")
    
    def _monitor_threats(self):
        """Background thread to monitor threat patterns"""
        while self.is_monitoring:
            try:
                # Check for sustained attack patterns
                self._check_sustained_attacks()
                time.sleep(5)
            except Exception as e:
                print(f"[✗] Monitoring error: {e}")
    
    def _check_sustained_attacks(self):
        """Check for sustained attack patterns over time"""
        recent_time = datetime.now() - timedelta(minutes=5)
        
        for threat_type, timestamps in self.alert_history.items():
            recent_alerts = [t for t in timestamps if t > recent_time]
            
            if len(recent_alerts) > 20:  # More than 20 alerts of same type
                print(f"\n⚠️  SUSTAINED ATTACK DETECTED: {threat_type}")
                print(f"   {len(recent_alerts)} incidents in last 5 minutes")
                print(f"   Consider implementing automated blocking\n")
    
    def add_alert_callback(self, callback):
        """Register callback for new alerts"""
        self.alert_callbacks.append(callback)
    
    def get_alerts(self, severity=None, limit=None):
        """Get alerts, optionally filtered by severity"""
        filtered_alerts = self.alerts
        
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
        
        if limit:
            filtered_alerts = filtered_alerts[-limit:]
        
        return filtered_alerts
    
    def acknowledge_alert(self, alert_id):
        """Mark alert as acknowledged"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                return True
        return False
    
    def get_statistics(self):
        """Get threat statistics"""
        stats = {
            'total_alerts': len(self.alerts),
            'critical': len([a for a in self.alerts if a['severity'] == 'CRITICAL']),
            'high': len([a for a in self.alerts if a['severity'] == 'HIGH']),
            'medium': len([a for a in self.alerts if a['severity'] == 'MEDIUM']),
            'low': len([a for a in self.alerts if a['severity'] == 'LOW']),
            'unacknowledged': len([a for a in self.alerts if not a['acknowledged']]),
            'threat_types': dict((k, len(v)) for k, v in self.alert_history.items())
        }
        return stats
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.is_monitoring = False


# Testing
if __name__ == "__main__":
    print("=== Testing Threat Detector Module ===\n")
    
    detector = ThreatDetector()
    
    # Simulate various threats
    test_packets = [
        {
            'protocol': 'HTTP',
            'src_ip': '192.168.1.100',
            'dst_ip': '93.184.216.34',
            'dst_port': 80,
            'details': ['URL: http://example.com/login']
        },
        {
            'protocol': 'TCP',
            'src_ip': '10.0.0.50',
            'dst_ip': '192.168.1.1',
            'dst_port': 22,
            'details': ["SELECT * FROM users WHERE '1'='1"]
        },
        {
            'protocol': 'TCP',
            'src_ip': '172.16.0.10',
            'dst_ip': '192.168.1.1',
            'dst_port': 23,
            'details': []
        }
    ]
    
    for packet in test_packets:
        threats = detector.analyze_packet(packet)
        time.sleep(1)
    
    print("\n=== Threat Statistics ===")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    detector.stop_monitoring()