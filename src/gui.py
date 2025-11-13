


import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime
from packet_capture import PacketCapture
from threat_detector import ThreatDetector
from secure_communication import SecureServer, SecureClient


class NetworkSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-time Secure Network Traffic Monitor")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.packet_capture = None
        self.threat_detector = ThreatDetector()
        self.server = None
        self.client = None
        
        # State variables
        self.is_capturing = False
        self.packet_count = 0
        self.alert_count = 0
        
        # Setup GUI
        self.setup_ui()
        
        # Register callbacks
        self.threat_detector.add_alert_callback(self.on_alert_received)
    
    def setup_ui(self):
        """Setup the user interface"""
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_monitoring_tab()
        self.create_alerts_tab()
        self.create_communication_tab()
        self.create_statistics_tab()
        
        # Status bar
        self.status_bar = tk.Label(
            self.root,
            text="Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_monitoring_tab(self):
        """Create network monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Network Monitoring")
        
        # Control panel
        control_frame = ttk.LabelFrame(monitor_frame, text="Controls", padding=10)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        # Start/Stop buttons
        self.start_btn = ttk.Button(
            control_frame,
            text="▶ Start Capture",
            command=self.start_capture
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            control_frame,
            text="⏹ Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            control_frame,
            text="Clear",
            command=self.clear_packets
        ).pack(side=tk.LEFT, padx=5)
        
        # Statistics display
        stats_frame = ttk.Frame(control_frame)
        stats_frame.pack(side=tk.RIGHT, padx=20)
        
        self.packet_count_label = ttk.Label(stats_frame, text="Packets: 0")
        self.packet_count_label.pack(side=tk.LEFT, padx=10)
        
        self.threat_count_label = ttk.Label(stats_frame, text="Threats: 0", foreground="red")
        self.threat_count_label.pack(side=tk.LEFT, padx=10)
        
        # Packet display
        packet_frame = ttk.LabelFrame(monitor_frame, text="Captured Packets", padding=5)
        packet_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create treeview
        columns = ('Time', 'Protocol', 'Source', 'Destination', 'Threat Level')
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show='headings', height=15)
        
        # Column headings
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=150)
        
        # Scrollbars
        vsb = ttk.Scrollbar(packet_frame, orient="vertical", command=self.packet_tree.yview)
        hsb = ttk.Scrollbar(packet_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.packet_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        packet_frame.grid_rowconfigure(0, weight=1)
        packet_frame.grid_columnconfigure(0, weight=1)
        
        # Configure row colors
        self.packet_tree.tag_configure('LOW', background='#d4edda')
        self.packet_tree.tag_configure('MEDIUM', background='#fff3cd')
        self.packet_tree.tag_configure('HIGH', background='#f8d7da')
        self.packet_tree.tag_configure('CRITICAL', background='#f5c6cb')
    
    def create_alerts_tab(self):
        """Create security alerts tab"""
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="Security Alerts")
        
        # Alert display
        alert_text_frame = ttk.LabelFrame(alerts_frame, text="Alert Log", padding=5)
        alert_text_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.alert_text = scrolledtext.ScrolledText(
            alert_text_frame,
            wrap=tk.WORD,
            height=20,
            font=('Courier', 10)
        )
        self.alert_text.pack(fill='both', expand=True)
        
        # Configure text tags for colors
        self.alert_text.tag_config('CRITICAL', foreground='red', font=('Courier', 10, 'bold'))
        self.alert_text.tag_config('HIGH', foreground='orange', font=('Courier', 10, 'bold'))
        self.alert_text.tag_config('MEDIUM', foreground='#ff8c00')
        self.alert_text.tag_config('LOW', foreground='blue')
        
        # Control buttons
        btn_frame = ttk.Frame(alerts_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(
            btn_frame,
            text="Clear Alerts",
            command=self.clear_alerts
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="Export Alerts",
            command=self.export_alerts
        ).pack(side=tk.LEFT, padx=5)
    
    def create_communication_tab(self):
        """Create secure communication tab"""
        comm_frame = ttk.Frame(self.notebook)
        self.notebook.add(comm_frame, text="Secure Communication")
        
        # Server section
        server_frame = ttk.LabelFrame(comm_frame, text="Server", padding=10)
        server_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(server_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.server_port = ttk.Entry(server_frame, width=10)
        self.server_port.insert(0, "8443")
        self.server_port.pack(side=tk.LEFT, padx=5)
        
        self.server_start_btn = ttk.Button(
            server_frame,
            text="Start Server",
            command=self.start_server
        )
        self.server_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.server_stop_btn = ttk.Button(
            server_frame,
            text="Stop Server",
            command=self.stop_server,
            state=tk.DISABLED
        )
        self.server_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Client section
        client_frame = ttk.LabelFrame(comm_frame, text="Client", padding=10)
        client_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(client_frame, text="Host:").pack(side=tk.LEFT, padx=5)
        self.client_host = ttk.Entry(client_frame, width=15)
        self.client_host.insert(0, "localhost")
        self.client_host.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(client_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.client_port = ttk.Entry(client_frame, width=10)
        self.client_port.insert(0, "8443")
        self.client_port.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            client_frame,
            text="Connect",
            command=self.connect_client
        ).pack(side=tk.LEFT, padx=5)
        
        # Message section
        msg_frame = ttk.LabelFrame(comm_frame, text="Send Message", padding=10)
        msg_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.message_entry = ttk.Entry(msg_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, fill='x', expand=True, padx=5)
        
        ttk.Button(
            msg_frame,
            text="Send Encrypted",
            command=self.send_message
        ).pack(side=tk.LEFT, padx=5)
        
        # Communication log
        log_frame = ttk.LabelFrame(comm_frame, text="Communication Log", padding=5)
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.comm_log = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=10,
            font=('Courier', 9)
        )
        self.comm_log.pack(fill='both', expand=True)
    
    def create_statistics_tab(self):
        """Create statistics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")
        
        # Packet statistics
        packet_stats_frame = ttk.LabelFrame(stats_frame, text="Packet Statistics", padding=10)
        packet_stats_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(
            packet_stats_frame,
            wrap=tk.WORD,
            height=15,
            font=('Courier', 10)
        )
        self.stats_text.pack(fill='both', expand=True)
        
        # Refresh button
        ttk.Button(
            stats_frame,
            text="Refresh Statistics",
            command=self.update_statistics
        ).pack(pady=5)
    
    # Event handlers
    def start_capture(self):
        """Start packet capture"""
        try:
            self.packet_capture = PacketCapture()
            self.packet_capture.add_callback(self.on_packet_captured)
            
            if self.packet_capture.start_capture():
                self.is_capturing = True
                self.start_btn.config(state=tk.DISABLED)
                self.stop_btn.config(state=tk.NORMAL)
                self.update_status("Capturing packets...")
                self.log_alert("INFO", "Packet capture started")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        if self.packet_capture:
            self.packet_capture.stop_capture()
            self.is_capturing = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.update_status("Capture stopped")
            self.log_alert("INFO", "Packet capture stopped")
    
    def clear_packets(self):
        """Clear packet display"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_count = 0
        self.update_packet_count()
    
    def clear_alerts(self):
        """Clear alert log"""
        self.alert_text.delete(1.0, tk.END)
        self.alert_count = 0
        self.update_threat_count()
    
    def on_packet_captured(self, packet_info):
        """Callback for captured packets"""
        self.packet_count += 1
        
        # Add to treeview
        self.root.after(0, self._add_packet_to_tree, packet_info)
        
        # Analyze for threats
        threats = self.threat_detector.analyze_packet(packet_info)
        
        # Update counts
        self.root.after(0, self.update_packet_count)
    
    def _add_packet_to_tree(self, packet_info):
        """Add packet to treeview (must run in main thread)"""
        values = (
            packet_info.get('timestamp', 'N/A'),
            packet_info.get('protocol', 'N/A'),
            f"{packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', '')}",
            f"{packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', '')}",
            packet_info.get('threat_level', 'LOW')
        )
        
        tag = packet_info.get('threat_level', 'LOW')
        self.packet_tree.insert('', 0, values=values, tags=(tag,))
        
        # Keep only last 1000 packets
        children = self.packet_tree.get_children()
        if len(children) > 1000:
            self.packet_tree.delete(children[-1])
    
    def on_alert_received(self, alert):
        """Callback for new alerts"""
        self.alert_count += 1
        self.root.after(0, self._add_alert_to_log, alert)
        self.root.after(0, self.update_threat_count)
    
    def _add_alert_to_log(self, alert):
        """Add alert to log (must run in main thread)"""
        alert_msg = (
            f"\n{'='*70}\n"
            f"[{alert['severity']}] Alert #{alert['id']} - {alert['timestamp']}\n"
            f"Type: {alert['type']}\n"
            f"Description: {alert['description']}\n"
            f"Source: {alert['source_ip']} → {alert['destination_ip']}\n"
            f"Recommendation: {alert['recommendation']}\n"
            f"{'='*70}\n"
        )
        
        self.alert_text.insert(tk.END, alert_msg, alert['severity'])
        self.alert_text.see(tk.END)
    
    def log_alert(self, severity, message):
        """Log a simple alert message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [{severity}] {message}\n"
        self.alert_text.insert(tk.END, log_msg, severity)
        self.alert_text.see(tk.END)
    
    def update_packet_count(self):
        """Update packet count label"""
        self.packet_count_label.config(text=f"Packets: {self.packet_count}")
    
    def update_threat_count(self):
        """Update threat count label"""
        self.threat_count_label.config(text=f"Threats: {self.alert_count}")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=message)
    
    def start_server(self):
        """Start secure server"""
        try:
            port = int(self.server_port.get())
            self.server = SecureServer(port=port)
            
            # Start in separate thread
            server_thread = threading.Thread(target=self.server.start, daemon=True)
            server_thread.start()
            
            self.server_start_btn.config(state=tk.DISABLED)
            self.server_stop_btn.config(state=tk.NORMAL)
            self.comm_log.insert(tk.END, f"Server started on port {port}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")
    
    def stop_server(self):
        """Stop secure server"""
        if self.server:
            self.server.stop()
            self.server_start_btn.config(state=tk.NORMAL)
            self.server_stop_btn.config(state=tk.DISABLED)
            self.comm_log.insert(tk.END, "Server stopped\n")
    
    def connect_client(self):
        """Connect client to server"""
        try:
            host = self.client_host.get()
            port = int(self.client_port.get())
            
            self.client = SecureClient(host=host, port=port)
            
            if self.client.connect():
                self.comm_log.insert(tk.END, f"Connected to {host}:{port}\n")
            else:
                messagebox.showerror("Error", "Failed to connect to server")
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")
    
    def send_message(self):
        """Send encrypted message"""
        if not self.client or not self.client.is_connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
        
        message = self.message_entry.get()
        if message:
            if self.client.send_encrypted(message):
                self.comm_log.insert(tk.END, f"Sent: {message}\n")
                self.message_entry.delete(0, tk.END)
                
                # Receive response in separate thread
                threading.Thread(target=self.receive_response, daemon=True).start()
    
    def receive_response(self):
        """Receive server response"""
        if self.client:
            response = self.client.receive_encrypted()
            if response:
                self.root.after(0, self.comm_log.insert, tk.END, f"Received: {response}\n")
    
    def update_statistics(self):
        """Update statistics display"""
        self.stats_text.delete(1.0, tk.END)
        
        # Packet statistics
        if self.packet_capture:
            packet_stats = self.packet_capture.get_statistics()
            self.stats_text.insert(tk.END, "=== Packet Statistics ===\n\n")
            for key, value in packet_stats.items():
                self.stats_text.insert(tk.END, f"{key.upper()}: {value}\n")
        
        # Threat statistics
        threat_stats = self.threat_detector.get_statistics()
        self.stats_text.insert(tk.END, "\n=== Threat Statistics ===\n\n")
        for key, value in threat_stats.items():
            self.stats_text.insert(tk.END, f"{key}: {value}\n")
    
    def export_alerts(self):
        """Export alerts to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_alerts_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(self.alert_text.get(1.0, tk.END))
            
            messagebox.showinfo("Success", f"Alerts exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")


# Main application
def main():
    root = tk.Tk()
    app = NetworkSecurityGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()