
import sys
import os
import argparse
import tkinter as tk
from pathlib import Path


sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gui import NetworkSecurityGUI
from secure_communication import SecureServer, SecureClient
from ssl_handler import SSLHandler
import config


def setup_environment():
    """Setup necessary directories and files"""
    print("=== Setting Up Environment ===\n")
    
   
    directories = [
        config.SSL_CERT_DIR,
        config.LOG_DIR,
        config.EXPORT_DIR,
        'src'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"[✓] Directory created/verified: {directory}")
    
   
    ssl_handler = SSLHandler(config.SSL_CERT_DIR)
    ssl_handler.setup_certificates()
    
    print("\n[✓] Environment setup complete\n")


def run_gui():
    """Run the GUI application"""
    print("=== Starting GUI Application ===\n")
    
    
    if os.name != 'nt':  
        if os.geteuid() != 0:
            print("[!] Warning: Packet capture requires root/administrator privileges")
            print("[!] Some features may not work without proper permissions")
            print("[!] Run with: sudo python main.py --gui\n")
    
    root = tk.Tk()
    app = NetworkSecurityGUI(root)
    
    print("[✓] GUI application started")
    print("[*] Close the window to exit\n")
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\n[*] Application terminated by user")


def run_server(host, port):
    """Run the secure server"""
    print(f"=== Starting Secure Server ===\n")
    print(f"[*] Server will run on {host}:{port}")
    print("[*] Press Ctrl+C to stop\n")
    
    server = SecureServer(host=host, port=port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        server.stop()
        print("[✓] Server stopped")


def run_client(host, port):
    """Run the secure client"""
    print(f"=== Starting Secure Client ===\n")
    
    client = SecureClient(host=host, port=port)
    
    if not client.connect():
        print("[✗] Failed to connect to server")
        return
    
    print("\n[*] Connected! Type your messages (or 'quit' to exit):\n")
    
    try:
        while True:
            message = input("You: ").strip()
            
            if message.lower() in ['quit', 'exit', 'q']:
                break
            
            if message:
                if client.send_encrypted(message):
                    response = client.receive_encrypted()
                    if response:
                        print(f"Server: {response}\n")
    
    except KeyboardInterrupt:
        print("\n[*] Disconnecting...")
    finally:
        client.close()
        print("[✓] Client disconnected")


def run_setup_only():
    """Run setup only without starting any service"""
    setup_environment()
    print("[✓] Setup completed successfully")
    print("[*] You can now run the application with:")
    print("    python main.py --gui         (GUI mode)")
    print("    python main.py --server      (Server mode)")
    print("    python main.py --client      (Client mode)")


def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    Real-time Secure Network Traffic Monitoring System            ║
║    with Encryption and Threat Detection                          ║
║                                                                  ║
║    Features:                                                     ║
║    • Network packet capture and analysis                         ║
║    • Real-time threat detection                                  ║
║    • SSL/TLS encrypted communication                             ║
║    • RSA & AES encryption                                        ║
║    • User-friendly GUI                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main application entry point"""
    
    print_banner()
    
    
    parser = argparse.ArgumentParser(
        description='Real-time Secure Network Traffic Monitoring System',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--gui',
        action='store_true',
        help='Run in GUI mode (default)'
    )
    
    parser.add_argument(
        '--server',
        action='store_true',
        help='Run as secure server'
    )
    
    parser.add_argument(
        '--client',
        action='store_true',
        help='Run as secure client'
    )
    
    parser.add_argument(
        '--setup',
        action='store_true',
        help='Run setup only (create directories, generate certificates)'
    )
    
    parser.add_argument(
        '--host',
        type=str,
        default=config.SERVER_HOST,
        help=f'Server host (default: {config.SERVER_HOST})'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=config.SERVER_PORT,
        help=f'Server port (default: {config.SERVER_PORT})'
    )
    
    parser.add_argument(
        '--no-setup',
        action='store_true',
        help='Skip environment setup'
    )
    
    args = parser.parse_args()
    
    
    if not args.no_setup:
        try:
            setup_environment()
        except Exception as e:
            print(f"[✗] Setup error: {e}")
            print("[!] Continuing anyway...")
    
    
    try:
        if args.setup:
            run_setup_only()
        elif args.server:
            run_server(args.host, args.port)
        elif args.client:
            run_client(args.host, args.port)
        else:
            
            run_gui()
    
    except Exception as e:
        print(f"\n[✗] Application error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()