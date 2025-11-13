"""
Secure Communication Module
Implements secure client-server communication with encryption
"""

import socket
import ssl
import json
import threading
from encryption import EncryptionHandler
from ssl_handler import SSLHandler


class SecureServer:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.is_running = False
        self.clients = []
        self.ssl_handler = SSLHandler()
        self.encryption = EncryptionHandler()
        
        # Generate RSA keys for the server
        private_key, public_key = self.encryption.generate_rsa_keys()
        self.public_key = public_key
        
        # Setup SSL certificates
        self.ssl_handler.setup_certificates()
    
    def start(self):
        """Start the secure server"""
        try:
            # Create socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            # Wrap with SSL
            context = self.ssl_handler.create_ssl_context(is_server=True)
            ssl_socket = context.wrap_socket(server_socket, server_side=True)
            
            self.is_running = True
            print(f"[✓] Secure server started on {self.host}:{self.port}")
            from config import SSL_MIN_TLS_VERSION
            print(f"[*] Using TLS version: {SSL_MIN_TLS_VERSION}")

            # print(f"[*] Using TLS v{ssl.TLS_VERSION}")
            print("[*] Waiting for connections...\n")
            
            while self.is_running:
                try:
                    client_socket, address = ssl_socket.accept()
                    print(f"[+] New connection from {address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.is_running:
                        print(f"[✗] Error accepting connection: {e}")
            
        except Exception as e:
            print(f"[✗] Server error: {e}")
        finally:
            print("[*] Server stopped")
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        try:
            # Send server's public key
            self.send_message(client_socket, {
                'type': 'public_key',
                'key': self.public_key.decode('utf-8')
            })
            
            # Receive client's public key
            response = self.receive_message(client_socket)
            if response and response.get('type') == 'public_key':
                client_public_key = response['key'].encode('utf-8')
                print(f"[✓] Key exchange completed with {address}")
                
                # Generate and send encrypted AES key
                aes_key = self.encryption.generate_aes_key()
                encrypted_aes_key = self.encryption.encrypt_key_for_transmission(
                    aes_key, client_public_key
                )
                
                self.send_message(client_socket, {
                    'type': 'aes_key',
                    'key': encrypted_aes_key
                })
                
                print(f"[✓] Secure channel established with {address}")
                
                # Handle encrypted communication
                while self.is_running:
                    data = self.receive_message(client_socket)
                    if not data:
                        break
                    
                    if data.get('type') == 'encrypted_message':
                        # Decrypt message
                        encrypted_msg = data['message']
                        decrypted_msg = self.encryption.decrypt_aes(encrypted_msg)
                        
                        if decrypted_msg:
                            print(f"[{address[0]}] {decrypted_msg}")
                            
                            # Echo back encrypted
                            response = f"Server received: {decrypted_msg}"
                            encrypted_response = self.encryption.encrypt_aes(response)
                            
                            self.send_message(client_socket, {
                                'type': 'encrypted_message',
                                'message': encrypted_response
                            })
        
        except Exception as e:
            print(f"[✗] Client handler error: {e}")
        finally:
            client_socket.close()
            print(f"[-] Connection closed: {address}")
    
    def send_message(self, sock, message):
        """Send JSON message over socket"""
        try:
            json_data = json.dumps(message)
            sock.sendall(json_data.encode('utf-8') + b'\n')
            return True
        except Exception as e:
            print(f"[✗] Send error: {e}")
            return False
    
    def receive_message(self, sock):
        """Receive JSON message from socket"""
        try:
            data = b''
            while b'\n' not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    return None
                data += chunk
            
            json_data = data.decode('utf-8').strip()
            return json.loads(json_data)
        except Exception as e:
            print(f"[✗] Receive error: {e}")
            return None
    
    def stop(self):
        """Stop the server"""
        self.is_running = False


class SecureClient:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.socket = None
        self.ssl_handler = SSLHandler()
        self.encryption = EncryptionHandler()
        self.is_connected = False
        
        # Generate RSA keys for the client
        private_key, public_key = self.encryption.generate_rsa_keys()
        self.public_key = public_key
    
    def connect(self):
        """Connect to secure server"""
        try:
            # Create socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap with SSL
            context = self.ssl_handler.create_ssl_context(is_server=False)
            self.socket = context.wrap_socket(
                client_socket,
                server_side=False,
                server_hostname=self.host
            )
            
            self.socket.connect((self.host, self.port))
            print(f"[✓] Connected to {self.host}:{self.port}")
            print(f"[*] TLS Version: {self.socket.version()}")
            print(f"[*] Cipher: {self.socket.cipher()}\n")
            
            # Perform key exchange
            if self.key_exchange():
                self.is_connected = True
                print("[✓] Secure channel established\n")
                return True
            
            return False
            
        except Exception as e:
            print(f"[✗] Connection error: {e}")
            return False
    
    def key_exchange(self):
        """Perform RSA key exchange"""
        try:
            # Receive server's public key
            data = self.receive_message()
            if data and data.get('type') == 'public_key':
                server_public_key = data['key'].encode('utf-8')
                print("[✓] Received server public key")
                
                # Send client's public key
                self.send_message({
                    'type': 'public_key',
                    'key': self.public_key.decode('utf-8')
                })
                print("[✓] Sent client public key")
                
                # Receive encrypted AES key
                data = self.receive_message()
                if data and data.get('type') == 'aes_key':
                    encrypted_aes_key = data['key']
                    
                    # Decrypt AES key
                    aes_key = self.encryption.decrypt_received_key(encrypted_aes_key)
                    if aes_key:
                        print("[✓] AES key received and decrypted")
                        return True
            
            return False
            
        except Exception as e:
            print(f"[✗] Key exchange error: {e}")
            return False
    
    def send_encrypted(self, message):
        """Send encrypted message"""
        try:
            if not self.is_connected:
                print("[✗] Not connected to server")
                return False
            
            # Encrypt message
            encrypted = self.encryption.encrypt_aes(message)
            if not encrypted:
                return False
            self.last_encrypted_message = encrypted

            # Send encrypted message
            return self.send_message({
                'type': 'encrypted_message',
                'message': encrypted
            })
            
        except Exception as e:
            print(f"[✗] Send error: {e}")
            return False
    
    def receive_encrypted(self):
        """Receive and decrypt message"""
        try:
            data = self.receive_message()
            if data and data.get('type') == 'encrypted_message':
                encrypted_msg = data['message']
                decrypted = self.encryption.decrypt_aes(encrypted_msg)
                return decrypted
            return None
        except Exception as e:
            print(f"[✗] Receive error: {e}")
            return None
    
    def send_message(self, message):
        """Send JSON message"""
        try:
            json_data = json.dumps(message)
            self.socket.sendall(json_data.encode('utf-8') + b'\n')
            return True
        except Exception as e:
            print(f"[✗] Send error: {e}")
            return False
    
    def receive_message(self):
        """Receive JSON message"""
        try:
            data = b''
            while b'\n' not in data:
                chunk = self.socket.recv(4096)
                if not chunk:
                    return None
                data += chunk
            
            json_data = data.decode('utf-8').strip()
            return json.loads(json_data)
        except Exception as e:
            print(f"[✗] Receive error: {e}")
            return None
    
    def close(self):
        """Close connection"""
        if self.socket:
            self.socket.close()
            self.is_connected = False
            print("[*] Connection closed")


# Testing
if __name__ == "__main__":
    import sys
    import time
    
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Run as server
        print("=== Starting Secure Server ===\n")
        server = SecureServer()
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
            server.stop()
    
    else:
        # Run as client
        print("=== Starting Secure Client ===\n")
        client = SecureClient()
        
        if client.connect():
            # Send test messages
            messages = [
                "Hello, secure server!",
                "This message is encrypted with AES-256",
                "Testing secure communication"
            ]
            
            for msg in messages:
                print(f"Sending: {msg}")
                client.send_encrypted(msg)
                
                response = client.receive_encrypted()
                if response:
                    print(f"Received: {response}\n")
                
                time.sleep(1)
            
            client.close()