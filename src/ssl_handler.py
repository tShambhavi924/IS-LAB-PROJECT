"""
SSL/TLS Handler Module - Pure Python Implementation
Manages SSL/TLS certificates and secure connections
No OpenSSL required!
"""

import ssl
import socket
import os
from datetime import datetime, timedelta
from pathlib import Path

# Use cryptography library instead of OpenSSL command
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("[!] Warning: cryptography package not installed")
    print("[!] Install with: pip install cryptography")


class SSLHandler:
    def __init__(self, cert_dir="certificates"):
        self.cert_dir = cert_dir
        self.server_cert_file = os.path.join(cert_dir, "server.crt")
        self.server_key_file = os.path.join(cert_dir, "server.key")
        self.client_cert_file = os.path.join(cert_dir, "client.crt")
        self.client_key_file = os.path.join(cert_dir, "client.key")
        
        # Create certificates directory if it doesn't exist
        Path(cert_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_self_signed_cert(self, cert_file, key_file, 
                                   common_name="localhost", 
                                   days_valid=365):
        """Generate self-signed SSL certificate using Python cryptography library"""
        
        if not CRYPTOGRAPHY_AVAILABLE:
            print("[✗] Cannot generate certificate: cryptography package not installed")
            print("[!] Install with: pip install cryptography")
            return False
        
        try:
            print(f"[*] Generating self-signed certificate for {common_name}...")
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Create certificate subject and issuer
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureNet"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            # Create certificate
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=days_valid)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(common_name),
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Write private key to file
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write certificate to file
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"[✓] Certificate generated: {cert_file}")
            print(f"[✓] Private key generated: {key_file}")
            return True
            
        except Exception as e:
            print(f"[✗] Error generating certificate: {e}")
            return False
    
    def create_ssl_context(self, is_server=True, verify_mode=ssl.CERT_NONE):
        """Create SSL context for secure connections"""
        try:
            if is_server:
                # Server context
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                
                # Check if certificate files exist
                if not os.path.exists(self.server_cert_file) or not os.path.exists(self.server_key_file):
                    print("[!] Server certificates not found, generating...")
                    if not self.generate_self_signed_cert(
                        self.server_cert_file,
                        self.server_key_file,
                        common_name="SecureNet-Server"
                    ):
                        return None
                
                context.load_cert_chain(
                    certfile=self.server_cert_file,
                    keyfile=self.server_key_file
                )
                print("[✓] Server SSL context created")
            else:
                # Client context
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = verify_mode
                
                # Load client certificate if exists
                if os.path.exists(self.client_cert_file):
                    context.load_cert_chain(
                        certfile=self.client_cert_file,
                        keyfile=self.client_key_file
                    )
                print("[✓] Client SSL context created")
            
            # Set strong cipher suites
            try:
                context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            except:
                # Fallback to default ciphers if the above fails
                pass
            
            # Set minimum TLS version
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            
            return context
            
        except Exception as e:
            print(f"[✗] Error creating SSL context: {e}")
            return None
    
    def wrap_socket_server(self, sock):
        """Wrap server socket with SSL"""
        try:
            context = self.create_ssl_context(is_server=True)
            if context:
                ssl_sock = context.wrap_socket(sock, server_side=True)
                print("[✓] Server socket wrapped with SSL")
                return ssl_sock
            return None
        except Exception as e:
            print(f"[✗] Error wrapping server socket: {e}")
            return None
    
    def wrap_socket_client(self, sock, server_hostname="localhost"):
        """Wrap client socket with SSL"""
        try:
            context = self.create_ssl_context(is_server=False)
            if context:
                ssl_sock = context.wrap_socket(
                    sock,
                    server_side=False,
                    server_hostname=server_hostname
                )
                print("[✓] Client socket wrapped with SSL")
                return ssl_sock
            return None
        except Exception as e:
            print(f"[✗] Error wrapping client socket: {e}")
            return None
    
    def get_certificate_info(self, cert_file):
        """Get information about a certificate"""
        if not CRYPTOGRAPHY_AVAILABLE:
            return "cryptography package not installed"
        
        try:
            with open(cert_file, "rb") as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            info = f"""
Certificate Information:
-----------------------
Subject: {cert.subject.rfc4514_string()}
Issuer: {cert.issuer.rfc4514_string()}
Serial Number: {cert.serial_number}
Valid From: {cert.not_valid_before}
Valid Until: {cert.not_valid_after}
            """
            return info
            
        except Exception as e:
            return f"Error reading certificate: {e}"
    
    def verify_certificate(self, cert_file):
        """Verify certificate validity"""
        try:
            # Check if certificate exists
            if not os.path.exists(cert_file):
                return False, "Certificate file not found"
            
            if not CRYPTOGRAPHY_AVAILABLE:
                return True, "Cannot verify (cryptography not installed)"
            
            with open(cert_file, "rb") as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check if certificate is still valid
            now = datetime.utcnow()
            if now < cert.not_valid_before:
                return False, "Certificate not yet valid"
            if now > cert.not_valid_after:
                return False, "Certificate expired"
            
            return True, f"Certificate valid until: {cert.not_valid_after}"
            
        except Exception as e:
            return False, f"Error verifying certificate: {e}"
    
    def setup_certificates(self, force_regenerate=False):
        """Setup all required certificates"""
        print("\n=== SSL/TLS Certificate Setup ===\n")
        
        # Check if certificates already exist
        server_exists = (os.path.exists(self.server_cert_file) and 
                        os.path.exists(self.server_key_file))
        
        if server_exists and not force_regenerate:
            print("[*] Server certificates already exist")
            valid, msg = self.verify_certificate(self.server_cert_file)
            print(f"[*] {msg}")
            
            if not valid:
                print("[!] Regenerating certificates...")
                force_regenerate = True
        
        if not server_exists or force_regenerate:
            # Generate server certificate
            success = self.generate_self_signed_cert(
                self.server_cert_file,
                self.server_key_file,
                common_name="SecureNet-Server"
            )
            
            if not success:
                print("[✗] Failed to generate server certificates")
                return False
        
        print("\n[✓] SSL/TLS certificates are ready")
        print(f"    Server Cert: {self.server_cert_file}")
        print(f"    Server Key:  {self.server_key_file}\n")
        
        return True


# Testing
if __name__ == "__main__":
    print("=== Testing SSL Handler Module ===\n")
    
    handler = SSLHandler()
    
    # Setup certificates
    handler.setup_certificates(force_regenerate=False)
    
    # Test SSL context creation
    print("\n=== Testing SSL Context ===")
    server_context = handler.create_ssl_context(is_server=True)
    client_context = handler.create_ssl_context(is_server=False)
    
    if server_context and client_context:
        print("[✓] SSL contexts created successfully")
    
    # Display certificate info
    print("\n=== Certificate Information ===")
    if os.path.exists(handler.server_cert_file):
        valid, msg = handler.verify_certificate(handler.server_cert_file)
        print(msg)
        print(handler.get_certificate_info(handler.server_cert_file))