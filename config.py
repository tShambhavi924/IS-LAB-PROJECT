"""
Configuration Module
Contains all configuration settings for the Network Security Monitor
"""

# Server Configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 8443
SERVER_BACKLOG = 5

# Client Configuration
CLIENT_TIMEOUT = 30

# SSL/TLS Configuration
SSL_CERT_DIR = 'certificates'
SSL_KEY_SIZE = 4096
SSL_CERT_VALIDITY_DAYS = 365
#SSL_MIN_TLS_VERSION = 'TLSv1.2'
SSL_MIN_TLS_VERSION = 'TLSv1.3'

# Encryption Configuration
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32  # 256 bits
AES_MODE = 'CBC'

# Packet Capture Configuration
CAPTURE_INTERFACE = None  # None for default interface
CAPTURE_FILTER = None  # BPF filter string
MAX_PACKET_STORAGE = 10000
PACKET_DISPLAY_LIMIT = 1000

# Threat Detection Configuration
PORT_SCAN_THRESHOLD = 10  # Different ports in 5 seconds
SYN_FLOOD_THRESHOLD = 50  # Packets per second
DOS_PACKET_THRESHOLD = 100  # Packets per second from single source

# Alert Configuration
ALERT_RETENTION_DAYS = 30
ENABLE_ALERT_SOUND = False
ALERT_CHECK_INTERVAL = 5  # seconds

# Logging Configuration
LOG_DIR = 'logs'
LOG_FILE_PREFIX = 'network_security'
LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# UI Configuration
UI_REFRESH_RATE = 1000  # milliseconds
UI_THEME = 'default'
UI_FONT_FAMILY = 'Courier'
UI_FONT_SIZE = 10

# Known Insecure Protocols
INSECURE_PROTOCOLS = {
    'HTTP': {'port': 80, 'severity': 'HIGH'},
    'FTP': {'port': 21, 'severity': 'HIGH'},
    'Telnet': {'port': 23, 'severity': 'CRITICAL'},
    'SMTP': {'port': 25, 'severity': 'MEDIUM'},
    'POP3': {'port': 110, 'severity': 'MEDIUM'},
    'IMAP': {'port': 143, 'severity': 'MEDIUM'},
    'SNMP': {'port': 161, 'severity': 'MEDIUM'},
}

# Malicious Patterns
MALICIOUS_PATTERNS = {
    'sql_injection': [
        b'SELECT', b'UNION', b'DROP TABLE', 
        b"' OR '1'='1", b'--', b'/*', b'*/'
    ],
    'xss': [
        b'<script>', b'</script>', b'javascript:',
        b'onerror=', b'onload=', b'<iframe>'
    ],
    'command_injection': [
        b'eval(', b'exec(', b'system(', b'passthru',
        b'shell_exec', b'`', b'$(', b'${{'
    ],
    'path_traversal': [
        b'../', b'..\\', b'%2e%2e%2f', b'%2e%2e\\',
        b'....', b'....'
    ],
    'file_inclusion': [
        b'/etc/passwd', b'c:\\windows\\', b'php://input',
        b'data://', b'expect://'
    ]
}

# Network Ranges
PRIVATE_IP_RANGES = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8'
]

# Performance Settings
MAX_CONCURRENT_CONNECTIONS = 100
SOCKET_TIMEOUT = 30
BUFFER_SIZE = 4096

# Feature Flags
ENABLE_PACKET_CAPTURE = True
ENABLE_THREAT_DETECTION = True
ENABLE_SECURE_COMMUNICATION = True
ENABLE_LOGGING = True
ENABLE_GUI = True

# Export Settings
EXPORT_FORMAT = 'txt'  # txt, json, csv
EXPORT_DIR = 'exports'

# Database Settings (for future enhancement)
USE_DATABASE = False
DATABASE_TYPE = 'sqlite'  # sqlite, mysql, postgresql
DATABASE_FILE = 'network_security.db'

# API Settings (for future enhancement)
ENABLE_REST_API = False
API_PORT = 5000
API_HOST = 'localhost'


def get_config():
    """Return configuration dictionary"""
    return {
        'server': {
            'host': SERVER_HOST,
            'port': SERVER_PORT,
            'backlog': SERVER_BACKLOG
        },
        'ssl': {
            'cert_dir': SSL_CERT_DIR,
            'key_size': SSL_KEY_SIZE,
            'validity_days': SSL_CERT_VALIDITY_DAYS,
            'min_tls_version': SSL_MIN_TLS_VERSION
        },
        'encryption': {
            'rsa_key_size': RSA_KEY_SIZE,
            'aes_key_size': AES_KEY_SIZE,
            'aes_mode': AES_MODE
        },
        'capture': {
            'interface': CAPTURE_INTERFACE,
            'filter': CAPTURE_FILTER,
            'max_storage': MAX_PACKET_STORAGE
        },
        'threat_detection': {
            'port_scan_threshold': PORT_SCAN_THRESHOLD,
            'syn_flood_threshold': SYN_FLOOD_THRESHOLD,
            'dos_threshold': DOS_PACKET_THRESHOLD
        },
        'logging': {
            'directory': LOG_DIR,
            'prefix': LOG_FILE_PREFIX,
            'level': LOG_LEVEL
        }
    }


def print_config():
    """Print current configuration"""
    config = get_config()
    print("=== Current Configuration ===\n")
    for category, settings in config.items():
        print(f"{category.upper()}:")
        for key, value in settings.items():
            print(f"  {key}: {value}")
        print()


if __name__ == "__main__":
    print_config()