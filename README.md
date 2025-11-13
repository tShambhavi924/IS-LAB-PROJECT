Real-Time Network Traffic Monitoring and Secure Communication System

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Tkinter](https://img.shields.io/badge/Tkinter-GUI-orange)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

In the modern digital age, securing data during transmission is of utmost importance. Network communication protocols are often vulnerable to attacks such as packet sniffing, man-in-the-middle attacks, and eavesdropping. Traditional tools like Wireshark allow packet capture and analysis but do not secure data during transmission.

This project implements a real-time network traffic monitoring system that identifies vulnerabilities in transmitted data and enhances communication security using SSL/TLS encryption, RSA public-key cryptography, and AES encryption. It also includes a real-time alert system to inform users about potential security threats, such as unsecured protocols and malicious packets.

---

## Problem Statement

Network traffic monitoring is critical for detecting potential threats, particularly when using unsecured protocols such as HTTP, FTP, or DNS. While tools like Wireshark can capture and analyze packets, they do not provide secure communication. Data transmitted between clients and servers is often vulnerable to interception, manipulation, and unauthorized access.

This project addresses this problem by integrating real-time network analysis with encryption techniques, ensuring the security and integrity of data in transit. It provides both vulnerability detection and secure communication channels between clients and servers.

---

## Objectives

- Capture and analyze network traffic using Wireshark to detect vulnerabilities such as unencrypted data and suspicious activity.
- Develop a secure communication system using SSL/TLS encryption to protect sensitive data during transmission.
- Implement RSA public-key cryptography for secure key exchange between clients and servers.
- Create a real-time alert system to detect and warn users about potential security threats, including unsecured protocols and man-in-the-middle attacks.
- Integrate a user-friendly Tkinter GUI to allow both technical and non-technical users to interact with the system.

---

## Tools and Technologies

- Wireshark for capturing and analyzing network traffic in real-time.
- OpenSSL for implementing SSL/TLS encryption and RSA key exchange mechanisms.
- Python for backend logic, packet analysis, and the alert system.
- Tkinter for building the graphical user interface.
- AES (Advanced Encryption Standard) for encrypting sensitive data during transmission.
- RSA (Rivest-Shamir-Adleman) for secure key exchange between client and server.

---

## Project Structure

```

IS-Lab-Project/
├── src/
│   ├── gui.py             # Main Tkinter GUI
│   ├── client.py          # Client connection logic
│   ├── server.py          # Server connection logic
│   ├── ssl_handler.py     # SSL/TLS context and certificate management
│   ├── crypto_utils.py    # RSA and AES encryption utilities
├── certificates/
│   ├── server.crt         # Server certificate (not for public use)
│   ├── server.key         # Server private key (not for public use)
├── README.md
└── .gitignore

````

Certificates and private keys should not be pushed publicly. Use placeholders if sharing the repository.

---

## Usage

### Start the Server
```bash
python src/server.py
````

### Start the Client

```bash
python src/client.py
```

### Run the GUI

```bash
python src/gui.py
```

---

## Security Highlights

* TLS v1.3 is used for encrypted transport.
* RSA 2048-bit keys are used for secure key exchange.
* AES-256 GCM is used for encrypting messages.
* A real-time alert system detects potential network threats.
* Logs and encrypted messages are displayed within the GUI.

---

## Future Enhancements

* Multi-client user authentication.
* Encrypted file transfer capabilities.
* Persistent message storage in a secure database.
* Improved exception handling and logging.

---

## Author

Shambhavi Tripathi

---

## License

MIT License

