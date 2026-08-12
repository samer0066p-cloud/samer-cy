import os
import socket
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

class CyberScanner:
    def __init__(self, target_url, target_ip):
        self.target_url = target_url if target_url.startswith("http") else f"http://{target_url}"
        self.target_ip = target_ip
        self.report_filename = f"Vulnerability_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        self.open_ports = []
        self.exposed_dirs = []
        self.missing_headers = []

    def scan_ports(self):
        print(f"[+] Scanning ports for {self.target_ip}...")
        common_ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt"}
        for port, service in common_ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((s
