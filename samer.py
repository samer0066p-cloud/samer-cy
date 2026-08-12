import socket
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
import os

class CyberScanner:
    def __init__(self, target_url, target_ip):
        self.target_url = target_url if target_url.startswith("http") else f"http://{target_url}"
        self.target_ip = target_ip
        self.clean_domain = target_url.replace("http://", "").replace("https://", "").split('/')[0]
        self.report_filename = f"Vulnerability_Report_{self.clean_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        self.open_ports = []
        self.missing_headers = []

    def scan_ports(self):
        print(f"[+] Scanning ports for {self.target_ip} ({self.clean_domain})...")
        common_ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt"}
        for port, service in common_ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((self.target_ip, port))
            if result == 0:
                print(f"    [*] Port {port} ({service}) is OPEN")
                self.open_ports.append(f"Port {port} ({service})")
            s.close()

    def check_security_headers(self):
        print(f"[+] Analyzing Security Headers for {self.target_url}...")
        important_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ]
        try:
            response = requests.get(self.target_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            for header in important_headers:
                if header not in response.headers:
                    print(f"    [!] Missing Security Header: {header}")
                    self.missing_headers.append(header)
        except Exception as e:
            print(f"[-] Failed to connect to URL for header analysis: {str(e)}")

    def generate_report(self):
        print(f"[+] Generating vulnerability report for {self.clean_domain}...")
        with open(self.report_filename, "w", encoding="utf-8") as f:
            f.write("=========================================\n")
            f.write("      VULNERABILITY SCANNER REPORT       \n")
            f.write("=========================================\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target URL: {self.target_url}\n")
            f.write(f"Target IP: {self.target_ip}\n\n")
            
            f.write("1. Open Ports Scan Results:\n")
            if self.open_ports:
                for port in self.open_ports:
                    f.write(f"   [!] Found Open Port: {port}\n")
            else:
                f.write("   [-] No open standard ports detected.\n")
                
            f.write("\n2. Missing Security Headers (Potential Vulnerabilities):\n")
            if self.missing_headers:
                for header in self.missing_headers:
                    f.write(f"   [!] MISSING: {header} (Risk: Configuration Flaw)\n")
            else:
                f.write("   [-] All analyzed security headers are present.\n")
                
            f.write("\n=========================================\n")
        print(f"[+] Report saved as {self.report_filename}")

    def send_report(self):
        print("[+] Sending report via email...")
        sender_email = "Samer0066p@gmail.com"
        sender_password = os.environ.get("SENDER_PASSWORD")
        target_email = os.environ.get("TARGET_EMAIL", "Samer0066p@gmail.com")

        if not sender_password:
            print("[-] Error: SENDER_PASSWORD secret is missing in GitHub settings!")
            return

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = target_email
        msg['Subject'] = f"Automated Vulnerability Report - {self.clean_domain}"

        body = f"Attached is the automated vulnerability scan report for {self.clean_domain}."
        msg.attach(MIMEText(body, 'plain'))

        try:
            with open(self.report_filename, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename= {self.report_filename}",
                )
                msg.attach(part)

            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, target_email, text)
            server.quit()
            print("[+] Email sent successfully with the report attachment!")
        except Exception as e:
            print(f"[-] Failed to send email. Error: {str(e)}")

if __name__ == "__main__":
    # قائمة المواقع المراد فحصها متتالياً (يمكنك استبدالها أو إضافة أي مواقع تريد فحصها هنا)
    targets = [
        {"url": "example.com", "ip": "93.184.216.34"},
        {"url": "http://scanme.nmap.org", "ip": "45.33.32.156"}
    ]
    
    for target in targets:
        scanner = CyberScanner(target["url"], target["ip"])
        scanner.scan_ports()       
        scanner.check_security_headers()
        scanner.generate_report()  
        scanner.send_report()      
