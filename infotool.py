import sys
import socket
import requests
import json
from datetime import datetime
import dns.resolver
import whois
import ssl
import OpenSSL
import http.client
 
BANNER = """
     ___            __           _                     _ 
    |_ _|  _ __    / _|   ___   | |_    ___     ___   | |
     | |  | '_ \\  | |_   / _ \\  | __|  / _ \\   / _ \\  | |
     | |  | | | | |  _| | (_) | | |_  | (_) | | (_) | | |
    |___| |_| |_| |_|    \\___/   \\__|  \\___/   \\___/  |_|
  
                                                     
                 Developed by Musraf  Khan
"""

class InfoTool:
    def __init__(self, website):
        self.website = website if website.startswith('http') else f'http://{website}'
        self.domain = website.split('//')[-1].split('/')[0]
        self.result = {}
        self.ipinfo_token = 'd15b790f2b2119'  

    def get_ip_address(self):
        """Get IP address of the website"""
        try:
            ip = socket.gethostbyname(self.domain)
            self.result['ip_address'] = ip
            return ip
        except socket.gaierror as e:
            self.result['ip_address'] = f"Error: {str(e)}"
            return None

    def get_ipinfo_location(self):
        """Get precise geolocation using ipinfo.io API"""
        try:
            ip = self.get_ip_address()
            if ip and not ip.startswith('Error'):
                url = f"https://ipinfo.io/{ip}/json?token={self.ipinfo_token}"
                response = requests.get(url, timeout=5)
                response.raise_for_status()  
                data = response.json()
                if 'bogon' not in data:
                    loc = data.get('loc', '').split(',')
                    self.result['location'] = {
                        'city': data.get('city', 'N/A'),
                        'region': data.get('region', 'N/A'),
                        'country': data.get('country', 'N/A'),
                        'latitude': float(loc[0]) if loc and loc[0] else None,
                        'longitude': float(loc[1]) if loc and loc[1] else None,
                        'isp': data.get('org', 'N/A'),
                        'organization': data.get('org', 'N/A'),
                        'postal': data.get('postal', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }
                else:
                    self.result['location'] = "Private or reserved IP (bogon)"
            else:
                self.result['location'] = "No valid IP address found"
        except requests.RequestException as e:
            self.result['location'] = f"Error fetching location: {str(e)}"

    def decode_bytes(self, data):
        """Convert bytes to strings in nested structures"""
        if isinstance(data, bytes):
            return data.decode('utf-8', errors='ignore')
        elif isinstance(data, list):
            return [self.decode_bytes(item) for item in data]
        elif isinstance(data, dict):
            return {self.decode_bytes(k): self.decode_bytes(v) for k, v in data.items()}
        elif isinstance(data, tuple):
            return tuple(self.decode_bytes(item) for item in data)
        return data

    def get_ssl_info(self):
        """Get SSL certificate information"""
        try:
            cert = ssl.get_server_certificate((self.domain, 443), timeout=5)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            issuer_components = [(k.decode('utf-8'), v.decode('utf-8')) for k, v in x509.get_issuer().get_components()]
            subject_components = [(k.decode('utf-8'), v.decode('utf-8')) for k, v in x509.get_subject().get_components()]
            self.result['ssl_info'] = {
                'issuer': dict(issuer_components),
                'subject': dict(subject_components),
                'serial_number': str(x509.get_serial_number()),
                'version': x509.get_version(),
                'not_before': x509.get_notBefore().decode('ascii'),
                'not_after': x509.get_notAfter().decode('ascii'),
                'has_expired': x509.has_expired()
            }
        except Exception as e:
            self.result['ssl_info'] = f"Error: {str(e)}"

    def get_website_status(self):
        """Check website status and response information"""
        try:
            response = requests.get(self.website, timeout=10, allow_redirects=True)
            conn = http.client.HTTPSConnection(self.domain, timeout=5)
            conn.request("HEAD", "/")
            buffer_size = conn.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) if conn.sock else 0
            
            self.result['website_status'] = {
                'status_code': response.status_code,
                'is_up': response.status_code == 200,
                'response_time_ms': round(response.elapsed.total_seconds() * 1000, 2),
                'buffer_size_bytes': buffer_size,
                'redirect_chain': [r.url for r in response.history] if response.history else [],
                'final_url': response.url
            }
        except requests.RequestException as e:
            self.result['website_status'] = f"Error: {str(e)}"

    def get_whois_info(self):
        """Get WHOIS information"""
        try:
            w = whois.whois(self.domain)
            self.result['whois'] = {
                'registrar': w.registrar if w.registrar else 'N/A',
                'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
                'name_servers': w.name_servers if w.name_servers else []
            }
        except AttributeError:
            self.result['whois'] = "Error: WHOIS module not properly installed. Install 'python-whois'"
        except Exception as e:
            self.result['whois'] = f"Error: {str(e)}"

    def get_dns_records(self):
        """Get DNS records"""
        dns_records = {}
        record_types = ['A', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                dns_records[record_type] = []
        
        self.result['dns_records'] = dns_records

    def get_server_info(self):
        """Get server headers information"""
        try:
            response = requests.head(self.website, timeout=5, allow_redirects=True)
            self.result['server_info'] = {
                'server': response.headers.get('Server', 'N/A'),
                'content_type': response.headers.get('Content-Type', 'N/A'),
                'content_length': response.headers.get('Content-Length', 'N/A'),
                'last_modified': response.headers.get('Last-Modified', 'N/A')
            }
        except requests.RequestException as e:
            self.result['server_info'] = f"Error: {str(e)}"

    def gather_all_info(self):
        """Gather all information"""
        self.result['timestamp'] = datetime.now().isoformat()
        self.result['domain'] = self.domain
        
        self.get_ip_address()
        self.get_ipinfo_location()
        self.get_ssl_info()
        self.get_website_status()
        self.get_whois_info()
        self.get_dns_records()
        self.get_server_info()
        
        return json.dumps(self.result, indent=2, default=str)

def main():
    print(BANNER)
    
    if len(sys.argv) != 2:
        print("Usage: python infotool.py <websiteurl>")
        print("Example: python infotool.py google.com")
        sys.exit(1)

    website = sys.argv[1]
    tool = InfoTool(website)
    
    try:
        result = tool.gather_all_info()
        print(result)
    except Exception as e:
        print(json.dumps({"error": f"Fatal error: {str(e)}"}, indent=2))

if __name__ == "__main__":
    main()
