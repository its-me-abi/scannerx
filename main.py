import sublist3r
import subprocess
import nmap
import requests
import json
import socket
import ssl
from urllib.parse import urlparse
import dns.resolver

def get_subdomains(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains
    

# def get_domain_info(domain):
#     domain_info = whois.whois(domain)             # funtion not working
#     return domain_info

def get_http_headers(url):
    response = requests.get(url)
    return response.headers

def port_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-65535')
    scan_data = nm[target]
    return scan_data

def dns_lookup(target):
    try:
        target_ip = socket.gethostbyname(target)
        return target_ip
    except socket.gaierror:
        return None


def port_scan(target):
    nm = nmap.PortScanner()
    common_ports = '21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5900,8080'  # Add more if needed
    try:
        nm.scan(target, common_ports, arguments='-T4')
        scan_data = nm[target]
        return scan_data
    except Exception as e:
        return {"error": str(e)}


def vulnerability_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='--script vuln')
    scan_data = nm[target]
    return scan_data

def get_dns_records(domain):
    records = {}
    for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except Exception as e:
            records[record_type] = str(e)
    return records

def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
    conn.connect((domain, 443))
    cert = conn.getpeercert()
    return cert

def main():
    target = input("Enter the target domain or IP address: ")
    # target_ip = socket.gethostbyname(target)
    target_ip = dns_lookup(target)
    
    print(f"[+] whois {target}...")                  
    print("")
    subprocess.call(f"whois {target}", shell=True)          # calling whois as terminal command. 

    print(f"\n[*] Gathering subdomains for {target}...")
    subdomains = get_subdomains(target)
    print(json.dumps(subdomains, indent=4))
    
    
    # print(f"\n[+] Gathering domain information for {target}...")
    # domain_info = get_domain_info(target)
    # print(domain_info)
    

    print(f"\n[+] Gathering DNS records for {target}...")
    dns_records = get_dns_records(target)
    print(json.dumps(dns_records, indent=4))
    
    print(f"\n[+] Gathering SSL/TLS information for {target}...")
    ssl_info = get_ssl_info(target)
    print(json.dumps(ssl_info, indent=4))
    
    print(f"\n[+] Gathering HTTP headers for {target}...")
    url = f"http://www.{target}"
    http_headers = get_http_headers(url)
    print(json.dumps(dict(http_headers), indent=4))
    
    print(f"\n[*] Conducting port scan on {target_ip}...")
    port_scan_data = port_scan(target_ip)
    print(json.dumps(port_scan_data, indent=4))
    
    print(f"\n[*] Conducting vulnerability scan on {target_ip}...")
    vulnerability_scan_data = vulnerability_scan(target_ip)
    print(json.dumps(vulnerability_scan_data, indent=4))

if __name__ == "__main__":
    main()
