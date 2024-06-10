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

def get_http_headers(url):
    response = requests.get(url)
    return response.headers

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

def banner_grab(target, port):
    s = socket.socket()
    s.connect((target, port))
    s.send(b'HEAD / HTTP/1.1\r\n\r\n')
    banner = s.recv(1024)
    return banner.decode()

def detect_os(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-O')
        if 'osmatch' in nm[target]:
            os_matches = nm[target]['osmatch']
            return os_matches
        else:
            return "No OS detected"
    except Exception as e:
        return str(e)

def vulnerability_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='--script vuln')
    scan_data = nm[target_ip]
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
    target = input("Enter the target domain: ")
    target_ip = dns_lookup(target)

    results = {}

    print(f"[+] whois {target}...")
    whois_result = subprocess.getoutput(f"whois {target}")  # Call WHOIS command and get the output
    results["whois"] = whois_result

    print(f"\n[*] Gathering subdomains for {target}...")
    subdomains = get_subdomains(target)
    results["subdomains"] = subdomains

    print("[+] Detecting operating system...")
    os_detection_results = detect_os(target)
    results["os_detection"] = os_detection_results

    print(f"\n[+] Gathering DNS records for {target}...")
    dns_records = get_dns_records(target)
    results["dns_records"] = dns_records

    print(f"\n[+] Gathering SSL/TLS information for {target}...")
    ssl_info = get_ssl_info(target)
    results["ssl_info"] = ssl_info

    print(f"\n[+] Gathering HTTP headers for {target}...")
    url = f"http://{target}"
    http_headers = get_http_headers(url)
    results["http_headers"] = dict(http_headers)

    print(f"\n[*] Conducting port scan on {target_ip}...")
    port_scan_data = port_scan(target_ip)
    results["port_scan"] = port_scan_data

    print(f"\n[*] Conducting vulnerability scan on {target_ip}...")
    vulnerability_scan_data = vulnerability_scan(target_ip)
    results["vulnerability_scan"] = vulnerability_scan_data

    print("Performing banner grabbing...")
    banner_results = {}
    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            banner = banner_grab(ip, 80)  # Assuming HTTP port
            banner_results[subdomain] = banner
        except Exception as e:
            banner_results[subdomain] = f"Could not grab banner: {e}"
    results["banner_grabbing"] = banner_results

    # Save results to JSON file
    with open(f"{target}_results.json", "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nResults saved to {target}_results.json")

if __name__ == "__main__":
    main()
