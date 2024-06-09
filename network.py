import requests
from bs4 import BeautifulSoup
import nmap
import socket
import ssl
import shodan
import json
import builtwith
import tldextract

# API keys
SHODAN_API_KEY = 'Shodan api key'

def ensure_url_scheme(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def get_urls_from_google(query):
    search_url = f"https://www.google.com/search?q={query}"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    response = requests.get(search_url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = []
    for item in soup.find_all('a'):
        href = item.get('href')
        if href and '/url?q=' in href:
            links.append(href.split('/url?q=')[1].split('&')[0])
    return links

def scrape_webpage(url):
    url = ensure_url_scheme(url)
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text()
    return text

def dns_info(domain):
    result = socket.gethostbyname_ex(domain)
    return {
        'hostname': result[0],
        'aliases': result[1],
        'addresses': result[2]
    }

def ssl_info(domain):
    domain = ensure_url_scheme(domain).replace('http://', '').replace('https://', '')
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.connect((domain, 443))
        cert = s.getpeercert()

    ssl_details = {
        'subject': cert['subject'],
        'issuer': cert['issuer'],
        'version': cert['version'],
        'serialNumber': cert['serialNumber'],
        'notBefore': cert['notBefore'],
        'notAfter': cert['notAfter'],
        'subjectAltName': cert['subjectAltName']
    }

    return ssl_details

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024', arguments='-O -sV -sS -T4')
    scan_info = {
        'scan': nm.scaninfo(),
        'host': nm[target],
        'all_hosts': nm.all_hosts()
    }
    return scan_info

def shodan_info(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    info = api.host(ip)
    return info

def builtwith_info(url):
    url = ensure_url_scheme(url)
    return builtwith.parse(url)

def banner_grabbing(ip, port=80):
    try:
        s = socket.socket()
        s.connect((ip, port))
        s.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
        banner = s.recv(1024)
        s.close()
        return banner.decode()
    except Exception as e:
        return str(e)

def geolocation_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        return str(e)

def subdomains(domain):
    subdomains_list = []
    extracted = tldextract.extract(domain)
    base_domain = f"{extracted.domain}.{extracted.suffix}"
    subdomains_url = f"https://crt.sh/?q=%25.{base_domain}&output=json"
    response = requests.get(subdomains_url)
    if response.status_code == 200:
        data = response.json()
        for entry in data:
            subdomains_list.append(entry['name_value'])
    return list(set(subdomains_list))

def save_report(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def gather_information(target):
    results = {}

    try:
        dns_results = dns_info(target)
        save_report(f"{target}_dns_info.json", dns_results)
        results['DNS Information'] = dns_results
    except Exception as e:
        results['DNS Information'] = str(e)

    try:
        ssl_results = ssl_info(target)
        save_report(f"{target}_ssl_info.json", ssl_results)
        results['SSL/TLS Information'] = ssl_results
    except Exception as e:
        results['SSL/TLS Information'] = str(e)

    try:
        nmap_results = nmap_scan(target)
        save_report(f"{target}_nmap_scan.json", nmap_results)
        results['Nmap Scan'] = "Nmap scan results saved in separate file."
    except Exception as e:
        results['Nmap Scan'] = str(e)

    try:
        ip = socket.gethostbyname(target)
        shodan_results = shodan_info(ip)
        save_report(f"{target}_shodan_info.json", shodan_results)
        results['Shodan Information'] = shodan_results
    except Exception as e:
        results['Shodan Information'] = str(e)

    try:
        builtwith_results = builtwith_info(target)
        save_report(f"{target}_builtwith_info.json", builtwith_results)
        results['BuiltWith Information'] = builtwith_results
    except Exception as e:
        results['BuiltWith Information'] = str(e)

    try:
        banner_grab_results = banner_grabbing(ip)
        save_report(f"{target}_banner_grabbing.json", banner_grab_results)
        results['Banner Grabbing'] = banner_grab_results
    except Exception as e:
        results['Banner Grabbing'] = str(e)

    try:
        geolocation_results = geolocation_info(ip)
        save_report(f"{target}_geolocation_info.json", geolocation_results)
        results['Geolocation Information'] = geolocation_results
    except Exception as e:
        results['Geolocation Information'] = str(e)

    try:
        subdomains_results = subdomains(target)
        save_report(f"{target}_subdomains.json", subdomains_results)
    except Exception as e:
        results['Subdomains'] = str(e)

    return results

def main():
    query = input("Enter the Google search query: ")
    urls = get_urls_from_google(query)

    results = {}
    results['Scraped URLs'] = urls

    for url in urls:
        webpage_content = scrape_webpage(url)
        save_report(f"{url.replace('http://', '').replace('https://', '').replace('/', '_')}_content.json", webpage_content)
        results[url] = webpage_content

    target = input("Enter the target domain for security audit: ")
    security_audit_results = gather_information(target)

    results['Security Audit'] = security_audit_results
    save_report(f"{target}_security_audit_summary.json", results)

    def convert_to_serializable(obj):
        if isinstance(obj, set):
            return list(obj)
        raise TypeError

    with open('final_results.json', 'w') as f:
        json.dump(results, f, indent=4, default=convert_to_serializable)

    print("Separate reports and final results saved.")

if __name__ == "__main__":
    main()
