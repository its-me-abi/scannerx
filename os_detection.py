def detect_os(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-O')
    if 'osmatch' in nm[target]:
        os_matches = nm[target]['osmatch']
        return os_matches
    else:
        return "No OS detected"


def main():
   print("Detecting operating system...")
    os_detection_results = detect_os(domain)
    print(f"OS Detection Results: {os_detection_results}")
