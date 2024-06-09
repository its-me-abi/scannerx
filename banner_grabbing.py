import socket

def banner_grab(target, port):
    s = socket.socket()
    s.connect((target, port))
    s.send(b'HEAD / HTTP/1.1\r\n\r\n')
    banner = s.recv(1024)
    return banner.decode()

def main():

    print("Performing banner grabbing...")
    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            banner = banner_grab(ip, 80)  # Assuming HTTP port
            print(f"Banner for {subdomain} ({ip}): {banner}")
        except Exception as e:
            print(f"Could not grab banner for {subdomain}:")


if __name__ == "__main__":
    main()
