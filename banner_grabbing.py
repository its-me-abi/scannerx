import socket

def banner_grab(target, port):
    s = socket.socket()
    s.connect((target, port))
    s.send(b'HEAD / HTTP/1.1\r\n\r\n')
    banner = s.recv(1024)
    return banner.decode()
