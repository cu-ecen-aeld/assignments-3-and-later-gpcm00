import socket

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 9000  # Port to listen on 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    for i in range(30):
        s.send(b"Hello, world\n")
        data = s.recv(512*1024)
        print(f"Received {data!r}")