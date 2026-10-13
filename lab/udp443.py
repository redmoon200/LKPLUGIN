import socket, sys
for ip in sys.argv[1:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(5): s.sendto(b'\xc3' + b'\x00' * 1199, (ip, 443))
