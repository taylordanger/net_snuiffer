# We’ll use a known behavior of most operating systems to determine
# if there is an active host at a particular IP address. When we send a UDP
# datagram to a closed port on a host, that host typically sends back an ICMP
# message indicating that the port is unreachable. This ICMP message tells us
# that there is a host alive, because if there was no host, we probably wouldn’t
# receive any response to the UDP datagram.

import socket
import os

#host to listen on
HOST = '192.168.1.203'

def main():
# creat raw socket, 
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((HOST, O))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print(sniffer.recvfrom(65565))

if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
