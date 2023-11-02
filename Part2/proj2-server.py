# Code has been sampled from Muhammad Haroon's code, with modifications for this activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week3/code/udp-server.py

import socket

HOST = '192.168.2.34'
PORT = 5500

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
    server_socket.bind((HOST, PORT))

    while True:
        data, addr = server_socket.recvfrom(1000)
        print(f"Received {data.decode()} from {addr}")
     