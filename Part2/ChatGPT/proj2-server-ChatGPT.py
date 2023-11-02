
import socket

server_host = '127.0.0.1'
server_port = 12345

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
    try:
        server_socket.bind((server_host, server_port))
        print(f"UDP server is listening on {server_host}:{server_port}")

        while True:
            data, client_address = server_socket.recvfrom(1024)
            print(f"Received data from {client_address}: {data.decode('utf-8')}")

    except Exception as e:
        print(f"An error occurred: {e}")
