
import socket
import time

# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_host = '127.0.0.1'
server_port = 12345

# Sending data in smaller chunks
data = b'A' * 102400  # Sending 100 kilobytes of data
chunk_size = 1024  # Set the chunk size to fit within the server's buffer

start_time = time.time()

# Send the data to the server in smaller chunks
for i in range(0, len(data), chunk_size):
    chunk = data[i:i + chunk_size]
    client_socket.sendto(chunk, (server_host, server_port))

end_time = time.time()

transfer_time = end_time - start_time
throughput = len(data) / transfer_time / 1024  # in kilobytes per second

# Format the transfer_time with more significant figures
formatted_transfer_time = "{:.6f}".format(transfer_time)

print(f"Data sent in {formatted_transfer_time} seconds")
print(f"Throughput: {throughput:.2f} KB/s")

client_socket.close()
