# Code has been sampled from Muhammad Haroon's code, with modifications for the activity.
# Original code: https://github.com/Haroon96/ecs152a-fall-2023/blob/main/week3/code/udp-client.py

import socket

# Determine, and print out, the byte size of the sent message (to verify it is 100 KB)
from sys import getsizeof

# fetch the time method to assist us in measuring throughput
from time import time 

SERVER_HOST = '192.168.2.34'
SERVER_PORT = 5500

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    
    transmissionTime = 0

    # Send 100 messages, each a size of 1 Kb. Ensures 100 kB are sent. Measure throughput with the aid of the time member
    for i in range(0, 100):

        data = b'L' * 991 # Length of this byte data-type is 1 kB

        # Returns the size of the message, in bytes
        print(f'size of message {i + 1}: {getsizeof(data)} bytes (1 kB)')

        # Start our time right before sending the data
        t_1 = time()
        
        client_socket.sendto(data, (SERVER_HOST, SERVER_PORT))

        # End our time right after transmission is complete
        t_2 = time()

        # Difference of beginning and ending time is our transmission time
        transmissionTime += (t_2 - t_1)

    # Throughput is total number of bytes sent (we can sum up the sizes of our packets as we receive them) per second. Measured in KiloBytes.
    throughput = 100 / transmissionTime
    print(f'Throughput of transmission: {throughput} kBps')

