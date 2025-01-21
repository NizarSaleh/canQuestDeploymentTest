#!/usr/bin/env python3

import socket
import time

# Server IP and Port (Update to match your server configuration)
SERVER_IP = '127.0.0.1'  # Change this to your server's IP if not local
SERVER_PORT = 8080       # Ensure this matches the port in your server code

def main():
    try:
        # Create a socket to connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to server at {SERVER_IP}:{SERVER_PORT}...")
        
        # Connect to the server
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print("Connected to server.")

        # Send some dummy data
        data_to_send = "0x123456789ABCDEF".encode('utf-8')
        print(f"Sending data: {data_to_send.decode('utf-8')}")
        client_socket.sendall(data_to_send)

        # Wait for server response
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Received response from server: {response}")

        # Test sending more data
        for i in range(5):
            message = f"Message {i}".encode('utf-8')
            print(f"Sending: {message.decode('utf-8')}")
            client_socket.sendall(message)
            time.sleep(1)  # Pause for a moment
            
            response = client_socket.recv(1024).decode('utf-8')
            print(f"Response: {response}")

        # Close the connection
        print("Closing connection.")
        client_socket.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
