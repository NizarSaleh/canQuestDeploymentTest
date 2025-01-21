#!/usr/bin/env python3

import sys
import can
import time
import random
import socket
import threading

IP = '127.0.0.1'
PORT = 8080

bus = None
wiper_status = 0x00
status_lock = threading.Lock()


def setup_can(interface):
    global bus
    try:
        print(f"Bringing up CAN interface {interface}...")
        time.sleep(0.1)
        bus = can.interface.Bus(interface=interface, channel='vcan0', bitrate=500000)
    except OSError:
        print(f"Error: Cannot find interface {interface}.")
        sys.exit(1)
    print("CAN interface ready.")


def send_msg(arb_id, data, is_extended=False):
    global bus
    if not bus:
        print("Error: CAN bus is not initialized.")
        return
    try:
        msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=is_extended)
        bus.send(msg)
        print(f"Message sent: {msg}")
    except can.CanError as e:
        print(f"Message NOT sent: {e}")


def broadcast_wiper_data():
    global wiper_status
    while True:
        with status_lock:
            stat_msg = [wiper_status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        send_msg(0x058, stat_msg)
        time.sleep(0.1)


def main():
    if len(sys.argv) < 2:
        print("Usage: old_uds_server.py <can interface>")
        sys.exit(1)

    interface = sys.argv[1]
    setup_can(interface)

    while True:
        try:
            msg = bus.recv()
            print(f"Received message: {msg}")
        except KeyboardInterrupt:
            print("Shutting down server...")
            bus.shutdown()
            sys.exit(0)


if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen(1)
    print(f"Server listening on {IP}:{PORT}")

    if len(sys.argv) < 2:
        print("Error: CAN interface not specified.")
        sys.exit(1)

    interface = sys.argv[1]
    setup_can(interface)

    # Start the wiper data broadcast thread
    threading.Thread(target=broadcast_wiper_data, daemon=True).start()

    while True:
        try:
            client_sock, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            main()
        except Exception as e:
            print(f"Error: {e}")
            print("Retrying...")

