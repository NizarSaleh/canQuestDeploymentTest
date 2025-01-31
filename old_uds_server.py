#!/usr/bin/env python3

import sys
import can
import time
import random
import socket
import threading

IP = '127.0.0.1'
PORT = 8080

# Global (shared) variables
bus = None
can_id = ""
verbose = 1
session = 1
security_access = 0
attempts = 0
key = None

# This is the global wiper status and a lock to safely update/read it
wiper_status = 0x00
status_lock = threading.Lock()

services = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x3e: "TesterPresent",
    0x83: "AccessTimingParameter",
    0x84: "SecuredDataTransmission",
    0x85: "ControlDTCSetting",
    0x86: "ResponseOnEvent",
    0x87: "LinkControl",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier",
    0x2a: "ReadDataByPeriodicIdentifier",
    0x2c: "DynamicallyDefineDataIdentifier",
    0x2e: "WriteDataByIdentifier",
    0x3d: "WriteMemoryByAddress",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x2f: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x21: "readDataByLocalIdentifier",
    0x3b: "writeDataByLocalIdentifier",
    0x37: "RequestTransferExit",
    0x18: "readDiagnosticTroubleCodesByStatus"
}

def setup_can(interface):
    """
    Initialize the SocketCAN bus on the given interface (e.g. 'vcan0', 'can0').
    """
    global bus
    try:
        print(f"[INFO] Setting up interface '{interface}'...")
        bus = can.interface.Bus(interface='socketcan', channel=interface, bitrate=500000)
        time.sleep(0.1)  # optional brief delay
    except OSError as e:
        print(f"[ERROR] Cannot find interface {interface}. Error: {e}")
        sys.exit(1)
    print("[INFO] CAN bus ready.")

def get_id_string(udsid):
    prefix = ""
    if (0x10 <= udsid <= 0x3e) or (0x80 <= udsid <= 0xbe):
        prefix = "Request_"
    if (0x50 <= udsid <= 0x7e) or (0xc0 <= udsid <= 0xfe):
        prefix = "PosResponse_"
        udsid -= 0x40
    if udsid == 0x7f:
        return "NegResponse"
    
    if udsid in services:
        id_s = prefix + services[udsid]
        if verbose:
            print(id_s)
    else:
        id_s = prefix + f"UNKNOWN_{udsid:02x}"
    return id_s

def handle_data(payload, pkt_len):
    """
    Handle incoming UDS frames (already parsed from the CAN message).
    Replace this placeholder logic with your real application code.
    """
    global security_access, session, key, attempts
    global wiper_status, can_id

    if len(payload) < 2:
        return
    
    udsid = int(payload[0:2], 16)
    id_s = get_id_string(udsid)
    # Example placeholder logic:
    # if can_id == 0x123:
    #     if udsid == 0x10:
    #         ...
    # else:
    #     ...
    # end placeholder

def recv_msg():
    """
    Blocking call to wait for the next CAN message.
    Returns (messageObj, dataString).
    """
    global bus
    message = bus.recv()  # Wait forever for a message
    if message is None:
        return None, ""
    c = '{0:f} {1:x} {2:x} '.format(message.timestamp, message.arbitration_id, message.dlc)
    s = ''
    for i in range(message.dlc):
        s += '{:02x} '.format(message.data[i])
    return message, s

def read_can_loop():
    """
    Infinite loop reading CAN messages from the bus in a background thread.
    """
    global can_id
    to_read = 0
    current_one = 0
    already_read = 0
    long_data = ""

    print("[INFO] CAN reading thread started.")

    while True:
        try:
            msg, data = recv_msg()  # blocks until a CAN frame arrives
            if msg is None:
                continue

            can_id = msg.arbitration_id
            data_type = data[0:2]  # e.g. '0x', '1x', '2x', '3x'
            if len(data_type) < 1:
                continue

            if data_type[0] == '0':
                # Single-frame
                pkt_len = int(data_type, 16)
                if len(data) < 3 + pkt_len * 3:
                    continue
                payload = data[3:3 + pkt_len * 3]
                if pkt_len:
                    handle_data(payload, pkt_len)

            elif data_type[0] == '1':
                # First frame
                if verbose:
                    print("[DEBUG] First frame received")
                if to_read != 0:
                    handle_data(long_data, already_read)
                
                pkt_len = (int(data_type[1], 16) << 8) + int(data[3:5], 16)
                current_one = 0
                to_read = pkt_len
                already_read = 6
                long_data = data[6:]
                # Send flow control if needed

            elif data_type[0] == '2':
                # Consecutive frame
                if verbose:
                    print("[DEBUG] Consecutive frame received")
                if current_one + 1 == int(data_type[1], 16):
                    current_one = int(data_type[1], 16)
                    payload = data[3:]
                    read_this_time = min(to_read - already_read, 7)
                    already_read += read_this_time
                    long_data += " " + data[3:3 + read_this_time * 3]
                    if already_read == to_read:
                        handle_data(long_data, to_read)
                        to_read = 0
                else:
                    if verbose:
                        print("[ERROR] Lost Packet")

            elif data_type[0] == '3':
                # Flow control
                if verbose:
                    print("[DEBUG] Flow control frame received")
                pass

        except KeyboardInterrupt:
            print("[INFO] CAN reading thread interrupted.")
            bus.shutdown()
            sys.exit(0)

def send_msg(arb_id, data, is_extended=False):
    """Send a CAN message with the given arbitration ID and data bytes."""
    global bus
    if bus is None:
        return  # bus not yet initialized
    try:
        msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=is_extended)
        bus.send(msg)
        if verbose:
            print(f"[INFO] Sent msg on {bus.channel_info}, ID={hex(arb_id)}, data={data}")
    except can.CanError:
        print("[ERROR] Message NOT sent")

def broadcast_wiper_data():
    """
    Continuously broadcasts wiper status frames on arbitration ID 0x058
    every 100ms.
    """
    global wiper_status
    print("[INFO] Starting wiper broadcast thread.")
    while True:
        with status_lock:
            stat_msg = [
                wiper_status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        send_msg(0x058, stat_msg)
        time.sleep(0.1)

def key_from_seed(seed):
    """
    Example seed->key function, inverting bytes with XOR 0xFF.
    """
    print("[DEBUG] Generated seed:", seed)
    key = [hex(seed_val ^ 0xFF) for seed_val in seed]
    print("[DEBUG] Calculated key:", key)
    return key

def handle_client_connection(sock):
    """
    Use a loop to read multiple messages from the same client. 
    We only exit when the client closes or there's an error.
    """
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                print("[INFO] Client disconnected (no more data).")
                break

            print(f"[INFO] Received from client: {data}")
            # Respond or process as needed
            sock.sendall(b"Hello from server!")
    
    except ConnectionResetError:
        print("[WARN] Connection reset by peer (client disconnected abruptly).")
    except Exception as e:
        print("[ERROR] Exception in handle_client_connection:", e)
    finally:
        sock.close()
        print("[INFO] Client socket closed.")

def main():
    """
    1) Parse command-line argument for interface name.
    2) Setup CAN.
    3) Start a separate thread to read CAN in the background.
    4) Start the TCP server in the main thread and accept a connection.
    """
    # 1) Parse interface name from sys.argv
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <can interface>")
        print("[INFO] Using default interface 'vcan0'.")
        interface = "vcan0"
    else:
        interface = sys.argv[1]

    # 2) Setup CAN
    setup_can(interface)

    # 3) Start reading CAN in a separate thread
    can_thread = threading.Thread(target=read_can_loop, daemon=True)
    can_thread.start()

    # 4) Start the TCP server in the main thread
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen(1)
    print(f"[INFO] Server listening on {IP}:{PORT}")

    while True:
        client_sock = None
        try:
            print("[INFO] Waiting for TCP client...")
            client_sock, addr = server_socket.accept()
            print(f"[INFO] Accepted connection from {addr}")

            # Start broadcasting wiper frames (only once or each time we get a new client)
            threading.Thread(target=broadcast_wiper_data, daemon=True).start()

            # Handle the client in a loop until they disconnect
            handle_client_connection(client_sock)

            # Break if you only want 1 client total. Otherwise, remove break to allow multiple.
            break

        except Exception as e:
            print("[ERROR] Exception in accept loop:", e)
            if client_sock is not None:
                client_sock.close()
            print("[INFO] Retrying...")

if __name__ == "__main__":
    main()

