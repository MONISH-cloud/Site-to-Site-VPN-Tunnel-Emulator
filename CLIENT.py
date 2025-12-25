# client_proxy.py (Final Code: Local SOCKS5 Listener with Timeout)
import socket
import threading
from cryptography.fernet import Fernet, InvalidToken
# Import specific socket exceptions for cleaner handling
from socket import error as socket_error, timeout as socket_timeout 
from crypto import ENCRYPTION_KEY, get_fernet 

# Local address and port for the BROWSER to connect to
LOCAL_PROXY_HOST = '127.0.0.1'
LOCAL_PROXY_PORT = 1080 
# Address and port of your Encrypted Server
REMOTE_SERVER_HOST = '127.0.0.1' 
REMOTE_SERVER_PORT = 65435 # Reverted to original port, ensure server matches
TIMEOUT_SECONDS = 60 # Define a timeout constant

fernet = get_fernet(ENCRYPTION_KEY)

# --- Resilient Forwarding Functions (Simplified, but needs Timeout in 'except') ---

def tunnel_to_remote(local_conn, remote_conn):
    """Encrypts data from the browser and sends it through the tunnel."""
    while True:
        try:
            data = local_conn.recv(4096)
            if not data: break
            # Note: This simple tunneling is prone to intermingled packets without length-prefixing
            remote_conn.sendall(fernet.encrypt(data))
        except (socket_error, socket_timeout, Exception): # Added socket_timeout
            break

def tunnel_from_remote(local_conn, remote_conn):
    """Reads encrypted data from the remote server, decrypts, and sends to the browser."""
    while True:
        try:
            encrypted_data = remote_conn.recv(4096)
            if not encrypted_data: break
            local_conn.sendall(fernet.decrypt(encrypted_data))
        except (socket_error, socket_timeout, InvalidToken, Exception): # Added socket_timeout
            break

# --- SOCKS Handshake Logic (Standard) ---

def handle_socks_handshake(local_conn):
    """Handles the SOCKS5 handshake to read the browser's destination address."""
    try:
        # 1. METHOD SELECTION
        data = local_conn.recv(262) 
        if not data or data[0] != 0x05: raise Exception("Invalid SOCKS version")
        
        local_conn.sendall(b'\x05\x00') # Send: SOCKS5, NO AUTH SUCCESS
        
        # 2. CONNECTION REQUEST HEADER
        data = local_conn.recv(4096)
        if data[1] != 0x01: raise Exception("SOCKS command not supported (must be CONNECT)")

        # 3. EXTRACT DESTINATION ADDRESS AND PORT
        addr_type = data[3]
        if addr_type == 0x01: 
            dest_host = socket.inet_ntoa(data[4:8])
            addr_len = 4
        elif addr_type == 0x03:
            addr_len = data[4]
            dest_host = data[5:5+addr_len].decode()
            addr_len += 1 
        else: raise Exception("Address type not supported")

        dest_port = int.from_bytes(data[4+addr_len : 6+addr_len], byteorder='big')
        
        # 4. SOCKS SUCCESS RESPONSE
        local_conn.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        
        return dest_host, dest_port

    except Exception:
        raise 

# --- Main Connection Handler (UPDATED with Timeouts) ---

def handle_local_connection(local_conn, addr):
    """Handles the browser's connection, extracts destination, and starts the tunnel."""
    remote_conn = None
    try:
        # NEW: Set timeout on the initial connection from the browser
        local_conn.settimeout(TIMEOUT_SECONDS) 
        
        # 1. SOCKS Handshake
        dest_host, dest_port = handle_socks_handshake(local_conn)
        print(f"[{addr[1]}] Browser requested: {dest_host}:{dest_port}")

        # 2. Send Destination Info to Encrypted Server (unprefixed)
        dest_info = f"{dest_host}:{dest_port}"
        remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # This connect call should now fail cleanly if server is down/blocked
        remote_conn.connect((REMOTE_SERVER_HOST, REMOTE_SERVER_PORT))
        
        # NEW: Set timeout on the connection to the remote server
        remote_conn.settimeout(TIMEOUT_SECONDS) 
        
        remote_conn.sendall(fernet.encrypt(dest_info.encode()))
        
        # 3. Start bi-directional data threads
        t1 = threading.Thread(target=tunnel_to_remote, args=(local_conn, remote_conn))
        t2 = threading.Thread(target=tunnel_from_remote, args=(local_conn, remote_conn))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
    except Exception as e:
        # Print error here to diagnose why the thread failed!
        # If the server is offline or the firewall is active, you will see the error here.
        # print(f"[{addr[1]}] Error: {e}") 
        pass
    finally:
        if remote_conn: remote_conn.close()
        local_conn.close()
        print(f"[{addr[1]}] Tunnel closed.")

# Main proxy listener loop
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LOCAL_PROXY_HOST, LOCAL_PROXY_PORT))
    s.listen(5)
    print(f"Local SOCKS Proxy listening on {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}")
    
    while True:
        try:
            conn, addr = s.accept()
            # The accept() call should be the only place that blocks indefinitely.
            threading.Thread(target=handle_local_connection, args=(conn, addr)).start()
        except KeyboardInterrupt:
            print("\nShutting down proxy...")
            break
        except Exception:
            pass