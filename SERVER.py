# SERVER.py (Final Code: Encrypted Proxy Gateway with Timeout)
import socket
import threading
from cryptography.fernet import Fernet, InvalidToken
# Import specific socket exceptions for cleaner handling
from socket import error as socket_error, timeout as socket_timeout 
from crypto import ENCRYPTION_KEY, get_fernet 

HOST = '127.0.0.1'
PORT = 65435 # Using the updated port
fernet = get_fernet(ENCRYPTION_KEY)
TIMEOUT_SECONDS = 60 # Define a timeout constant

# --- Resilient Forwarding Functions ---

def forward_data_decrypt(source_conn, dest_conn):
    """Reads length header, receives the full encrypted message, decrypts, and forwards to website."""
    while True:
        try:
            # 1. Read the 4-byte length header
            header = source_conn.recv(4)
            if not header: break
            
            encrypted_len = int.from_bytes(header, 'big')
            
            # 2. Read EXACTLY the encrypted length using a loop
            encrypted_data = b''
            bytes_received = 0
            while bytes_received < encrypted_len:
                chunk = source_conn.recv(encrypted_len - bytes_received)
                if not chunk: raise ConnectionResetError
                encrypted_data += chunk
                bytes_received += len(chunk)
            
            # 3. Decrypt the complete token
            raw_data = fernet.decrypt(encrypted_data)
            
            # 4. Forward the raw data
            dest_conn.sendall(raw_data)
            
        # Catch all connection/crypto errors, including the socket.timeout
        except (socket_error, socket_timeout, InvalidToken, Exception): 
            break 

def forward_data_encrypt(source_conn, dest_conn):
    """Receives raw chunks from the internet, encrypts, prefixes with length, and forwards back to client."""
    while True:
        try:
            raw_data = source_conn.recv(4096)
            if not raw_data: break
            
            # Encrypt the data
            encrypted_data = fernet.encrypt(raw_data)

            # CRITICAL: Add length prefix for client to read correctly
            length = len(encrypted_data).to_bytes(4, 'big')
            
            dest_conn.sendall(length + encrypted_data)
            
        except (socket_error, socket_timeout, Exception):
            break

# --- Main Proxy Handler (UPDATED) ---

def handle_proxy_client(conn, addr):
    """Receives encrypted destination info, connects to the final site, and tunnels traffic."""
    print(f"THREAD START: Proxy client connected by {addr}.")
    dest_socket = None
    
    try:
        # 1. Set timeout on the connection from the client
        conn.settimeout(TIMEOUT_SECONDS) 
        
        # 2. Receive and decrypt the destination info 
        encrypted_dest = conn.recv(1024)
        if not encrypted_dest: return
        
        dest_info = fernet.decrypt(encrypted_dest).decode()
        dest_host, dest_port = dest_info.split(':')
        dest_port = int(dest_port)
        
        print(f"[{addr[1]}] Decrypted destination: {dest_host}:{dest_port}")

        # 3. Connect to the final destination
        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.connect((dest_host, dest_port))
        
        # *** NEW: Set timeout for the newly established tunnel ***
        dest_socket.settimeout(TIMEOUT_SECONDS) 
        
        print(f"[{addr[1]}] Tunnel established to {dest_host}:{dest_port}")

        # 4. Start bi-directional data forwarding
        t_recv = threading.Thread(target=forward_data_decrypt, args=(conn, dest_socket))
        t_send = threading.Thread(target=forward_data_encrypt, args=(dest_socket, conn))
        
        t_recv.start()
        t_send.start()
        
        # Wait for threads to complete (they will complete on data EOF or timeout)
        t_recv.join() 
        t_send.join() 
        
    except Exception as e:
        # Pass silently to ensure 'finally' block executes cleanly
        pass
    finally:
        if dest_socket: dest_socket.close()
        conn.close()
        print(f"THREAD END: Connection closed for {addr}.")


# Main server loop
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}")
    
    while True:
        try:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_proxy_client, args=(conn, addr))
            client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            break
        except Exception as e:
            print(f"Main loop error: {e}")