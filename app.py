import flask
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import datetime
import jwt
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import uuid
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

# In-memory database for simplicity
users_db = {
    "alice": {
        "password": "password123",
        "sensitive_data": "CONFIDENTIAL: Alice's bank account number is 1234-5678-9012-3456",
        "sequence_number": 1  # Starting sequence number
    }
}

# In-memory token store for both scenarios
tokens_without_cert = {}
tokens_with_cert = {}

# Generate keys for server
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

server_public_key = server_private_key.public_key()

# Generate keys for client certificate
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

client_public_key = client_private_key.public_key()

# Create a self-signed client certificate
client_cert = x509.CertificateBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"client"),
    ])
).issuer_name(
    x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"client"),
    ])
).public_key(
    client_public_key
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).sign(client_private_key, hashes.SHA256())

# Convert keys and certificate to PEM format for storage/use
client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
client_private_key_pem = client_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

server_private_key_pem = server_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')


# Helper function to encrypt data with certificate
def encrypt_with_cert(data_dict, public_key):
    # Convert data to JSON string
    data_json = json.dumps(data_dict)

    # Generate a random AES key
    aes_key = os.urandom(32)  # 256 bit key
    iv = os.urandom(16)  # Initialization vector

    # Encrypt the data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data_json.encode()) + encryptor.finalize()

    # Encrypt the AES key with the public key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return everything needed for decryption
    result = {
        'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

    return result


# Helper function to decrypt data with private key
def decrypt_with_key(encrypted_package, private_key):
    # Extract components
    encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
    encrypted_key = base64.b64decode(encrypted_package['encrypted_key'])
    iv = base64.b64decode(encrypted_package['iv'])

    # Decrypt the AES key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Convert back to dictionary
    return json.loads(decrypted_data.decode('utf-8'))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        auth_type = request.form.get('auth_type')

        if username not in users_db or users_db[username]["password"] != password:
            return jsonify({"error": "Invalid credentials"}), 401

        # Generate JWT token
        if auth_type == 'without_cert':
            # Standard JWT without certificate protection
            payload = {
                'sub': username,
                'iat': datetime.datetime.utcnow(),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                'jti': str(uuid.uuid4())  # JWT ID for uniqueness
            }
            token = jwt.encode(payload, 'secret_key', algorithm='HS256')
            session['token'] = token
            # Store token for scenario without cert
            tokens_without_cert[token] = {"username": username, "used": False}
            return redirect(url_for('dashboard', auth_type=auth_type))

        elif auth_type == 'with_cert':
            # JWT with certificate protection and sequence number
            # Generate a nonce which will be signed by client
            nonce = os.urandom(16).hex()
            session['nonce'] = nonce
            session['username'] = username
            # Store current sequence number for this session
            session['sequence_number'] = users_db[username]['sequence_number']
            return render_template('cert_auth.html',
                                   nonce=nonce,
                                   username=username,
                                   sequence_number=users_db[username]['sequence_number'],
                                   client_private_key=client_private_key_pem,
                                   client_cert=client_cert_pem)

    return render_template('login.html')


@app.route('/cert_auth', methods=['POST'])
def cert_auth():
    data = request.json
    username = data.get('username')
    nonce = session.get('nonce', '')
    sequence_number = session.get('sequence_number', 1)

    # For demo purposes, we'll simulate certificate validation
    # In a real TLS implementation, this would verify the client certificate

    # Generate JWT with sequence number and nonce protection
    payload = {
        'sub': username,
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'jti': str(uuid.uuid4()),  # JWT ID
        'nonce': nonce,  # Add nonce to prevent replay
        'sequence_number': sequence_number  # Add sequence number like TLS
    }

    # Step 1: Sign the payload with the server's private key
    token = jwt.encode(payload, server_private_key_pem, algorithm='RS256')

    # Step 2: Encrypt the signed token using the client certificate
    # This simulates the TLS encryption layer
    encrypted_token_package = encrypt_with_cert(
        {'token': token, 'sequence_number': sequence_number},
        client_public_key
    )

    # Store token for scenario with cert
    tokens_with_cert[token] = {
        "username": username,
        "used": False,
        "nonce": nonce,
        "sequence_number": sequence_number
    }

    # Increment the sequence number for next login
    users_db[username]['sequence_number'] += 1

    # Store the encrypted token in session
    session['encrypted_token'] = encrypted_token_package
    session['token'] = token  # Also store unencrypted for demo purposes

    return jsonify({
        "success": True,
        "sequence_number": sequence_number,
        "redirect": url_for('dashboard', auth_type='with_cert')
    })


@app.route('/dashboard/<auth_type>')
def dashboard(auth_type):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        if auth_type == 'without_cert':
            payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
            # In a real system, we would check if token has been used
            # For demo, we'll allow it to show the vulnerability
            username = payload['sub']
        else:  # with_cert
            payload = jwt.decode(token, server_public_key, algorithms=['RS256'])
            # Check if token has been revoked or sequence is invalid
            token_info = tokens_with_cert.get(token)

            if not token_info:
                return "Invalid token! Access denied.", 401

            username = payload['sub']

            # The dashboard view doesn't validate the sequence number
            # This is just for display purposes

        return render_template('dashboard.html',
                               username=username,
                               auth_type=auth_type,
                               token=token,
                               sequence_number=payload.get('sequence_number', 'N/A'))

    except jwt.ExpiredSignatureError:
        return "Token expired. Please login again.", 401
    except jwt.InvalidTokenError:
        return "Invalid token. Please login again.", 401


@app.route('/api/resource', methods=['GET'])
def protected_resource():
    auth_header = request.headers.get('Authorization')
    auth_type = request.args.get('auth_type')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "No token provided"}), 401

    token = auth_header.split(' ')[1]

    try:
        if auth_type == 'without_cert':
            # Without certificate - vulnerable to replay
            payload = jwt.decode(token, 'secret_key', algorithms=['HS256'])
            username = payload['sub']
            sensitive_data = users_db.get(username, {}).get("sensitive_data", "No data available")
            return jsonify({
                "message": f"Protected resource for {username}",
                "success": True,
                "sensitive_data": sensitive_data
            })

        else:  # with_cert
            # With certificate and sequence number - protected against replay
            payload = jwt.decode(token, server_public_key, algorithms=['RS256'])
            username = payload['sub']
            token_sequence = payload.get('sequence_number')

            # Check if token sequence is valid
            token_info = tokens_with_cert.get(token)

            if not token_info:
                return jsonify({"error": "Invalid token or token not found!"}), 401

            # For secure TLS-like behavior, verify the sequence number matches what's expected
            expected_sequence = token_info["sequence_number"]

            if token_sequence != expected_sequence:
                return jsonify({
                    "error": f"Invalid sequence number! Expected {expected_sequence}, got {token_sequence}. Possible replay attack!"
                }), 401

            # Check if token has been used before (one-time use token)
            if token_info["used"]:
                return jsonify({
                    "error": "Token already used! Sequence mismatch. Replay attack detected!"
                }), 401

            # Mark token as used
            token_info["used"] = True

            sensitive_data = users_db.get(username, {}).get("sensitive_data", "No data available")
            return jsonify({
                "message": f"Protected resource for {username}",
                "success": True,
                "sensitive_data": sensitive_data,
                "sequence_number": token_sequence
            })

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@app.route('/attacker')
def attacker_page():
    return render_template('attacker.html')


@app.route('/simulate_mitm', methods=['POST'])
def simulate_mitm():
    # This endpoint simulates a MITM attack by capturing and reusing a token
    token = request.json.get('token')
    auth_type = request.json.get('auth_type')

    if not token:
        return jsonify({"error": "No token provided"}), 400

    # Simulate the attacker making a request with the captured token
    headers = {
        'Authorization': f'Bearer {token}'
    }

    # Simulate a delay to represent a different request
    time.sleep(1)

    # Use Flask's test client to simulate the request
    with app.test_client() as client:
        response = client.get(f'/api/resource?auth_type={auth_type}', headers=headers)

    data = response.get_json()
    status_code = response.status_code

    if status_code == 200:
        return jsonify({
            "success": True,
            "message": "Replay attack successful! Gained access to protected resource.",
            "sensitive_data": data.get("sensitive_data", "No sensitive data found"),
            "sequence_info": data.get("sequence_number", "No sequence information")
        })
    else:
        return jsonify({
            "success": False,
            "error": data.get("error", "Unknown error occurred during replay attack")
        })


if __name__ == '__main__':
    app.run(debug=True)