import os
import base64
import secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import hashlib

class CryptoManager:
    """
    Handles cryptographic operations for OpenVPN certificate generation and encryption
    """
    
    @staticmethod
    def generate_key():
        """Generate a random AES key"""
        return os.urandom(32)  # 32 bytes = 256 bits for AES-256
    
    @staticmethod
    def generate_iv():
        """Generate a random initialization vector"""
        return os.urandom(16)  # 16 bytes = 128 bits for AES block size
        
    @staticmethod
    def encrypt_data(data, key, iv=None):
        """
        Encrypt data using AES-256-CBC
        
        Args:
            data (bytes): Data to encrypt
            key (bytes): Encryption key (32 bytes for AES-256)
            iv (bytes, optional): Initialization vector (16 bytes)
            
        Returns:
            tuple: (encrypted_data, iv)
        """
        if iv is None:
            iv = CryptoManager.generate_iv()
            
        # Apply PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Create cipher and encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data, iv
    
    @staticmethod
    def decrypt_data(encrypted_data, key, iv):
        """
        Decrypt data using AES-256-CBC
        
        Args:
            encrypted_data (bytes): Encrypted data
            key (bytes): Encryption key (32 bytes for AES-256)
            iv (bytes): Initialization vector (16 bytes)
            
        Returns:
            bytes: Decrypted data
        """
        # Create cipher and decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    @staticmethod
    def encode_encrypted_data(encrypted_data, iv):
        """
        Encode encrypted data and IV to a string format for storage
        
        Args:
            encrypted_data (bytes): Encrypted data
            iv (bytes): Initialization vector
            
        Returns:
            str: Encoded string in format "iv:encrypted_data" (both base64 encoded)
        """
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        return f"{iv_b64}:{encrypted_b64}"
    
    @staticmethod
    def decode_encrypted_data(encoded_data):
        """
        Decode encrypted data from encoded string format
        
        Args:
            encoded_data (str): Encoded string in format "iv:encrypted_data"
            
        Returns:
            tuple: (encrypted_data, iv) as bytes
        """
        iv_b64, encrypted_b64 = encoded_data.split(':', 1)
        iv = base64.b64decode(iv_b64)
        encrypted_data = base64.b64decode(encrypted_b64)
        return encrypted_data, iv

class OpenvpnCertificateManager:
    """
    Generates and manages OpenVPN certificates and keys
    """
    
    @staticmethod
    def generate_ca_certificate():
        """
        Generate a Certificate Authority (CA) certificate and key
        
        Returns:
            tuple: (ca_cert_pem, ca_key_pem)
        """
        # Generate CA private key
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jakarta"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jakarta"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NetCrypt CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"NetCrypt Root CA"),
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).sign(ca_key, hashes.SHA256())
        
        # Serialize to PEM format
        ca_cert_pem = ca_cert.public_bytes(Encoding.PEM).decode('utf-8')
        ca_key_pem = ca_key.private_bytes(
            Encoding.PEM, 
            PrivateFormat.PKCS8, 
            NoEncryption()
        ).decode('utf-8')
        
        return ca_cert_pem, ca_key_pem
    
    @staticmethod
    def generate_client_certificate(ca_cert_pem, ca_key_pem, common_name):
        """
        Generate a client certificate signed by the CA
        
        Args:
            ca_cert_pem (str): CA certificate in PEM format
            ca_key_pem (str): CA private key in PEM format
            common_name (str): Client common name
            
        Returns:
            tuple: (client_cert_pem, client_key_pem)
        """
        # Load CA certificate and key
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'))
        ca_key = serialization.load_pem_private_key(
            ca_key_pem.encode('utf-8'),
            password=None
        )
        
        # Generate client key
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create client certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jakarta"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jakarta"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NetCrypt"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        client_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            client_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)  # 1 year
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]), critical=True
        ).sign(ca_key, hashes.SHA256())
        
        # Serialize to PEM format
        client_cert_pem = client_cert.public_bytes(Encoding.PEM).decode('utf-8')
        client_key_pem = client_key.private_bytes(
            Encoding.PEM, 
            PrivateFormat.PKCS8, 
            NoEncryption()
        ).decode('utf-8')
        
        return client_cert_pem, client_key_pem
    
    @staticmethod
    def generate_tls_auth_key():
        """
        Generate a TLS authentication key
        
        Returns:
            str: TLS authentication key in OpenVPN format
        """
        key_lines = ["-----BEGIN OpenVPN Static key V1-----"]
        # Generate 16 lines of random hex values (8 words per line)
        for _ in range(16):
            # line = " ".join(secrets.token_hex(4) for _ in range(8))
            line = secrets.token_hex(16)
            key_lines.append(line)
        key_lines.append("-----END OpenVPN Static key V1-----")
        
        return "\n".join(key_lines)

def generate_vpn_certificate_components(username):
    """
    Generate all required OpenVPN certificate components for a user
    
    Args:
        username (str): Username for which to generate certificates
        
    Returns:
        dict: Dictionary containing ca_cert, client_cert, client_key, and tls_auth_key
    """
    # Generate CA certificate
    ca_cert_pem, ca_key_pem = OpenvpnCertificateManager.generate_ca_certificate()
    
    # Generate client certificate
    client_cert_pem, client_key_pem = OpenvpnCertificateManager.generate_client_certificate(
        ca_cert_pem, ca_key_pem, f"client_{username}"
    )
    
    # Generate TLS authentication key
    tls_auth_key = OpenvpnCertificateManager.generate_tls_auth_key()
    
    return {
        'ca_cert': ca_cert_pem,
        'client_cert': client_cert_pem,
        'client_key': client_key_pem,
        'tls_auth_key': tls_auth_key
    }

def encrypt_vpn_components(components, key=None):
    """
    Encrypt OpenVPN certificate components using AES-256
    
    Args:
        components (dict): Dictionary containing certificate components
        key (bytes, optional): Encryption key (will be generated if None)
        
    Returns:
        dict: Dictionary containing encrypted components and the encryption key
    """
    if key is None:
        key = CryptoManager.generate_key()
    
    encrypted_components = {}
    
    # Encrypt each component
    for component_name, component_data in components.items():
        encrypted_data, iv = CryptoManager.encrypt_data(component_data.encode('utf-8'), key)
        encrypted_components[component_name] = CryptoManager.encode_encrypted_data(encrypted_data, iv)
    
    # Return encrypted components and the key
    return {
        'encrypted_components': encrypted_components,
        'encryption_key': base64.b64encode(key).decode('utf-8')
    }

def decrypt_vpn_components(encrypted_components, key_b64):
    """
    Decrypt OpenVPN certificate components
    
    Args:
        encrypted_components (dict): Dictionary containing encrypted components
        key_b64 (str): Base64-encoded encryption key
        
    Returns:
        dict: Dictionary containing decrypted components
    """
    key = base64.b64decode(key_b64)
    decrypted_components = {}
    
    # Decrypt each component
    for component_name, encoded_data in encrypted_components.items():
        encrypted_data, iv = CryptoManager.decode_encrypted_data(encoded_data)
        decrypted_data = CryptoManager.decrypt_data(encrypted_data, key, iv)
        decrypted_components[component_name] = decrypted_data.decode('utf-8')
    
    return decrypted_components

def get_vpn_certificate_components(username, encrypt=True):
    """
    Generate and optionally encrypt OpenVPN certificate components
    
    Args:
        username (str): Username for which to generate certificates
        encrypt (bool): Whether to encrypt the components
        
    Returns:
        dict: Dictionary containing certificate components (encrypted if encrypt=True)
    """
    # Generate VPN certificate components
    components = generate_vpn_certificate_components(username)
    
    if encrypt:
        # Encrypt components
        result = encrypt_vpn_components(components)
        return result
    else:
        return {'components': components, 'encryption_key': None}