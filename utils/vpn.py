import os
import random
import string
from datetime import datetime
import sqlite3
import base64

# Import from crypto.py
from utils.crypto import get_vpn_certificate_components, decrypt_vpn_components

def generate_vpn_config(server_info, username, client_configs_dir):
    """
    Generate an OpenVPN client configuration file.
    
    Args:
        server_info: Dictionary containing server information
        username: Username for the VPN connection
        client_configs_dir: Directory to store client configs
        
    Returns:
        Path to the generated .ovpn file
    """
    # Create client configs directory if it doesn't exist
    if not os.path.exists(client_configs_dir):
        os.makedirs(client_configs_dir)
    
    # Generate unique config name
    config_name = f"{username}_{server_info['name'].lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ovpn"
    config_path = os.path.join(client_configs_dir, config_name)
    
    # Generate certificate components
    cert_result = get_vpn_certificate_components(username, encrypt=True)
    encrypted_components = cert_result['encrypted_components']
    encryption_key = cert_result['encryption_key']
    
    # Decrypt components for embedding in config file
    decrypted_components = decrypt_vpn_components(encrypted_components, encryption_key)
    
    # Generate client configuration
    config_content = f"""# NetCrypt OpenVPN Client Configuration
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Server: {server_info['name']}

client
dev tun
proto {server_info['protocol']}
remote {server_info['server']} {server_info['port']}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
comp-lzo
verb 3
auth-user-pass
redirect-gateway def1
remote-cert-tls server

# Certificate Authentication
<ca>
{decrypted_components['ca_cert']}
</ca>

<cert>
{decrypted_components['client_cert']}
</cert>

<key>
{decrypted_components['client_key']}
</key>

<tls-auth>
{decrypted_components['tls_auth_key']}
</tls-auth>
"""
    
    # Write configuration to file
    with open(config_path, 'w') as f:
        f.write(config_content)
    
    # Store encryption key in database along with config info
    # This would be implemented in the store_vpn_config function
    
    return config_path

def store_vpn_config(db_path, user_id, config_name, server_country, encryption_key=None):
    """Store VPN configuration information in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Check if encryption_key was provided and update query accordingly
    if encryption_key:
        cursor.execute(
            """INSERT INTO vpn_configs 
               (user_id, config_name, server_country, encryption_key, created_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, config_name, server_country, encryption_key, current_time)
        )
    else:
        cursor.execute(
            """INSERT INTO vpn_configs 
               (user_id, config_name, server_country, created_at) 
               VALUES (?, ?, ?, ?)""",
            (user_id, config_name, server_country, current_time)
        )
    
    conn.commit()
    conn.close()
    
    return True

def get_user_configs(db_path, user_id):
    """Get all VPN configurations for a user."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        """SELECT id, config_name, server_country, encryption_key, created_at, last_used 
           FROM vpn_configs WHERE user_id = ? ORDER BY created_at DESC""",
        (user_id,)
    )
    
    configs = cursor.fetchall()
    conn.close()
    
    return configs

def update_config_usage(db_path, config_id):
    """Update the last_used timestamp for a VPN configuration."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE vpn_configs SET last_used = ? WHERE id = ?",
        (datetime.now(), config_id)
    )
    
    conn.commit()
    conn.close()

def delete_vpn_config(db_path, config_id, user_id):
    """Delete a VPN configuration."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Verify that the config belongs to the user
    cursor.execute(
        "SELECT id FROM vpn_configs WHERE id = ? AND user_id = ?",
        (config_id, user_id)
    )
    
    if not cursor.fetchone():
        conn.close()
        return False, "Configuration not found or does not belong to user"
    
    cursor.execute("DELETE FROM vpn_configs WHERE id = ?", (config_id,))
    
    conn.commit()
    conn.close()
    
    return True, "Configuration deleted successfully"