# config.py

import os

# Konfigurasi dasar
SECRET_KEY = os.urandom(24)
DEBUG = True

# Konfigurasi database SQLite
DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database', 'netcrypt.db')

# Konfigurasi OpenVPN
OPENVPN_BASE_CONFIG_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'openvpn')
OPENVPN_CLIENT_CONFIG_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'client_configs')

# Konfigurasi server OpenVPN
VPN_SERVERS = {
    'id': {
        'name': 'Indonesia',
        'server': '103.10.124.1',
        'port': 1194,
        'protocol': 'udp'
    },
    'sg': {
        'name': 'Singapore',
        'server': '103.15.226.1',
        'port': 1194,
        'protocol': 'udp'
    },
    'us': {
        'name': 'United States',
        'server': '104.16.89.1',
        'port': 1194,
        'protocol': 'udp'
    }
}

# Konfigurasi AES-256
AES_KEY_SIZE = 256