import os

SECRET_KEY = os.urandom(24)
DEBUG = True

# SQLite Database Configuration
DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database', 'netcrypt.db')

# OpenVPN Configuration
OPENVPN_BASE_CONFIG_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'openvpn')
OPENVPN_CLIENT_CONFIG_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'client_configs')

# OpenVPN server Configuration
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

# AES-256 Configuration
AES_KEY_SIZE = 256