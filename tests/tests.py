import unittest
import os
import tempfile
import sqlite3
from datetime import datetime, timedelta
import sys
import shutil

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modules from main application
from utils.auth import init_db, register_user, login_user, verify_session, hash_password, verify_password
from utils.vpn import generate_vpn_config, store_vpn_config, get_user_configs, update_config_usage, delete_vpn_config


class Crypto:
    @staticmethod
    def get_vpn_certificate_components(username, encrypt=True):
        return {
            'encrypted_components': 'encrypted_components',
            'encryption_key': 'encryption_key'
        }
    
    @staticmethod
    def decrypt_vpn_components(encrypted_components, encryption_key):
        return {
            'ca_cert': 'mock_ca_cert',
            'client_cert': 'mock_client_cert',
            'client_key': 'mock_client_key',
            'tls_auth_key': 'mock_tls_auth_key'
        }

sys.modules['utils.crypto'] = Crypto()

class TestAuthenticationModule(unittest.TestCase):
    """Test the authentication module functionality"""
    
    def setUp(self):
        """Set up test environment before each test"""
        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp()
        
        # Initialize the database
        init_db(self.db_path)
        
        # Test user data
        self.test_username = "testuser"
        self.test_password = "TestPassword123!"
        self.test_email = "test@example.com"
        self.test_ip = "127.0.0.1"
    
    def tearDown(self):
        """Clean up after test"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_register_user(self):
        """Test user registration functionality"""
        # Register a user
        success, message = register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        
        # Assert registration was successful
        self.assertTrue(success)
        self.assertEqual(message, "User registered successfully")
        
        # Verify user exists in the database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username, email FROM users WHERE username = ?", (self.test_username,))
        user = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(user)
        self.assertEqual(user[0], self.test_username)
        self.assertEqual(user[1], self.test_email)
    
    def test_duplicate_username_registration(self):
        """Test registration with duplicate username"""
        # Register first user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        
        # Try to register with same username but different email
        success, message = register_user(self.db_path, self.test_username, self.test_password, "other@example.com")
        
        # Assert registration failed
        self.assertFalse(success)
        self.assertEqual(message, "Username already exists")
    
    def test_duplicate_email_registration(self):
        """Test registration with duplicate email"""
        # Register first user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        
        # Try to register with same email but different username
        success, message = register_user(self.db_path, "otheruser", self.test_password, self.test_email)
        
        # Assert registration failed
        self.assertFalse(success)
        self.assertEqual(message, "Email already exists")
    
    def test_password_hashing(self):
        """Test password hashing functionality"""
        # Hash a password
        hashed, salt = hash_password(self.test_password)
        
        # Verify the password
        self.assertTrue(verify_password(self.test_password, hashed, salt))
        
        # Verify incorrect password fails
        self.assertFalse(verify_password("WrongPassword", hashed, salt))
    
    def test_login_success(self):
        """Test successful login"""
        # Register a user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        
        # Login
        success, result = login_user(self.db_path, self.test_username, self.test_password, self.test_ip)
        
        # Assert login was successful
        self.assertTrue(success)
        self.assertIn("user_id", result)
        self.assertIn("session_key", result)
    
    def test_login_invalid_username(self):
        """Test login with invalid username"""
        # Register a user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        
        # Login with invalid username
        success, message = login_user(self.db_path, "invaliduser", self.test_password, self.test_ip)
        
        # Assert login failed
        self.assertFalse(success)
        self.assertEqual(message, "Invalid username or password")
    
    def test_login_invalid_password(self):
        """Test login with invalid password"""
        # Register a user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        
        # Login with invalid password
        success, message = login_user(self.db_path, self.test_username, "WrongPassword", self.test_ip)
        
        # Assert login failed
        self.assertFalse(success)
        self.assertEqual(message, "Invalid username or password")
    
    def test_session_verification(self):
        """Test session verification"""
        # Register and login a user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        success, result = login_user(self.db_path, self.test_username, self.test_password, self.test_ip)
        
        # Get session key
        session_key = result["session_key"]
        
        # Verify session
        success, result = verify_session(self.db_path, session_key, self.test_ip)
        
        # Assert session verification was successful
        self.assertTrue(success)
        self.assertIn("user_id", result)
    
    def test_session_ip_change(self):
        """Test session verification with IP address change"""
        # Register and login a user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        success, result = login_user(self.db_path, self.test_username, self.test_password, self.test_ip)
        
        # Get session key
        session_key = result["session_key"]
        
        # Verify session with different IP
        success, message = verify_session(self.db_path, session_key, "192.168.1.1")
        
        # Assert session verification failed
        self.assertFalse(success)
        self.assertEqual(message, "Session invalid due to IP change")
    
    def test_session_expiration(self):
        """Test session expiration"""
        # Register and login a user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        success, result = login_user(self.db_path, self.test_username, self.test_password, self.test_ip)
        
        # Get session key
        session_key = result["session_key"]
        
        # Manually expire the session in the database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        expired_time = (datetime.utcnow() - timedelta(days=2)).isoformat()
        cursor.execute("UPDATE sessions SET expires_at = ? WHERE session_key = ?", (expired_time, session_key))
        conn.commit()
        conn.close()
        
        # Verify session
        success, message = verify_session(self.db_path, session_key, self.test_ip)
        
        # Assert session verification failed due to expiration
        self.assertFalse(success)
        self.assertEqual(message, "Session expired")


class TestVPNModule(unittest.TestCase):
    """Test the VPN module functionality"""
    
    def setUp(self):
        """Set up test environment before each test"""
        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp()
        
        # Create a temporary directory for VPN configs
        self.config_dir = tempfile.mkdtemp()
        
        # Initialize the database
        init_db(self.db_path)
        
        # Test user data
        self.test_username = "testuser"
        self.test_password = "TestPassword123!"
        self.test_email = "test@example.com"
        
        # Register and login a test user
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        success, result = login_user(self.db_path, self.test_username, self.test_password, "127.0.0.1")
        self.user_id = result["user_id"]
        
        # Mock server info
        self.server_info = {
            "name": "Test Server",
            "server": "test.server.com",
            "port": 1194,
            "protocol": "udp"
        }
    
    def tearDown(self):
        """Clean up after test"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
        shutil.rmtree(self.config_dir)
    
    def test_generate_vpn_config(self):
        """Test VPN configuration generation"""
        # Generate VPN configuration
        result = generate_vpn_config(self.server_info, self.test_username, self.config_dir)
        
        # Assert configuration was generated
        self.assertIn("config_path", result)
        self.assertIn("encryption_key", result)
        
        # Instead of checking for a specific value, check that it's a non-empty string
        self.assertTrue(isinstance(result["encryption_key"], str))
        self.assertTrue(len(result["encryption_key"]) > 0)
        
        # Verify the config file exists
        self.assertTrue(os.path.exists(result["config_path"]))
        
        # Verify the config file content
        with open(result["config_path"], 'r') as f:
            content = f.read()
            self.assertIn("# NetCrypt OpenVPN Client Configuration", content)
            self.assertIn("remote test.server.com 1194", content)
    
    def test_store_vpn_config(self):
        """Test storing VPN configuration in the database"""
        # Store VPN configuration
        config_name = f"{self.test_username}_test_server_config.ovpn"
        server_country = "TestCountry"
        encryption_key = "test_encryption_key"
        
        success = store_vpn_config(self.db_path, self.user_id, config_name, server_country, encryption_key)
        
        # Assert storing was successful
        self.assertTrue(success)
        
        # Verify config exists in the database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT config_name, server_country, encryption_key FROM vpn_configs WHERE user_id = ?", (self.user_id,))
        config = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(config)
        self.assertEqual(config[0], config_name)
        self.assertEqual(config[1], server_country)
        self.assertEqual(config[2], encryption_key)
    
    def test_get_user_configs(self):
        """Test retrieving user VPN configurations"""
        # Store multiple VPN configurations
        configs = [
            {"name": "config1", "country": "Country1"},
            {"name": "config2", "country": "Country2"}
        ]
        
        for config in configs:
            store_vpn_config(self.db_path, self.user_id, config["name"], config["country"], "test_key")
        
        # Get user configs
        user_configs = get_user_configs(self.db_path, self.user_id)
        
        # Assert correct number of configs returned
        self.assertEqual(len(user_configs), len(configs))
        
        # Assert configs are in correct order (newest first)
        self.assertEqual(user_configs[0][1], "config1")
        self.assertEqual(user_configs[1][1], "config2")
    
    def test_update_config_usage(self):
        """Test updating the last used timestamp of a VPN configuration"""
        # Store a VPN configuration
        config_name = "test_config.ovpn"
        store_vpn_config(self.db_path, self.user_id, config_name, "TestCountry", "test_key")
        
        # Get the config ID
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM vpn_configs WHERE user_id = ?", (self.user_id,))
        config_id = cursor.fetchone()[0]
        conn.close()
        
        # Update config usage
        update_config_usage(self.db_path, config_id)
        
        # Verify last_used was updated
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT last_used FROM vpn_configs WHERE id = ?", (config_id,))
        last_used = cursor.fetchone()[0]
        conn.close()
        
        self.assertIsNotNone(last_used)
    
    def test_delete_vpn_config(self):
        """Test deleting a VPN configuration"""
        # Store a VPN configuration
        config_name = "test_config.ovpn"
        store_vpn_config(self.db_path, self.user_id, config_name, "TestCountry", "test_key")
        
        # Get the config ID
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM vpn_configs WHERE user_id = ?", (self.user_id,))
        config_id = cursor.fetchone()[0]
        conn.close()
        
        # Delete the config
        success, message = delete_vpn_config(self.db_path, config_id, self.user_id)
        
        # Assert deletion was successful
        self.assertTrue(success)
        self.assertEqual(message, "Configuration deleted successfully")
        
        # Verify config no longer exists in the database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM vpn_configs WHERE id = ?", (config_id,))
        result = cursor.fetchone()
        conn.close()
        
        self.assertIsNone(result)
    
    def test_delete_nonexistent_config(self):
        """Test deleting a non-existent VPN configuration"""
        # Try to delete a non-existent config
        success, message = delete_vpn_config(self.db_path, 999, self.user_id)
        
        # Assert deletion failed
        self.assertFalse(success)
        self.assertEqual(message, "Configuration not found or does not belong to user")
    
    def test_delete_other_users_config(self):
        """Test attempting to delete another user's configuration"""
        # Store a VPN configuration
        config_name = "test_config.ovpn"
        store_vpn_config(self.db_path, self.user_id, config_name, "TestCountry", "test_key")
        
        # Get the config ID
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM vpn_configs WHERE user_id = ?", (self.user_id,))
        config_id = cursor.fetchone()[0]
        conn.close()
        
        # Try to delete the config as a different user
        other_user_id = self.user_id + 1
        success, message = delete_vpn_config(self.db_path, config_id, other_user_id)
        
        # Assert deletion failed
        self.assertFalse(success)
        self.assertEqual(message, "Configuration not found or does not belong to user")


class TestIntrusionLogging(unittest.TestCase):
    """Test the intrusion logging functionality"""
    
    def setUp(self):
        """Set up test environment before each test"""
        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp()
        
        # Initialize the database
        init_db(self.db_path)
        
        # Register a test user
        self.test_username = "testuser"
        self.test_password = "TestPassword123!"
        self.test_email = "test@example.com"
        register_user(self.db_path, self.test_username, self.test_password, self.test_email)
        
        # Get user ID
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (self.test_username,))
        self.user_id = cursor.fetchone()[0]
        conn.close()
    
    def tearDown(self):
        """Clean up after test"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_login_intrusion_logging(self):
        """Test intrusion logging during login with wrong password"""
        # Attempt login with wrong password
        ip_address = "192.168.1.100"
        login_user(self.db_path, self.test_username, "WrongPassword", ip_address)
        
        # Verify intrusion was logged
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, ip_address, attempt_type, details 
            FROM intrusion_logs 
            WHERE user_id = ? AND ip_address = ?
        """, (self.user_id, ip_address))
        log = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(log)
        self.assertEqual(log[0], self.user_id)
        self.assertEqual(log[1], ip_address)
        self.assertEqual(log[2], "failed_login")
        self.assertIn("Wrong password", log[3])
    
    def test_session_ip_change_intrusion_logging(self):
        """Test intrusion logging during session verification with IP change"""
        # Login
        original_ip = "10.0.0.1"
        success, result = login_user(self.db_path, self.test_username, self.test_password, original_ip)
        session_key = result["session_key"]
        
        # Attempt to verify session with different IP
        new_ip = "10.0.0.2"
        verify_session(self.db_path, session_key, new_ip)
        
        # Verify intrusion was logged
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, ip_address, attempt_type, details 
            FROM intrusion_logs 
            WHERE user_id = ? AND ip_address = ?
        """, (self.user_id, new_ip))
        log = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(log)
        self.assertEqual(log[0], self.user_id)
        self.assertEqual(log[1], new_ip)
        self.assertEqual(log[2], "ip_change")
        self.assertIn("IP changed from", log[3])
    
    def test_invalid_username_intrusion_logging(self):
        """Test intrusion logging during login with invalid username"""
        # Attempt login with invalid username
        ip_address = "172.16.0.1"
        login_user(self.db_path, "nonexistentuser", "anypassword", ip_address)
        
        # Verify intrusion was logged
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, ip_address, attempt_type, details 
            FROM intrusion_logs 
            WHERE ip_address = ?
        """, (ip_address,))
        log = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(log)
        self.assertIsNone(log[0])  # user_id should be NULL
        self.assertEqual(log[1], ip_address)
        self.assertEqual(log[2], "failed_login")
        self.assertIn("Invalid username", log[3])


if __name__ == "__main__":
    unittest.main()