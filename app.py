# app.py

import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

from config import SECRET_KEY, DEBUG, DATABASE, VPN_SERVERS, OPENVPN_CLIENT_CONFIG_DIR
from utils.auth import init_db, register_user, login_user, verify_session, log_intrusion
from utils.vpn import generate_vpn_config, store_vpn_config, get_user_configs, update_config_usage, delete_vpn_config

# Initialize Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Ensure database directory exists
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

# Ensure client configs directory exists
os.makedirs(OPENVPN_CLIENT_CONFIG_DIR, exist_ok=True)

# Initialize database
init_db(DATABASE)

@app.before_request
def check_session():
    """Check if user is logged in for protected routes."""
    # Public routes
    public_routes = ['index', 'login', 'register', 'static']
    
    # Check if the route is public
    if request.endpoint in public_routes:
        return
    
    # Check if user is logged in
    if 'user_id' not in session:
        flash('You need to login first', 'danger')
        return redirect(url_for('login'))

@app.route('/')
def index():
    """Landing page."""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        
        # Validate inputs
        if not username or not password or not email:
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        # Register user
        success, message = register_user(DATABASE, username, password, email)
        
        if success:
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate inputs
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        
        # Login user
        success, result = login_user(DATABASE, username, password, request.remote_addr)
        
        if success:
            session['user_id'] = result['user_id']
            session['username'] = username
            session.permanent = True
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(result, 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """User dashboard."""
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Get user's VPN configurations
    configs = get_user_configs(DATABASE, user_id)
    
    return render_template('dashboard.html', username=username, configs=configs, servers=VPN_SERVERS)

@app.route('/create_config', methods=['POST'])
def create_config():
    """Create a new VPN configuration."""
    user_id = session.get('user_id')
    username = session.get('username')
    server_country = request.form.get('server_country')
    
    if server_country not in VPN_SERVERS:
        flash('Invalid server selection', 'danger')
        return redirect(url_for('dashboard'))
    
    server_info = VPN_SERVERS[server_country]
    
    # Generate OpenVPN configuration
    # The generate_vpn_config function returns the config_path
    config_path = generate_vpn_config(server_info, username, OPENVPN_CLIENT_CONFIG_DIR)
    config_name = os.path.basename(config_path)
    
    # Get the encryption key from the certificate result
    # In a real implementation, you would need to retrieve this from generate_vpn_config
    # For now, we'll just store an empty or placeholder value
    encryption_key = None  # In a real scenario, this would be cert_result['encryption_key']
    
    # Store configuration in database with the encryption key
    store_vpn_config(DATABASE, user_id, config_name, server_country, encryption_key)
    
    flash('VPN configuration created successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download_config/<config_name>')
def download_config(config_name):
    """Download a VPN configuration file."""
    user_id = session.get('user_id')
    
    # Security check: verify that the config belongs to the user
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM vpn_configs WHERE config_name = ? AND user_id = ?",
        (config_name, user_id)
    )
    config_id = cursor.fetchone()
    conn.close()
    
    if not config_id:
        flash('Configuration not found or does not belong to you', 'danger')
        return redirect(url_for('dashboard'))
    
    # Update usage timestamp
    update_config_usage(DATABASE, config_id[0])
    
    # Send file for download
    return send_file(
        os.path.join(OPENVPN_CLIENT_CONFIG_DIR, config_name),
        as_attachment=True,
        download_name=config_name
    )

@app.route('/delete_config/<int:config_id>', methods=['POST'])
def delete_config(config_id):
    """Delete a VPN configuration."""
    user_id = session.get('user_id')
    
    success, message = delete_vpn_config(DATABASE, config_id, user_id)
    
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/intrusion_logs')
def intrusion_logs():
    """View intrusion logs (admin only)."""
    user_id = session.get('user_id')
    
    # Check if user is admin (user_id = 1)
    if user_id != 1:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get intrusion logs
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT il.id, u.username, il.ip_address, il.attempt_type, il.details, il.timestamp
        FROM intrusion_logs il
        LEFT JOIN users u ON il.user_id = u.id
        ORDER BY il.timestamp DESC
        """
    )
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('intrusion_logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=DEBUG)