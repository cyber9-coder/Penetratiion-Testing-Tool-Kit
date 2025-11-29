import os
import json
import socket
import whois
import dns.resolver
import requests
import threading
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from urllib.parse import urlparse

# Import utility modules
from utils.network_utils import scan_ports, perform_whois_lookup, perform_dns_lookup
from utils.web_utils import test_sql_injection, test_xss_vulnerability, enumerate_subdomains, get_http_headers, test_login
from forms import LoginForm, RegistrationForm

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersec.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
from models import db, User, ScanResult
db.init_app(app)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
# Set login view (using attribute assignment even if LSP shows error)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    return User.get(user_id)

# Create tables and a demo user if it doesn't exist
with app.app_context():
    db.create_all()
    # Create a demo user if none exists
    if not User.find_by_email("demo@example.com"):
        User.create(username="demo", email="demo@example.com", password="password123")

@app.route('/')
def index():
    """Render the main application page"""
    return render_template('index.html')

@app.route('/results')
@login_required
def user_results():
    """View saved scan results"""
    return render_template('results.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.find_by_email(form.email.data)
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash('Login successful!', 'success')
        
        # Redirect to the page the user was trying to access
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
        return redirect(next_page)
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.create(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/api/port_scan', methods=['POST'])
@login_required
def port_scan():
    """API endpoint for port scanning (requires authentication)"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    target = data.get('target', '')
    port_range = data.get('port_range', '1-1024')
    
    if not target:
        return jsonify({'error': 'Please enter a target IP or hostname'}), 400
        
    try:
        start_port, end_port = map(int, port_range.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            return jsonify({'error': 'Invalid port range. Use format start-end (1-65535)'}), 400
    except:
        return jsonify({'error': 'Invalid port range format. Use start-end (e.g., 1-1024)'}), 400
        
    # Run the port scan in a background thread
    results = scan_ports(target, start_port, end_port)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="Port Scan",
            target=target,
            result_data=json.dumps(results)
        )
    
    return jsonify(results)

@app.route('/api/brute_force', methods=['POST'])
@login_required
def brute_force():
    """API endpoint for testing login (requires authentication)"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    url = data.get('url', '')
    username = data.get('username', '')
    
    if not url or not username:
        return jsonify({'error': 'Please enter both URL and username'}), 400
    
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
    except:
        return jsonify({'error': 'Invalid URL'}), 400
        
    results = test_login(url, username)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="Brute Force Test",
            target=f"{url} (username: {username})",
            result_data=json.dumps(results)
        )
    
    return jsonify(results)

@app.route('/api/whois_lookup', methods=['POST'])
def whois_lookup():
    """API endpoint for WHOIS lookup"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Please enter a domain'}), 400
        
    result = perform_whois_lookup(domain)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="WHOIS Lookup",
            target=domain,
            result_data=json.dumps(result)
        )
    
    return jsonify(result)

@app.route('/api/dns_lookup', methods=['POST'])
def dns_lookup():
    """API endpoint for DNS lookup"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Please enter a domain'}), 400
        
    result = perform_dns_lookup(domain)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="DNS Lookup",
            target=domain,
            result_data=json.dumps(result)
        )
    
    return jsonify(result)

@app.route('/api/sqli_test', methods=['POST'])
@login_required
def sqli_test():
    """API endpoint for SQL injection testing (requires authentication)"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'Please enter a URL to test'}), 400
        
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
    except:
        return jsonify({'error': 'Invalid URL'}), 400
        
    result = test_sql_injection(url)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="SQL Injection Test",
            target=url,
            result_data=json.dumps(result)
        )
    
    return jsonify(result)

@app.route('/api/xss_test', methods=['POST'])
@login_required
def xss_test():
    """API endpoint for XSS vulnerability testing (requires authentication)"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'Please enter a URL to test'}), 400
        
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
    except:
        return jsonify({'error': 'Invalid URL'}), 400
        
    result = test_xss_vulnerability(url)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="XSS Vulnerability Test",
            target=url,
            result_data=json.dumps(result)
        )
    
    return jsonify(result)

@app.route('/api/subdomain_enum', methods=['POST'])
@login_required
def subdomain_enum():
    """API endpoint for subdomain enumeration (requires authentication)"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Please enter a domain'}), 400
        
    result = enumerate_subdomains(domain)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="Subdomain Enumeration",
            target=domain,
            result_data=json.dumps(result)
        )
    
    return jsonify(result)

@app.route('/api/header_view', methods=['POST'])
@login_required
def header_view():
    """API endpoint for HTTP header viewing (requires authentication)"""
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400
        
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
    except:
        return jsonify({'error': 'Invalid URL'}), 400
        
    result = get_http_headers(url)
    
    # Save results to database if user is authenticated
    if current_user.is_authenticated:
        ScanResult.create(
            user_id=current_user.id,
            tool_name="HTTP Headers",
            target=url,
            result_data=json.dumps(result)
        )
    
    return jsonify(result)

@app.route('/api/saved_results', methods=['GET'])
@login_required
def get_saved_results():
    """API endpoint to get saved scan results for the current user"""
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    results = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.created_at.desc()).all()
    
    results_list = []
    for result in results:
        results_list.append({
            'id': result.id,
            'tool_name': result.tool_name,
            'target': result.target,
            'result_data': json.loads(result.result_data),
            'created_at': result.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'success': True,
        'count': len(results_list),
        'results': results_list
    })

@app.route('/api/saved_results/<int:result_id>', methods=['DELETE'])
@login_required
def delete_saved_result(result_id):
    """API endpoint to delete a saved scan result"""
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    result = ScanResult.query.get_or_404(result_id)
    
    # Ensure the result belongs to the current user
    if result.user_id != current_user.id:
        return jsonify({'error': 'You are not authorized to delete this result'}), 403
    
    # Delete the result
    db.session.delete(result)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Result deleted successfully'
    })

@app.route('/api/saved_results/clear', methods=['DELETE'])
@login_required
def clear_saved_results():
    """API endpoint to clear all saved scan results for the current user"""
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Delete all results for the current user
    results = ScanResult.query.filter_by(user_id=current_user.id).all()
    for result in results:
        db.session.delete(result)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'All results cleared successfully'
    })

@app.route('/api/save_results', methods=['POST'])
def save_results():
    """API endpoint for saving results (returns the content to be downloaded on client side)"""
    data = request.json
    results = data.get('results', '')
    
    if not results:
        return jsonify({'error': 'No results to save'}), 400
        
    # Return the results as text, frontend will handle download
    return jsonify({
        'success': True,
        'results': results,
        'filename': f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    })

@app.route('/api/theme', methods=['POST'])
@login_required
def update_theme():
    """API endpoint for updating user theme preference"""
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Handle both JSON and form data
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    theme = data.get('theme', '')
    
    if not theme or theme not in ['light', 'dark']:
        return jsonify({'error': 'Invalid theme option'}), 400
    
    # Update the user's theme
    result = current_user.update_theme(theme)
    if not result:
        return jsonify({'error': 'Failed to update theme'}), 500
    
    return jsonify({
        'success': True,
        'theme': theme,
        'message': 'Theme updated successfully'
    })

@app.route('/api/dashboard', methods=['GET'])
def dashboard_data():
    """API endpoint for getting dashboard threat data"""
    # Get current user's scan results if authenticated
    if current_user.is_authenticated:
        # Get the latest scan results from the database
        scan_results = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.created_at.desc()).limit(10).all()
    else:
        scan_results = []
    
    # Calculate overall threat level based on scan history, vulnerabilities found, etc.
    # In a real application, this would be more sophisticated with actual threat intelligence
    if scan_results:
        # Base calculation on number and types of vulnerabilities found
        vulnerability_count = 0
        sql_injection_found = False
        xss_found = False
        network_vulnerabilities = 0
        
        for result in scan_results:
            result_data = result.result_data
            
            # Check for SQL injection vulnerabilities
            if result.tool_name == 'SQL Injection Test' and 'VULNERABLE' in result_data:
                sql_injection_found = True
                vulnerability_count += 10
            
            # Check for XSS vulnerabilities
            if result.tool_name == 'XSS Test' and 'VULNERABLE' in result_data:
                xss_found = True
                vulnerability_count += 8
            
            # Check for open ports from port scans
            if result.tool_name == 'Port Scanner':
                try:
                    if isinstance(result_data, str):
                        result_data_dict = json.loads(result_data)
                    else:
                        result_data_dict = result_data
                    
                    open_ports = result_data_dict.get('open_ports', [])
                    if open_ports:
                        # Add risk based on number of open ports and well-known sensitive ports
                        sensitive_ports = [21, 22, 23, 25, 53, 3306, 5432]
                        for port in open_ports:
                            network_vulnerabilities += 1
                            if int(port) in sensitive_ports:
                                network_vulnerabilities += 2
                except (json.JSONDecodeError, AttributeError, KeyError):
                    pass  # Skip if there's an issue with the result data
        
        # Calculate overall threat level (scale 0-100)
        overall_threat_level = min(100, vulnerability_count * 5 + network_vulnerabilities * 2)
        
        # Calculate individual risk indicators
        network_vulnerability = min(100, network_vulnerabilities * 10)
        web_application_risk = min(100, 30 + (50 if sql_injection_found else 0) + (40 if xss_found else 0))
        authentication_security = 20  # Base value, would be calculated from actual auth tests
        data_protection = 25  # Base value, would be calculated from actual data protection tests
    else:
        # Default values for no scan history
        overall_threat_level = 15
        network_vulnerability = 10
        web_application_risk = 25
        authentication_security = 15
        data_protection = 20
    
    # Generate recent activity based on scan history and detected threats
    recent_activity = []
    
    # Add scan history as activities
    for result in scan_results[:5]:  # Use the 5 most recent scans
        severity = "Low"
        description = f"Scan completed on {result.target}"
        
        # Determine severity based on tool and results
        if result.tool_name == 'SQL Injection Test' and 'VULNERABLE' in result.result_data:
            severity = "High"
            description = f"SQL Injection vulnerability detected on {result.target}"
        elif result.tool_name == 'XSS Test' and 'VULNERABLE' in result.result_data:
            severity = "High"
            description = f"Cross-Site Scripting vulnerability detected on {result.target}"
        elif result.tool_name == 'Port Scanner':
            try:
                # Parse the result data to check for specific issues
                if isinstance(result.result_data, str):
                    result_data = json.loads(result.result_data)
                else:
                    result_data = result.result_data
                
                open_ports = result_data.get('open_ports', [])
                if any(int(port) in [21, 22, 23, 25, 3306, 5432] for port in open_ports):
                    severity = "Medium"
                    description = f"Sensitive ports detected open on {result.target}"
            except (json.JSONDecodeError, AttributeError, KeyError):
                pass  # Skip if there's an issue with the result data
                
        recent_activity.append({
            'time': result.created_at.strftime('%H:%M:%S'),
            'title': f"{result.tool_name} Scan",
            'description': description,
            'severity': severity
        })
    
    # Return the dashboard data
    return jsonify({
        'overallThreatLevel': overall_threat_level,
        'riskIndicators': {
            'networkVulnerability': network_vulnerability,
            'webApplicationRisk': web_application_risk,
            'authenticationSecurity': authentication_security,
            'dataProtection': data_protection
        },
        'recentActivity': recent_activity
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
