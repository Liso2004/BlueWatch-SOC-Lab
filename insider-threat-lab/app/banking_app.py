from flask import Flask, render_template, request, session, redirect, jsonify
import pymysql
import bcrypt
import secrets
import logging
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configure logging - CRITICAL for SOC detection
logging.basicConfig(
    filename='/var/log/app/banking_app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - USER:%(user)s - IP:%(ip)s'
)

# Database connection
def get_db():
    return pymysql.connect(
        host='mysql',
        user='bankapp',
        password='BankApp123!',
        database='banking',
        cursorclass=pymysql.cursors.DictCursor
    )

# Custom logging function
def log_event(event_type, details, user=None):
    extra = {
        'user': user or session.get('username', 'anonymous'),
        'ip': request.remote_addr
    }
    app.logger.info(f"{event_type}: {details}", extra=extra)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        
        # Secure password check
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            session['username'] = username
            session['user_id'] = user['id']
            log_event('LOGIN_SUCCESS', f'User {username} logged in', username)
            return redirect('/dashboard')
        else:
            log_event('LOGIN_FAILED', f'Failed login attempt for {username}')
            return "Invalid credentials", 401
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    
    log_event('DASHBOARD_ACCESS', 'User accessed dashboard', session['username'])
    return render_template('dashboard.html', username=session['username'])

@app.route('/api/customers', methods=['GET'])
def get_customers():
    """Endpoint to retrieve customer data - monitors query patterns"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    
    # Log the query with timing - THIS IS WHAT WE'LL DETECT
    query_start = datetime.now()
    
    # INTENTIONALLY VULNERABLE: Too permissive access
    cursor.execute("SELECT id, name, email, account_number, balance FROM customers LIMIT 50")
    customers = cursor.fetchall()
    
    query_time = (datetime.now() - query_start).total_seconds()
    
    # Detailed logging for detection
    log_event('DATABASE_QUERY', 
              f'Query: SELECT customers | Rows: {len(customers)} | Time: {query_time}s',
              session['username'])
    
    return jsonify(customers)

@app.route('/api/search', methods=['GET'])
def search_customers():
    """Search endpoint - can be abused for bulk extraction"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    search_term = request.args.get('q', '')
    
    db = get_db()
    cursor = db.cursor()
    
    # INTENTIONALLY VULNERABLE: Can search with wildcards for mass extraction
    query = f"SELECT * FROM customers WHERE name LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
    
    query_start = datetime.now()
    cursor.execute(query)
    results = cursor.fetchall()
    query_time = (datetime.now() - query_start).total_seconds()
    
    # Log search activity
    log_event('SEARCH_QUERY', 
              f'Search: "{search_term}" | Results: {len(results)} | Time: {query_time}s',
              session['username'])
    
    return jsonify(results)

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    log_event('LOGOUT', f'User {username} logged out', username)
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)