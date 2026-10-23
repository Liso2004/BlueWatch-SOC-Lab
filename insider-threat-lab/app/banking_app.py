from flask import Flask, render_template, request, session, redirect, jsonify
import pymysql
import bcrypt
import secrets
import logging
from datetime import datetime
import os

from mobile_risk import api_v1 as mobile_risk_api_v1
from mobile_risk import bp as mobile_risk_bp


app = Flask(__name__)
# A fixed key from .env keeps sessions valid across restarts; fall back to a random one.
app.secret_key = os.getenv('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024

# BlueWatch Mobile: Android app risk triage for SOC analysts (UI) and bank systems (API v1)
app.register_blueprint(mobile_risk_bp)
app.register_blueprint(mobile_risk_api_v1)


# Configure logging - CRITICAL for SOC detection
logging.basicConfig(
    filename=os.getenv('APP_LOG_FILE', '/var/log/app/banking_app.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - USER:%(user)s - IP:%(ip)s'
)


class SocLogDefaults(logging.Filter):
    """Library log records (werkzeug etc.) have no user/ip; give them defaults so the
    SOC log format above does not raise on them."""

    def filter(self, record):
        record.user = getattr(record, 'user', '-')
        record.ip = getattr(record, 'ip', '-')
        return True


for handler in logging.getLogger().handlers:
    handler.addFilter(SocLogDefaults())


# Database connection
def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "mysql"),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.getenv("DB_NAME", "banking"),
        cursorclass=pymysql.cursors.DictCursor
    )


# Custom logging function
def log_event(event_type, details, user=None):
    extra = {
        'user': user or session.get('username', 'anonymous'),
        'ip': request.remote_addr
    }

    app.logger.info(
        f"{event_type}: {details}",
        extra=extra
    )


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get('username', '')
        password = request.form.get('password', '')

        db = get_db()

        try:
            with db.cursor() as cursor:

                # Secure parameterized user lookup
                cursor.execute(
                    "SELECT * FROM users WHERE username = %s",
                    (username,)
                )

                user = cursor.fetchone()

                if user and bcrypt.checkpw(
                    password.encode(),
                    user['password'].encode()
                ):

                    session['username'] = username
                    session['user_id'] = user['id']

                    log_event(
                        'LOGIN_SUCCESS',
                        f'User {username} logged in',
                        username
                    )

                    return redirect('/dashboard')

                log_event(
                    'LOGIN_FAILED',
                    f'Failed login attempt for {username}',
                    username
                )

                return "Invalid credentials", 401

        finally:
            db.close()

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():

    if 'username' not in session:
        return redirect('/login')

    log_event(
        'DASHBOARD_ACCESS',
        'User accessed dashboard',
        session['username']
    )

    return render_template(
        'dashboard.html',
        username=session['username']
    )


@app.route('/api/customers', methods=['GET'])
def get_customers():
    """
    Retrieve customer records.

    The endpoint intentionally allows authenticated employees
    broad access to customer information so insider-abuse
    behavior can be detected by BlueWatch.
    """

    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    db = get_db()

    try:
        with db.cursor() as cursor:

            query_start = datetime.now()

            # Intentionally broad access for insider-threat lab.
            # The SQL itself remains safe from injection.
            cursor.execute(
                """
                SELECT id,
                       name,
                       email,
                       account_number,
                       balance
                FROM customers
                LIMIT 50
                """
            )

            customers = cursor.fetchall()

            query_time = (
                datetime.now() - query_start
            ).total_seconds()

            # Detailed security telemetry
            log_event(
                'DATABASE_QUERY',
                (
                    f'Query: SELECT customers | '
                    f'Rows: {len(customers)} | '
                    f'Time: {query_time}s'
                ),
                session['username']
            )

            return jsonify(customers)

    finally:
        db.close()


@app.route('/api/search', methods=['GET'])
def search_customers():
    """
    Search customer records.

    Broad wildcard searching is intentionally permitted for the
    insider-threat simulation, but parameterized SQL prevents
    SQL injection.
    """

    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    search_term = request.args.get('q', '')

    # Preserve broad wildcard searching for the insider-threat lab
    search_pattern = f"%{search_term}%"

    db = get_db()

    try:
        with db.cursor() as cursor:

            query = """
                SELECT *
                FROM customers
                WHERE name LIKE %s
                   OR email LIKE %s
            """

            query_start = datetime.now()

            cursor.execute(
                query,
                (
                    search_pattern,
                    search_pattern
                )
            )

            results = cursor.fetchall()

            query_time = (
                datetime.now() - query_start
            ).total_seconds()

            # Security telemetry used by anomaly detection
            log_event(
                'SEARCH_QUERY',
                (
                    f'Search: "{search_term}" | '
                    f'Results: {len(results)} | '
                    f'Time: {query_time}s'
                ),
                session['username']
            )

            return jsonify(results)

    finally:
        db.close()


@app.route('/logout')
def logout():

    username = session.get(
        'username',
        'unknown'
    )

    log_event(
        'LOGOUT',
        f'User {username} logged out',
        username
    )

    session.clear()

    return redirect('/')


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        # The Werkzeug debugger allows code execution; only enable it explicitly.
        debug=os.getenv('FLASK_DEBUG', '0') == '1'
    )