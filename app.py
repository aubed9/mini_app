from flask import Flask, request, jsonify, render_template_string
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import hmac
import hashlib
from urllib.parse import parse_qs
import json

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'A1u3b8e0d@#'  # Replace with a secure key in production

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# SQLite database setup
def init_db():
    conn = sqlite3.connect('/data-base/users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  bale_user_id INTEGER UNIQUE, 
                  username TEXT)''')
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, bale_user_id, username):
        self.id = id
        self.bale_user_id = bale_user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('/data-base/users.db')
    c = conn.cursor()
    c.execute("SELECT id, bale_user_id, username FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

# Bot token (replace with your actual bot token)
BOT_TOKEN = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"  # Store securely in production

# Validate initData
def validate_init_data(init_data):
    print(f"init_data type{type(init_data)}")
    print(f"init_data: {init_data}")
    parsed_data = parse_qs("auth_date=1741927541&hash=bf471fa6492b7360214fc40f40b545369db3e1e9a1fa95638594e098817d8994&query_id=YYTUYQYmipTEGbIfkR4IGaaM&user=%7B%22allows_write_to_pm%22%3Atrue%2C%22first_name%22%3A%22%D9%85%D8%AD%D9%85%D8%AF%D8%B9%D8%A7%D8%A8%D8%AF+%D8%A7%D8%B5%D9%81%D9%87%D8%A7%D9%86%DB%8C+%D8%B2%D8%A7%D8%AF%D9%87%22%2C%22id%22%3A31315407%2C%22username%22%3A%22aubed%22%7D")
    print(f"pars:{parsed_data}")
    print(f"parsed_data type: {parsed_data}")
    data_dict = {k: v[0] for k, v in parsed_data.items()}
    print(f"dict: {data_dict}")
    hash_value = data_dict.pop('hash', None)
    print(f"hash: {hash_value}")
    if not hash_value:
        return False, "Missing hash in initData"
    
    sorted_keys = sorted(data_dict.keys())
    data_check_string = "\n".join([f"{k}={data_dict[k]}" for k in sorted_keys])
    
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    check_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    
    if check_hash != hash_value:
        return False, "Invalid hash, data may be tampered"
    
    return True, data_dict

# Routes
@app.route('/register', methods=['POST'])
def register():
    init_data = request.get_json().get('initData')
    if not init_data:
        return jsonify({'error': 'Missing initData'}), 400
    
    is_valid, result = validate_init_data(init_data)
    if not is_valid:
        return jsonify({'error': result}), 400
    data_dict = result
    
    user_json = data_dict.get('user')
    if not user_json:
        return jsonify({'error': 'Missing user data'}), 400
    try:
        user_data = json.loads(user_json)
        bale_user_id = user_data['id']
        username = user_data.get('username', '')
    except (json.JSONDecodeError, KeyError):
        return jsonify({'error': 'Invalid user data'}), 400
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE bale_user_id = ?", (bale_user_id,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'User already exists'}), 400
    
    c.execute("INSERT INTO users (bale_user_id, username) VALUES (?, ?)", 
              (bale_user_id, username))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    init_data = request.get_json().get('initData')
    print(f"init_data type{type(init_data)}")
    print(init_data)
    if not init_data:
        return jsonify({'error': 'Missing initData'}), 400
    
    is_valid, result = validate_init_data(init_data)
    if not is_valid:
        return jsonify({'error': result}), 400
    data_dict = result
    
    user_json = data_dict.get('user')
    if not user_json:
        return jsonify({'error': 'Missing user data'}), 400
    try:
        user_data = json.loads(user_json)
        bale_user_id = user_data['id']
    except (json.JSONDecodeError, KeyError):
        return jsonify({'error': 'Invalid user data'}), 400
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, bale_user_id, username FROM users WHERE bale_user_id = ?", (bale_user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        user = User(user_data[0], user_data[1], user_data[2])
        login_user(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    return jsonify({'error': 'User not found'}), 404

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/protected')
@login_required
def protected():
    return jsonify({'message': f'Hello, {current_user.username}! This is a protected route.'})

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Auth Test</title>
        <script src="https://tapi.bale.ai/miniapp.js?1"></script>
    </head>
    <body>
        <h1>Auth Test</h1>
        <p id="status">Checking authentication...</p>
        <a href="/logout">Logout</a> | <a href="/protected">Protected Route</a>
        <script>
            window.onload = function() {
                if (typeof Bale !== 'undefined' && Bale.WebApp) {
                    const initData = Bale.WebApp.initData;
                    if (initData) {
                        fetch('/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ initData: initData })
                        })
                        .then(response => {
                            if (response.ok) {
                                return response.json().then(data => {
                                    document.getElementById('status').textContent = data.message;
                                });
                            } else if (response.status === 404) {
                                return fetch('/register', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ initData: initData })
                                }).then(registerResponse => {
                                    if (registerResponse.ok) {
                                        return registerResponse.json().then(data => {
                                            document.getElementById('status').textContent = data.message;
                                        });
                                    }
                                    return registerResponse.json().then(data => {
                                        document.getElementById('status').textContent = 'Error: ' + data.error;
                                    });
                                });
                            }
                            return response.json().then(data => {
                                document.getElementById('status').textContent = 'Error: ' + data.error;
                            });
                        })
                        .catch(error => {
                            document.getElementById('status').textContent = 'Fetch error: ' + error.message;
                        });
                    } else {
                        document.getElementById('status').textContent = 'No initData available';
                    }
                } else {
                    document.getElementById('status').textContent = 'Bale mini-app script not loaded';
                }
            };
        </script>
    </body>
    </html>
    ''')
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
