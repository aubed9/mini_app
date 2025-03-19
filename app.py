
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
import hmac
import hashlib
import json
from gradio_client import Client, handle_file
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import threading
import time
import uuid
import aiomysql

# Initialize tasks storage and lock
tasks = defaultdict(dict)
task_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=4)
# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'A1u3b8e0d@#'  # Replace with a secure key in production
#app.config['SESSION_COOKIE_SECURE'] = True  # If using HTTPS
#app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Adjust based on your cross-site requirements
# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# MySQL database setup
def init_db():
    try:
        conn = mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
        )
        if conn.is_connected():
            print('Connected to MySQL.')
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                             (id INT PRIMARY KEY AUTO_INCREMENT, 
                              bale_user_id INT UNIQUE, 
                              username TEXT)''')
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Error connecting to MySQL: {e}")

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, bale_user_id, username):
        self.id = id
        self.bale_user_id = bale_user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, bale_user_id, username FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2])
        return None
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

# Bot token
BOT_TOKEN = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"

# Custom URL decoding functions
def url_decode(s):
    bytes_list = []
    i = 0
    while i < len(s):
        if s[i] == '%':
            try:
                hex_code = s[i+1:i+3]
                byte_val = int(hex_code, 16)
                bytes_list.append(byte_val)
                i += 3
            except (ValueError, IndexError):
                bytes_list.append(ord('%'))
                i += 1
        elif s[i] == '+':
            bytes_list.append(0x20)
            i += 1
        else:
            bytes_list.append(ord(s[i]))
            i += 1
    return bytes(bytes_list).decode('utf-8', errors='replace')

def parse_qs(query_string):
    params = {}
    pairs = query_string.split('&')
    for pair in pairs:
        if not pair:
            continue
        parts = pair.split('=', 1)
        key = url_decode(parts[0])
        value = url_decode(parts[1]) if len(parts) > 1 else ''
        if key in params:
            if isinstance(params[key], list):
                params[key].append(value)
            else:
                params[key] = [params[key], value]
        else:
            params[key] = value
    return params

# Validate initData
def validate_init_data(init_data):
    decoded_init_data = url_decode(init_data)
    parsed_data = parse_qs(decoded_init_data)
    data_dict = {k: v[0] if isinstance(v, list) else v for k, v in parsed_data.items()}
    hash_value = data_dict.pop('hash', None)
    if not hash_value:
        return False, "Missing hash in initData"
    sorted_keys = sorted(data_dict.keys())
    data_check_string = "\n".join([f"{k}={data_dict[k]}" for k in sorted_keys])
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    check_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    if check_hash != hash_value:
        return False, "Invalid hash, data may be tampered"
    return True, data_dict

from datetime import datetime

# Database configuration
db_config = {
    'host': 'annapurna.liara.cloud',
    'port': 32002,
    'user': 'root',
    'password': '4zjqmEfeRhCqYYDhvkaODXD3',
    'database': 'users',
    'auth_plugin': 'mysql_native_password'
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        app.logger.error(f"Database connection error: {err}")
        return None


@app.route('/save_video', methods=['POST'])
async def save_video():
    # Get JSON data from the bot request
    data = request.get_json()
    bale_user_id = data.get('bale_user_id')
    username = data.get('username')
    chat_id = data.get('chat_id')
    url = data.get('url')
    video_name = data.get('video_name')
    # Validate required fields
    required_fields = ['bale_user_id', 'username', 'chat_id', 'url', 'video_name']
    for field in required_fields:
        if field not in data:
            return jsonify({'status': 'error', 'message': f'Missing field: {field}'}), 400

    try:
        # Using aiomysql
        conn = await aiomysql.connect(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            db='users'
        )
        
        async with conn.cursor() as cursor:
            # Check user exists
            await cursor.execute(
                "SELECT id FROM users WHERE bale_user_id = %s", 
                (bale_user_id,)
            )
            user = await cursor.fetchone()

            if user:
                # Update chat_id
                await cursor.execute(
                    "UPDATE users SET chat_id = %s WHERE id = %s",
                    (chat_id, user[0])
                )
            else:
                # Insert new user
                await cursor.execute(
                    "INSERT INTO users (bale_user_id, username) VALUES (%s, %s)",
                    (bale_user_id, username)
                )
                await conn.commit()
                user_id = cursor.lastrowid

            return jsonify({'status': 'success'})

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': 'Database operation failed'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

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
    try:
        conn = mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
            port=32002,
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, bale_user_id, username FROM users WHERE bale_user_id = %s", (bale_user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            user = User(user_data[0], user_data[1], user_data[2])
            login_user(user)
            return jsonify({'message': 'Logged in successfully'}), 200
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    return jsonify({'message': f'Hello, {current_user.username}! This is a protected route.'})

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>بررسی صحت کاربر</title>
        <script src="https://tapi.bale.ai/miniapp.js?1"></script>
    </head>
    <body>
        <h1>بررسی صحت کاربر</h1>
        <p id="status">... در حال بررسی</p>
        <script>
            window.onload = function() {
                if (typeof Bale !== 'undefined' && Bale.WebApp) {
                    const initData = Bale.WebApp.initData;
                    if (initData) {
                        fetch('/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ initData: initData }),
                            credentials: 'include'  // Add this line
                        })
                        .then(response => {
                            if (response.ok) {
                                window.location.href = '/dashboard';
                            } else if (response.status === 404) {
                                return fetch('/register', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ initData: initData }),
                                    credentials: 'include'  // Add this line for register too
                                }).then(registerResponse => {
                                    if (registerResponse.ok) {
                                        window.location.href = '/dashboard';
                                    } else {
                                        return registerResponse.json().then(data => {
                                            document.getElementById('status').textContent = 'Registration error: ' + data.error;
                                        });
                                    }
                                });
                            } else {
                                return response.json().then(data => {
                                    document.getElementById('status').textContent = 'Login error: ' + data.error;
                                });
                            }
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

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
        )
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT video_name, url, creation_time 
            FROM videos 
            WHERE user_id = %s 
            AND creation_time >= NOW() - INTERVAL 24 HOUR
            ORDER BY creation_time DESC
        ''', (current_user.id,))
        videos = cursor.fetchall()
        conn.close()

        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Dashboard - {{ username }}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .video-list { margin-top: 20px; }
                    .video-item { margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
                    .parameters { margin: 20px 0; padding: 20px; border: 1px solid #ddd; }
                    .param-group { margin: 10px 0; }
                    label { display: block; margin: 5px 0; }
                    input[type="text"], select, input[type="number"], input[type="color"] {
                        width: 200px; padding: 5px; margin-bottom: 10px;
                    }
                </style>
            </head>
            <body>
                <h1>{{ username }} خوش آمدید</h1>
                <form method="POST" action="{{ url_for('process_video') }}">
                    <div class="video-list">
                        <h2>ویدئوی خود را انتخاب کنید:</h2>
                        {% if videos %}
                            {% for video in videos %}
                                <div class="video-item">
                                    <input type="radio" name="video_url" value="{{ video.url }}" required>
                                    <strong>{{ video.video_name }}</strong><br>
                                    <a href="{{ video.url }}" class="video-link" target="_blank">View Video</a><br>
                                    <span class="timestamp">{{ video.creation_time }} :آپلود شده در</span>
                                </div>
                            {% endfor %}
                        {% else %}
                            <p>ویدئویی در ۲۴ ساعت گذشته بارگزاری نشده است.</p>
                        {% endif %}
                    </div>

                    <div class="parameters">
                        <h2>:پارامتر ها</h2>
                        <div class="param-group">
                            <label>:نوع فونت
                                <select name="font_type" required>
                                    <option value="arial">آریال</option>
                                    <option value="yekan">یکان</option>
                                    <option value="nazanin">نازنین</option>
                                </select>
                            </label>
                            
                            <label>:اندازه فونت
                                <input type="number" name="font_size" min="8" max="72" value="12" required>
                            </label>
                            
                            <label>: رنگ فونت
                                <select name="font_color" required>
                                    <option value="#yellow">زرد</option>
                                    <option value="#black">مشکی</option>
                                    <option value="#white">سفید</option>
                                </select>
                            </label>
                        </div>

                        <div class="param-group">
                            
                            <label> جامعه مخاطبین هدف شما چه کسانی هستند؟
                                <input type="text" name="target" placeholder="دانش آموزانی که به دنبال یادگیری ریاضی هستند" >
                            </label>
                            
                            <label>لحن و شیوه سخن ترجمه چگونه باشد؟
                                <input type="text" name="style" placeholder="...خبری،‌ ساده و روان، پرهیجان" >
                            </label>
                            
                            <label>موضوع اصلی ویدئوت چیه؟
                                <input type="text" name="subject" placeholder="...آموزش ریاضی دانشگاه، تحلیل و بررسی گوشی جدید سامسونگ" >
                            </label>
                            
                            <label>هر نکته دیگه که بنظرت ترجمه رو بهتر می کنه رو اینجا بنویس
                                <input type="text" name="subject" placeholder="لغات فنی و خاص تکتنولوژی رو ترجمه نکن" >
                            </label>
                        </div>
                    </div>

                    <input type="submit" value="تایید پارامترها و ارسال؟">
                </form>
            </body>
            </html>
        ''', username=current_user.username, videos=videos)

    except Exception as e:
        print(f"Dashboard error: {e}")
        return "Error loading dashboard", 500

@app.route('/process_video', methods=['POST'])
@login_required
def process_video():
    try:
        # Get form data
        video_url = request.form.get('video_url')
        font_type = request.form.get('font_type')
        font_size = request.form.get('font_size')
        font_color = request.form.get('font_color')
        target = request.form.get('target')
        style = request.form.get('style')
        subject = request.form.get('subject')
        
        # Construct parameters string with default service
        service = 'default_service'  # Add default service parameter
        parameters = f"{font_type},{font_size},{font_color},{service},{target},{style},{subject}"
        
        # Connect to Gradio app
        client = Client("rayesh/process_miniapp")  # Adjust URL if hosted elsewhere
        
        # Start processing job
        job = client.submit(
            video_url,
            parameters,
            fn_index=0  # Assuming main function is first in interface
        )
        
        # Wait for completion and get result
        while not job.done():
            time.sleep(0.5)
            
        result = job.result()
        output_video_path = result[1]['video']  # Extract final video path
        
        # Redirect to dashboard with success message
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Processing error: {e}")
        return redirect(url_for('dashboard', error=str(e)))
        
# Start cleaner thread when app starts
if __name__ == '__main__':
    uvicorn.run("main:app", host="0.0.0.0", port=80, ws="none")
