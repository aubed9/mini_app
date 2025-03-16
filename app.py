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
    'password': 'Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12',
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
@login_required
def save_video():
    conn = None
    cursor = None
    try:
        # Validate request data
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

        required_fields = ['bale_user_id', 'username', 'video_url', 'parameters']
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'message': f'Missing field: {field}'}), 400

        # Get database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500

        cursor = conn.cursor()

        # Create videos table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS videos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                bale_user_id VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                video_url TEXT NOT NULL,
                parameters TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Insert video data
        insert_query = '''
            INSERT INTO videos 
            (bale_user_id, username, video_url, parameters)
            VALUES (%s, %s, %s, %s)
        '''
        video_data = (
            data['bale_user_id'],
            data['username'],
            data['video_url'],
            data['parameters']
        )
        
        cursor.execute(insert_query, video_data)
        conn.commit()

        return jsonify({
            'status': 'success',
            'message': 'Video saved successfully',
            'video_id': cursor.lastrowid
        }), 200

    except mysql.connector.Error as err:
        app.logger.error(f"Database error: {err}")
        return jsonify({'status': 'error', 'message': str(err)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
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
        <title>Auth Test</title>
        <script src="https://tapi.bale.ai/miniapp.js?1"></script>
    </head>
    <body>
        <h1>Auth Test</h1>
        <p id="status">Checking authentication...</p>
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
                <h1>Welcome, {{ username }}!</h1>
                <form method="POST" action="{{ url_for('process_video') }}">
                    <div class="video-list">
                        <h2>Select a Video:</h2>
                        {% if videos %}
                            {% for video in videos %}
                                <div class="video-item">
                                    <input type="radio" name="video_url" value="{{ video.url }}" required>
                                    <strong>{{ video.video_name }}</strong><br>
                                    <a href="{{ video.url }}" class="video-link" target="_blank">View Video</a><br>
                                    <span class="timestamp">Uploaded at: {{ video.creation_time }}</span>
                                </div>
                            {% endfor %}
                        {% else %}
                            <p>No videos uploaded in the last 24 hours.</p>
                        {% endif %}
                    </div>

                    <div class="parameters">
                        <h2>Customization Parameters:</h2>
                        <div class="param-group">
                            <label>Font Type:
                                <select name="font_type" required>
                                    <option value="arial">Arial</option>
                                    <option value="yekan">Yekan</option>
                                    <option value="nazanin">Nazanin</option>
                                </select>
                            </label>
                            
                            <label>Font Size:
                                <input type="number" name="font_size" min="8" max="72" value="12" required>
                            </label>
                            
                            <label>Font Color:
                                <select name="font_color" required>
                                    <option value="#yellow">Yellow</option>
                                    <option value="#black">Black</option>
                                    <option value="#white">White</option>
                                </select>
                            </label>
                        </div>

                        <div class="param-group">
                            <label>Service:
                                <input type="text" name="service" placeholder="Enter service type" required>
                            </label>
                            
                            <label>Target Audience:
                                <input type="text" name="target" placeholder="Enter target audience" required>
                            </label>
                            
                            <label>Style:
                                <input type="text" name="style" placeholder="Enter video style" required>
                            </label>
                            
                            <label>Subject:
                                <input type="text" name="subject" placeholder="Enter main subject" required>
                            </label>
                        </div>
                    </div>

                    <input type="submit" value="Process Video">
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
    task_id = str(uuid.uuid4())
    
    # Initialize task with lock
    with task_lock:
        tasks[task_id] = {
            'status': 'initializing',
            'message': 'Starting processing...',
            'progress': 0,
            'result': None,
            'created_at': time.time()
        }

    # Submit task to thread pool
    executor.submit(
        process_video_task,
        task_id,
        dict(request.form),
        current_user.id
    )
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Processing Video</title>
            <style>
                .progress-container {
                    margin: 20px;
                    padding: 20px;
                    border: 1px solid #ddd;
                }
                .progress-bar {
                    width: 100%;
                    height: 30px;
                    background-color: #f1f1f1;
                    margin: 10px 0;
                }
                .progress-fill {
                    height: 100%;
                    background-color: #4CAF50;
                    transition: width 0.3s ease;
                }
                .status-message {
                    margin: 10px 0;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="progress-container">
                <h2>Video Processing Progress</h2>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress" style="width: 0%"></div>
                </div>
                <div class="status-message" id="status">Starting processing...</div>
                <div id="result"></div>
            </div>

            <script>
                const task_id = "{{ task_id }}";
                
                function checkProgress() {
                    fetch(`/progress/${task_id}`)
                        .then(response => response.json())
                        .then(data => {
                            document.getElementById('progress').style.width = `${data.progress}%`;
                            document.getElementById('status').textContent = data.message;
                            
                            if (data.status === 'completed') {
                                document.getElementById('result').innerHTML = `
                                    <a href="${data.result}" class="download-btn" download>
                                        Download Processed Video
                                    </a>
                                `;
                            } else if (data.status !== 'failed') {
                                setTimeout(checkProgress, 1000);
                            }
                        });
                }
                
                setTimeout(checkProgress, 1000);
            </script>
        </body>
        </html>
    ''', task_id=task_id)

def process_video_task(task_id, form_data, user_id):
    try:
        # Validate and set default values
        params = {
            'font_type': form_data.get('font_type', 'Arial'),
            'font_size': str(form_data.get('font_size', '24')),
            'font_color': form_data.get('font_color', 'black'),
            'service': form_data.get('service', 'general'),
            'target': form_data.get('target', 'general'),
            'style': form_data.get('style', 'formal'),
            'subject': form_data.get('subject', 'general')
        }

        # Verify required parameters
        if not form_data.get('video_url'):
            raise ValueError("Missing video URL")

        # Format parameters as comma-separated string
        param_string = ",".join([
            params['font_type'],
            params['font_size'],
            params['font_color'],
            params['service'],
            params['target'],
            params['style'],
            params['subject']
        ])
        with task_lock:
            tasks[task_id].update({
                'status': 'processing',
                'message': 'پردازش شروع شد',
                'progress': 0
            })
        
        client = Client("rayesh/process_miniapp")
        
        # Process with progress updates
        job = client.submit(
            form_data['video_url'],
            f"{form_data['font_type']},{form_data['font_size']},{form_data['font_color']},"
            f"{form_data['service']},{form_data['target']},{form_data['style']},{form_data['subject']}",
            api_name="/main"
        )

        while not job.done():
            time.sleep(0.5)
            progress_data = job.communicator.job.outputs[0].progress_data
            if progress_data:
                tasks[task_id].update({
                    'progress': progress_data[0][0] * 100,
                    'message': progress_data[0][1]
                })

        result = job.outputs()
        tasks[task_id].update({
            'status': 'completed',
            'progress': 100,
            'message': 'پردازش کامل شد',
            'result': result[1]
        })

    except Exception as e:
        tasks[task_id].update({
            'status': 'failed',
            'message': f'Error: {str(e)}',
            'progress': 100
        })

@app.route('/progress/<task_id>')
@login_required
def get_progress(task_id):
    return jsonify(tasks.get(task_id, {
        'status': 'unknown',
        'message': 'Task not found',
        'progress': 0
    }))


def task_cleaner():
    while True:
        time.sleep(60)
        now = time.time()
        with task_lock:
            for tid in list(tasks.keys()):
                if now - tasks[tid].get('created_at', 0) > 3600:  # 1 hour retention
                    del tasks[tid]

# Start cleaner thread when app starts
if __name__ == '__main__':
    threading.Thread(target=task_cleaner, daemon=True).start()
    app.run()
