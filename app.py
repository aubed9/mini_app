from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
import hmac
import hashlib
import json
from gradio_client import Client, handle_file

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

# Route to save video data
@app.route('/save_video', methods=['POST'])
def save_video():
    # Get JSON data from the bot request
    data = request.get_json()
    bale_user_id = data.get('user_id')
    username = data.get('username')
    video_data = data.get('video')
    chat_id = data.get('chat_id')
    # Validate required fields
    if not bale_user_id or not username or not video_data:
        return jsonify({'error': 'Missing bale_user_id, username, or video data'}), 400

    try:
        # Connect to the database
        conn = mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users'
        )
        cursor = conn.cursor()

        # Check if user exists by bale_user_id
        cursor.execute("SELECT id FROM users WHERE bale_user_id = %s", (bale_user_id,))
        user = cursor.fetchone()

        if user:
            # User exists, use their ID
            user_id = user[0]
            cursor.execute("UPDATE users SET chat_id = %s WHERE id = %s", (chat_id, user[0]))
        else:
            # Register new user
            cursor.execute("INSERT INTO users (bale_user_id, username) VALUES (%s, %s)", 
                          (bale_user_id, username))
            conn.commit()
            user_id = cursor.lastrowid  # Get the new user's ID

        # Extract video properties
        
        url = video_data.get('url')
        name = video_data.get('video_name')

        # Validate video properties
        if not all([chat_id, url, name]):
            return jsonify({'error': 'Missing video properties'}), 400

        try: 
            cursor.execute("INSERT INTO videos (user_id, username, chat_id, url, video_name) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, username, chat_id, url, name))
            conn.commit()
            conn.close()

        except:
            return jsonify({'error': 'Missin preview images'}), 400

        return jsonify({'message': 'Video saved successfully'}), 201

    except Exception as e:
        print(f"Error in save_video: {e}")
        return jsonify({'error': 'Database error'}), 500

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
    try:
        # Get form data
        video_url = request.form['video_url']
        params = {
            'font_type': request.form['font_type'],
            'font_size': int(request.form['font_size']),
            'font_color': request.form['font_color'],
            'service': request.form['service'],
            'target': request.form['target'],
            'style': request.form['style'],
            'subject': request.form['subject']
        }
        params_string = ",".join([f"{value}" for key, value in params.items()])
        # Connect to Gradio API
        client = Client("rayesh/process_miniapp")
        result = client.predict(
    		url=video_url,
    		parameters=params_string,
            api_name="/predict"
        )

        # Handle the result (modify according to your Gradio API response)
        processed_video = handle_file(result)
        
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Processing Complete</title>
                <style>
                    .result { margin: 20px; padding: 20px; border: 2px solid #4CAF50; }
                    .download-btn {
                        background-color: #4CAF50;
                        color: white;
                        padding: 15px 25px;
                        text-decoration: none;
                        border-radius: 5px;
                    }
                </style>
            </head>
            <body>
                <div class="result">
                    <h2>Video Processing Complete!</h2>
                    <p>Your customized video is ready for download:</p>
                    <a href="{{ video_url }}" class="download-btn" download>Download Video</a>
                </div>
            </body>
            </html>
        ''', video_url=processed_video)

    except Exception as e:
        print(f"Processing error: {e}")
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error</title>
                <style>
                    .error { color: #ff0000; margin: 20px; }
                </style>
            </head>
            <body>
                <div class="error">
                    <h2>Processing Error</h2>
                    <p>An error occurred while processing your video. Please try again.</p>
                </div>
            </body>
            </html>
        ''')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
