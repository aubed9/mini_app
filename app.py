from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
import hmac
import hashlib
import json
from gradio_client import Client, handle_file
import asyncio
import httpx

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
async def save_video():
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
        # Database connection setup
        conn = mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users'
        )
        cursor = conn.cursor()

        # User handling
        cursor.execute("SELECT id FROM users WHERE bale_user_id = %s", (bale_user_id,))
        user = cursor.fetchone()

        if user:
            user_id = user[0]
            cursor.execute("UPDATE users SET chat_id = %s WHERE id = %s", (chat_id, user[0]))
        else:
            cursor.execute("INSERT INTO users (bale_user_id, username) VALUES (%s, %s)", 
                          (bale_user_id, username))
            conn.commit()
            user_id = cursor.lastrowid

        # Extract video properties
        url = video_data.get('url')
        name = video_data.get('video_name')
        
        if not all([chat_id, url, name]):
            return jsonify({'error': 'Missing video properties'}), 400

        # Asynchronous Gradio request
        try:
            cursor.execute("INSERT INTO videos (user_id, username, chat_id, url, video_name) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, username, chat_id, url, name))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Video saved successfully'}), 201
        except mysql.connector.Error as db_err:
            print(f"Database error: {db_err}")
            return jsonify({'error': 'Database operation failed'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'Server error'}), 500
        

@app.route('/login', methods=['POST'])
async def login():
    init_data = await request.get_json().get('initData')
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
        conn = await mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users',
            port=32002,
        )
        cursor = conn.cursor()
        cursor.execute("SELECT id, bale_user_id, username FROM users WHERE bale_user_id = %s", (bale_user_id,))
        user_data = await cursor.fetchone()
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
async def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    return jsonify({'message': f'Hello, {current_user.username}! This is a protected route.'})

@app.route('/')
async def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template_string('''
    <!DOCTYPE html>
<html>
<head>
    <title>Video Dashboard</title>
    <style>
        .video-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            padding: 20px;
        }
        
        .video-card {
            background-color: #f5f5f5;
            border-radius: 10px;
            padding: 20px;
            width: 300px;
            height: auto;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .video-name {
            font-size: 18px;
            margin-bottom: 10px;
        }
        
        .preview-thumbnails {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            padding: 10px;
        }
        
        .thumbnail {
            width: 64px;
            height: 48px;
            object-fit: cover;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h1>Welcome to your Dashboard, {{ current_user.username }}!</h1>
    
    <div class="video-container">
        {% for video in videos %}
        <div class="video-card">
            <div class="video-name">{{ video.video_name }}</div>
            
            <div class="preview-thumbnails">
                {% if video.preview_images %}
                {% for preview_image in video.preview_images %}
                <img src="{{ preview_image }}" alt="Preview" class="thumbnail">
                {% endfor %}
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>

    <a href="{{ url_for('index') }}">Back to Home</a>
</body>
</html>
    ''')

# Add this function to fetch user videos
def get_user_videos(user_id):
    try:
        conn = mysql.connector.connect(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            database='users'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT username, chat_id, url, video_name, preview_images FROM videos WHERE user_id = %s", (user_id,))
        videos = []
        for row in cursor.fetchall():
            videos.append({
                'username': row[0],
                'chat_id': row[1],
                'url': row[2],
                'video_name': row[3],
                'preview_images': row[4].split(',') if row[4] else []
            })
        conn.close()
        return videos
    except Exception as e:
        print(f"Error getting user videos: {e}")
        return []

# Modify the dashboard route to include video data
@app.route('/dashboard', methods=['GET'])
@login_required
async def dashboard():
    videos = await get_user_videos(current_user.id)
    return render_template_string("""<!DOCTYPE html>
<html>
<head>
    <title>Video Dashboard</title>
    <style>
        .video-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            padding: 20px;
        }
        
        .video-card {
            background-color: #f5f5f5;
            border-radius: 10px;
            padding: 20px;
            width: 300px;
            height: auto;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .video-name {
            font-size: 18px;
            margin-bottom: 10px;
        }
        
        .preview-thumbnails {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .thumbnail {
            width: 64px;
            height: 48px;
            object-fit: cover;
            cursor: pointer;
        }
        
        .video-link {
            color: blue;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <h1>Welcome to your Dashboard, {{ current_user.username }}!</h1>
    
    <div class="video-container">
        {% for video in videos %}
        <div class="video-card">
            <div class="video-name">{{ video.video_name }}</div>
            
            <div class="preview-thumbnails">
                {% for preview_image in video.preview_images %}
                    <img src="{{ preview_image }}" alt="Preview" class="thumbnail">
                {% endfor %}
            </div>
        </div>
        {% endfor %}
        <a href="{{ video.url }}" class="video-link">View Video</a>
    </div>
</body>
</html>
""", videos=videos)



if __name__ == '__main__':
    init_db()
    app.run(debug=True)
