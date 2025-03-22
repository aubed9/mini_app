from quart import Quart, request, jsonify, render_template_string, redirect, url_for, session
import hmac
import hashlib
import json
from aiomysql import create_pool, Error as aiomysqlError
from datetime import datetime
import logging
from typing import Dict, Any
from functools import wraps

# Initialize Quart app
app = Quart(__name__)
app.secret_key = 'A1u3b8e0d@#'  # Should be environment variable in production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Bot configuration
BOT_TOKEN = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"
REQUIRED_FIELDS = ['bale_user_id', 'username', 'chat_id', 'url', 'video_name']

class User:
    def __init__(self, user_id: int, user_data: Dict[str, Any]):
        self.user_id = user_id
        self.user_data = user_data

def login_required(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return await f(*args, **kwargs)
    return decorated_function

async def get_current_user():
    if 'user_id' not in session:
        return None
    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT id, bale_user_id, username FROM users WHERE id = %s",
                    (session['user_id'],)
                )
                user_data = await cursor.fetchone()
                if user_data:
                    return User(
                        user_id=user_data[0],
                        user_data={
                            'id': user_data[0],
                            'bale_user_id': user_data[1],
                            'username': user_data[2]
                        }
                    )
    except Exception as e:
    return None

@app.before_serving
async def setup_db():
    """Create database pool and tables"""
    try:
        app.pool = await create_pool(
            host='annapurna.liara.cloud',
            user='root',
            port=32002,
            password='4zjqmEfeRhCqYYDhvkaODXD3',
            db='users',
            autocommit=False,
            minsize=3,
            maxsize=10
        )
        
        async with app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                # Create tables if not exists
                await cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        bale_user_id INT UNIQUE,
                        username TEXT,
                        chat_id INT
                    )
                ''')
                await cursor.execute('''
                    CREATE TABLE IF NOT EXISTS videos (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        user_id INT,
                        username TEXT,
                        chat_id INT,
                        url TEXT,
                        video_name TEXT,
                        creation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                ''')
                await conn.commit()

                
    except Exception as e:
        raise

# Core validation functions remain same but async where needed
# [Keep the url_decode, parse_qs, validate_init_data functions unchanged]

@app.route('/save_video', methods=['POST'])
async def save_video():
    """Async video saving endpoint"""
    try:
        data = await request.get_json()
        missing = [field for field in REQUIRED_FIELDS if field not in data]
        if missing:
            return jsonify({'status': 'error', 'message': f'Missing fields: {", ".join(missing)}'}), 400

        async with app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await conn.begin()
                
                # User handling
                await cursor.execute(
                    "SELECT id FROM users WHERE bale_user_id = %s",
                    (data['bale_user_id'],)
                )
                user = await cursor.fetchone()
                
                if user:
                    user_id = user[0]
                    await cursor.execute(
                        "UPDATE users SET chat_id = %s WHERE id = %s",
                        (data['chat_id'], user_id)
                    )
                else:
                    await cursor.execute(
                        "INSERT INTO users (bale_user_id, username) VALUES (%s, %s)",
                        (data['bale_user_id'], data['username'])
                    )
                    user_id = cursor.lastrowid

                # Video insertion
                await cursor.execute('''
                    INSERT INTO videos 
                    (user_id, username, chat_id, url, video_name)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (user_id, data['username'], data['chat_id'], data['url'], data['video_name']))
                
                await conn.commit()
                return jsonify({'message': 'Video saved successfully'}), 201

    except aiomysqlError as e:
        await conn.rollback()
        logger.error(f"Database error: {e}")
        return jsonify({'error': 'Database operation failed'}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/login', methods=['POST'])
async def login():
    """Modified login endpoint with session management"""
    data = await request.get_json()
    init_data = data.get('initData')
    
    if not init_data:
        return jsonify({'error': 'Missing initData'}), 400

    is_valid, validation_result = validate_init_data(init_data)
    if not is_valid:
        return jsonify({'error': validation_result}), 400

    try:
        user_data = json.loads(validation_result.get('user', '{}'))
        bale_user_id = user_data['id']
    except (KeyError, json.JSONDecodeError) as e:
        return jsonify({'error': f'Invalid user data: {e}'}), 400

    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT id, bale_user_id, username FROM users WHERE bale_user_id = %s",
                    (bale_user_id,)
                )
                user_record = await cursor.fetchone()
                
                if user_record:
                    session['user_id'] = user_record[0]
                    return jsonify({
                        'status': 'logged_in',
                        'user': {
                            'id': user_record[0],
                            'username': user_record[2]
                        }
                    })
                else:
                    return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        app.logger.error(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/logout', methods=['POST'])
async def logout():
    """Session termination endpoint"""
    session.pop('user_id', None)
    return jsonify({'status': 'logged_out'})


@app.route('/register', methods=['POST'])
async def register():
    """Async user registration"""
    data = await request.get_json()
    init_data = data.get('initData')
    
    if not init_data:
        return jsonify({'error': 'Missing initData'}), 400

    is_valid, validation_result = validate_init_data(init_data)
    if not is_valid:
        return jsonify({'error': validation_result}), 400

    try:
        user_data = json.loads(validation_result.get('user', '{}'))
        bale_user_id = user_data['id']
        username = user_data.get('username', '')
    except (KeyError, json.JSONDecodeError) as e:
        return jsonify({'error': f'Invalid user data: {e}'}), 400

    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor(DictCursor) as cursor:
                await cursor.execute(
                    "SELECT id FROM users WHERE bale_user_id = %s",
                    (bale_user_id,)
                )
                if await cursor.fetchone():
                    return jsonify({'error': 'User already exists'}), 400

                await cursor.execute(
                    "INSERT INTO users (bale_user_id, username) VALUES (%s, %s)",
                    (bale_user_id, username)
                )
                user_id = cursor.lastrowid
                await conn.commit()

                new_user = User(
                    auth_id=str(user_id),
                    user_data={
                        'id': user_id,
                        'bale_user_id': bale_user_id,
                        'username': username
                    }
                )
                login_user(new_user)
                return jsonify({'message': 'User registered successfully'}), 201

    except aiomysqlError as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Database operation failed'}), 500

@app.route('/dashboard')
@login_required
async def dashboard():
    user = await get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor(DictCursor) as cursor:
                await cursor.execute('''
                    SELECT video_name, url, creation_time 
                    FROM videos 
                    WHERE user_id = %s 
                    AND creation_time >= NOW() - INTERVAL 24 HOUR
                    ORDER BY creation_time DESC
                ''', (current_user.auth_id,))
                
                videos = await cursor.fetchall()

        return await render_template_string('''
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
            ''', 
            username=current_user.username, 
            videos=videos
        )

    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return "Error loading dashboard", 500

# Modified process_video route
@app.route('/process_video', methods=['POST'])
@login_required
async def process_video():
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
        # Use async sleep instead of blocking sleep
        while not job.done():
            await asyncio.sleep(0.5)
            
        result = job.result()
        output_video_path = result[1]['video']  # Extract final video path
    
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        app.logger.error(f"Processing error: {e}")
        return redirect(url_for('dashboard'))

# Async index route
@app.route('/')
async def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return await render_template_string('''
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

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=False)
