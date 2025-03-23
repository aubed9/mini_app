from quart import Quart, request, jsonify, render_template_string, redirect, url_for, session
import hmac
import hashlib
import json
from aiomysql import DictCursor, create_pool, Error as aiomysqlError
from datetime import datetime
import logging
from typing import Dict, Any
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

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
        self.is_authenticated = user_id is not None  # Add this property

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
        app.logger.error(f"Database error: {e}")
        return jsonify({'error': 'Database operation failed'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
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
                await cursor.execute(
                    "INSERT INTO users (bale_user_id, username) VALUES (%s, %s)",
                    (data['bale_user_id'], data['username'])
                )
                user_id = cursor.lastrowid
                
                return jsonify({'message': 'User registered successfully'}), 201

    except aiomysqlError as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Database operation failed'}), 500

# Global state management (use Redis in production)
progress_states = {}
completed_jobs = set()
executor = ThreadPoolExecutor(max_workers=4)

@app.route('/process_video', methods=['POST'])
@login_required
async def process_video():
    try:
        form_data = request.form.to_dict()
        parameters = (
            f"{form_data['font_type']},"
            f"{form_data['font_size']},"
            f"{form_data['font_color']},"
            f"default_service,"
            f"{form_data.get('target', '')},"
            f"{form_data.get('style', '')},"
            f"{form_data.get('subject', '')}"
        )

        client = Client("rayesh/process_miniapp")
        
        # Submit job asynchronously
        loop = asyncio.get_event_loop()
        job = await loop.run_in_executor(
            executor,
            lambda: client.submit(
                form_data['video_url'],
                parameters,
                fn_index=0
            )
        )

        # Store initial state
        progress_states[job.job_hash] = {
            'status': 'started',
            'progress': 0,
            'message': ''
        }

        # Start tracking task
        asyncio.create_task(track_progress(job))

        return jsonify({
            'tracking_id': job.job_hash,
            'progress_url': url_for('progress_status', job_id=job.job_hash)
        }), 202

    except Exception as e:
        app.logger.error(f"Processing error: {e}")
        return jsonify({'error': str(e)}), 500

async def track_progress(job):
    job_id = job.job_hash
    try:
        while not job.done():
            await asyncio.sleep(0.5)
            status = await asyncio.get_event_loop().run_in_executor(
                executor, job.status
            )
            outputs = await asyncio.get_event_loop().run_in_executor(
                executor, job.outputs
            )
            
            if outputs:
                progress_states[job_id]['message'] = outputs[0]
                progress_states[job_id]['progress'] = len(outputs) * 25  # Example progress calculation

        if job.done():
            progress_states[job_id]['status'] = 'completed'
            completed_jobs.add(job_id)
    except Exception as e:
        progress_states[job_id]['status'] = 'failed'
        progress_states[job_id]['error'] = str(e)

@app.route('/progress/<job_id>')
@login_required
async def progress_status(job_id):
    state = progress_states.get(job_id, {})
    return jsonify({
        'status': state.get('status', 'unknown'),
        'progress': state.get('progress', 0),
        'message': state.get('message', ''),
        'completed': job_id in completed_jobs
    })

# Modified dashboard route with progress handling
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
                ''', (user.user_id,))
                videos = await cursor.fetchall()

        return await render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - {{ username }}</title>
            <style>
                /* Existing styles... */
                .progress-container {
                    display: none;
                    margin: 20px 0;
                    padding: 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }
                .progress-bar {
                    width: 0%;
                    height: 20px;
                    background-color: #4CAF50;
                    transition: width 0.3s ease;
                }
                #status-message { margin-top: 10px; }
            </style>
        </head>
        <body>
            <h1>{{ username }} خوش آمدید</h1>
            
            <!-- Progress Container -->
            <div class="progress-container">
                <div class="progress-bar"></div>
                <div id="status-message"></div>
            </div>

            <form id="processingForm" method="POST" action="{{ url_for('process_video') }}">
                <!-- Existing form content... -->
                
                <!-- Modified submit button -->
                <input type="submit" value="تایید پارامترها و ارسال" onclick="startProcessing(event)">
            </form>

            <script>
                function startProcessing(e) {
                    e.preventDefault();
                    const form = document.getElementById('processingForm');
                    const formData = new FormData(form);
                    
                    // Show progress container
                    document.querySelector('.progress-container').style.display = 'block';

                    fetch('/process_video', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.tracking_id) {
                            trackProgress(data.tracking_id, data.progress_url);
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                    });
                }

                function trackProgress(trackingId, progressUrl) {
                    const checkInterval = 1000;
                    const progressBar = document.querySelector('.progress-bar');
                    const statusMessage = document.getElementById('status-message');

                    const interval = setInterval(() => {
                        fetch(progressUrl)
                            .then(response => response.json())
                            .then(data => {
                                progressBar.style.width = data.progress + '%';
                                statusMessage.textContent = data.message;

                                if (data.completed) {
                                    clearInterval(interval);
                                    if (data.status === 'completed') {
                                        window.location.reload(); // Refresh to show new video
                                    }
                                }
                            });
                    }, checkInterval);
                }
            </script>
        </body>
        </html>
        ''',  username=user.user_data['username'], videos=videos)

    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return "Error loading dashboard", 500

# Async index route
@app.route('/')
async def index():
    user = await get_current_user()
    if user and user.is_authenticated:
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
