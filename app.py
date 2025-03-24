import uuid
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
import asyncio
from gradio_client import Client, handle_file
import queue

# Initialize Quart app
app = Quart(__name__)
app.progress_lock = asyncio.Lock()
app.secret_key = 'A1u3b8e0d@#'  # Should be environment variable in production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Bot configuration
BOT_TOKEN = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"
REQUIRED_FIELDS = ['bale_user_id', 'username', 'chat_id', 'url', 'video_name']

class User:
    def __init__(self, user_id: int, user_data: Dict[str, Any]):
        self.user_id = user_id  # ✅ Correct attribute name
        self.user_data = user_data
        self.is_authenticated = user_id is not None

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

# Modified progress state management

async def run_processing(job, progress_queue, job_id):
    try:
        loop = asyncio.get_event_loop()
        final_video = await loop.run_in_executor(
            executor,
            process_video_job,
            job,
            progress_queue
        )
        
        # Update state on completion
        progress_states[job_id].update({
            'status': 'completed',
            'progress': 100,
            'result_url': final_video,
            'end_time': datetime.now().isoformat()
        })
        
    except Exception as e:
        progress_states[job_id].update({
            'status': 'failed',
            'error': str(e),
            'end_time': datetime.now().isoformat()
        })


    except Exception as e:
        progress_states[job_id].update({
            'status': 'failed',
            'error': str(e)
        })
        app.logger.error(f"Processing failed: {e}")

def process_video_job(job, progress_queue):
    """Blocking video processing with progress updates"""
    final_video = None
    try:
        for update in job:
            progress_msg, video_output = update
            if progress_msg:
                progress_queue.put({
                    'message': progress_msg,
                    'progress': progress_msg  # Implement your progress parsing
                })
            if video_output:
                final_video = video_output
        return final_video
    except Exception as e:
        progress_queue.put({'error': str(e)})
        raise

async def update_progress(progress_queue, job_id):
    """Async progress state updater"""
    while True:
        try:
            update = progress_queue.get_nowait()
            
            if update is None:  # Completion signal
                break
                
            if 'error' in update:
                progress_states[job_id].update({
                    'status': 'failed',
                    'error': update['error']
                })
                break
                
            progress_states[job_id].update({
                'status': 'processing',
                'message': update['message'],
                'progress': update['progress']
            })

        except queue.Empty:
            await asyncio.sleep(0.1)

# Modified process_video endpoint
@app.route('/process_video', methods=['POST'])
@login_required
async def process_video():
    try:
        user = await get_current_user()
        # CORRECTED FORM HANDLING
        form_data = await request.form  # Get MultiDict
        video_url = form_data.get('video_url')
        
        if not video_url:
            return jsonify({'error': 'آدرس ویدیو الزامی است'}), 400

        parameters = (
            f"{form_data.get('font_type', 'arial')},"
            f"{form_data.get('font_size', 12)},"
            f"{form_data.get('font_color', 'yellow')},"
            f"{form_data.get('service', 'default_service')},"
            f"{form_data.get('target', '')},"
            f"{form_data.get('style', '')},"
            f"{form_data.get('subject', '')}"
        )

        client = Client("rayesh/process_miniapp")
        job = client.submit(
            video_url,
            parameters,
            fn_index=0
        )
        
        # Create progress queue and state
        progress_queue = queue.Queue()
        job_id = str(uuid.uuid4())  # Generate unique job ID
        
        progress_states[job_id] = {
            'user_id': user.user_id,
            'status': 'queued',
            'progress': 0,
            'message': 'در صف پردازش',
            'start_time': datetime.now().isoformat(),
            'parameters': parameters
        }

        # Start processing task
        asyncio.create_task(run_processing(job, progress_queue, job_id))

        return jsonify({
            'tracking_id': job_id,
            'progress_url': url_for('progress_status', job_id=job_id)
        }), 202

    except Exception as e:
        app.logger.error(f"Processing error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    

# Progress endpoint remains the same
# In progress_status endpoint
@app.route('/progress/<job_id>')
@login_required
async def progress_status(job_id):
    state = progress_states.get(job_id, {})
    user = await get_current_user()
    # Verify ownership
    if state.get('user_id') != user.user_id:
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    
    return jsonify({
        'status': state.get('status', 'unknown'),
        'progress': state.get('progress', 0),
        'message': state.get('message', ''),
        'result_url': state.get('result_url')
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
                /* Combined Styles */
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px;
                    direction: rtl;
                }
                .video-list { 
                    margin-top: 20px; 
                    padding: 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }
                .video-item { 
                    margin: 10px 0; 
                    padding: 10px; 
                    border: 1px solid #ddd; 
                    border-radius: 5px; 
                }
                .parameters { 
                    margin: 20px 0; 
                    padding: 20px; 
                    border: 1px solid #ddd; 
                }
                .param-group { 
                    margin: 10px 0; 
                }
                label { 
                    display: block; 
                    margin: 5px 0; 
                }
                input[type="text"], select, input[type="number"], input[type="color"] {
                    width: 200px; 
                    padding: 5px; 
                    margin-bottom: 10px;
                }
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
                .progress-states {
                margin: 20px 0;
                border-collapse: collapse;
                width: 100%;
                }
                .progress-states td {
                    padding: 8px;
                    border: 1px solid #ddd;
                }
                .status-indicator {
                    width: 20px;
                    height: 20px;
                    border-radius: 50%;
                    display: inline-block;
                }
                .processing { background-color: #ffd700; }
                .completed { background-color: #4CAF50; }
                .failed { background-color: #ff4444; }                           
                #status-message { 
                    margin-top: 10px; 
                    color: #666;
                }
            </style>
        </head>
        <body>
            <h1>{{ username }} خوش آمدید</h1>
        
            <!-- Progress Container -->
            <div class="progress-container">
                    <h2>وضعیت پردازش فعلی</h2>
                    <div class="progress-bar"></div>
                    <div id="status-message"></div>
                    <table class="progress-states">
                        <tr>
                            <td>شناسه کار:</td>
                            <td id="job-id">---</td>
                        </tr>
                        <tr>
                            <td>زمان شروع:</td>
                            <td id="start-time">---</td>
                        </tr>
                        <tr>
                            <td>وضعیت فعلی:</td>
                            <td>
                                <span id="current-status" class="status-indicator"></span>
                                <span id="status-text">در انتظار شروع</span>
                            </td>
                        </tr>
                    </table>
                </div>

        
            <form id="processingForm" method="POST" action="{{ url_for('process_video') }}">
                <div class="video-list">
                    <h2>انتخاب ویدیو:</h2>
                    {% if videos %}
                        {% for video in videos %}
                            <div class="video-item">
                                <input type="radio" name="video_url" value="{{ video.url }}" required>
                                <strong>{{ video.video_name }}</strong><br>
                                <a href="{{ video.url }}" class="video-link" target="_blank">مشاهده ویدیو</a><br>
                                <span class="timestamp">زمان آپلود: {{ video.creation_time }}</span>
                            </div>
                        {% endfor %}
                    {% else %}
                        <p>هیچ ویدیویی در ۲۴ ساعت گذشته آپلود نشده است.</p>
                    {% endif %}
                </div>
        
                <div class="parameters">
                    <h2>تنظیمات سفارشی:</h2>
                    <div class="param-group">
                        <label>نوع فونت:
                            <select name="font_type" required>
                                <option value="arial">آریال</option>
                                <option value="yekan">یکان</option>
                                <option value="nazanin">نازنین</option>
                            </select>
                        </label>
                        
                        <label>اندازه فونت:
                            <input type="number" name="font_size" min="8" max="72" value="12" required>
                        </label>
                        
                        <label>رنگ فونت:
                            <select name="font_color" required>
                                <option value="yellow">زرد</option>
                                <option value="black">مشکی</option>
                                <option value="white">سفید</option>
                            </select>
                        </label>
                    </div>
        
                    <div class="param-group">
                        <label>نوع سرویس:
                            <input type="text" name="service" placeholder="نوع سرویس را وارد کنید" required>
                        </label>
                        
                        <label>مخاطبان هدف:
                            <input type="text" name="target" placeholder="مخاطبان هدف را وارد کنید" required>
                        </label>
                        
                        <label>سبک:
                            <input type="text" name="style" placeholder="سبک ویدیو را وارد کنید" required>
                        </label>
                        
                        <label>موضوع اصلی:
                            <input type="text" name="subject" placeholder="موضوع اصلی را وارد کنید" required>
                        </label>
                    </div>
                </div>
        
                <input type="submit" value="تایید پارامترها و ارسال" onclick="startProcessing(event)">
            </form>
        
            <script>
                
                // Enhanced tracking with error handling
                function trackProgress(jobId) {
                    let retryCount = 0;
                    const maxRetries = 5;
                    const progressUrl = `/progress/${jobId}`;

                    const updateProgress = async () => {
                        try {
                            const response = await fetch(progressUrl);
                            
                            if (!response.ok) {
                                throw new Error(`HTTP error! status: ${response.status}`);
                            }
                            
                            const data = await response.json();
                            
                            // Update UI elements
                            document.querySelector('.progress-bar').style.width = `${data.progress}%`;
                            document.getElementById('status-text').textContent = data.message;
                            document.getElementById('job-id').textContent = jobId;
                            
                            // Update status indicator
                            const statusIndicator = document.getElementById('current-status');
                            statusIndicator.className = 'status-indicator ' + data.status;
                            
                            // Handle completion
                            if (data.status === 'completed') {
                                document.getElementById('start-time').textContent = new Date().toLocaleString();
                                if (data.result_url) {
                                    // Dynamically add new video to list
                                    const videoList = document.querySelector('.video-list');
                                    const newVideo = document.createElement('div');
                                    newVideo.className = 'video-item';
                                    newVideo.innerHTML = `
                                        <strong>ویدیو پردازش شده</strong><br>
                                        <a href="${data.result_url}" target="_blank">مشاهده ویدیو</a>
                                    `;
                                    videoList.prepend(newVideo);
                                }
                            } else if (data.status === 'failed') {
                                document.getElementById('status-text').textContent = `خطا: ${data.error}`;
                            }

                            // Continue polling if still processing
                            if (!['completed', 'failed'].includes(data.status)) {
                                setTimeout(updateProgress, 1000);
                            }

                        } catch (error) {
                            if (retryCount < maxRetries) {
                                retryCount++;
                                setTimeout(updateProgress, 1000 * retryCount);
                            } else {
                                document.getElementById('status-text').textContent = 
                                    'خطا در ارتباط با سرور. لطفا صفحه را رفرش کنید.';
                            }
                        }
                    };

                    // Get initial job metadata
                    fetch(`/job_meta/${jobId}`)
                        .then(response => response.json())
                        .then(meta => {
                            document.getElementById('start-time').textContent = 
                                new Date(meta.start_time).toLocaleString();
                        });

                    updateProgress();
                }

                // Modified startProcessing with enhanced error handling
                async function startProcessing(e) {
                    e.preventDefault();
                    const form = document.getElementById('processingForm');
                    const formData = new FormData(form);
                    
                    try {
                        // Show progress section
                        document.querySelector('.progress-container').style.display = 'block';
                        document.getElementById('status-text').textContent = 'در حال آماده سازی پردازش...';

                        const response = await fetch('/process_video', {
                            method: 'POST',
                            body: formData
                        });

                        if (!response.ok) {
                            throw new Error(`HTTP error! status: ${response.status}`);
                        }

                        const data = await response.json();
                        
                        if (data.tracking_id) {
                            trackProgress(data.tracking_id);
                        } else {
                            throw new Error('Missing tracking ID in response');
                        }

                    } catch (error) {
                        console.error('Processing error:', error);
                        document.getElementById('status-text').textContent = 
                            `خطا در شروع پردازش: ${error.message}`;
                        document.getElementById('current-status').className = 
                            'status-indicator failed';
                    }
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
