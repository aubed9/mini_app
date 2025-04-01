import uuid

import aiofiles
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
import aiohttp
from urllib.parse import quote_plus
import os
from aiohttp import FormData
from typing import Dict, Any, Tuple, Union, List
from functools import wraps


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
                        "INSERT INTO users (bale_user_id, username, chat_id) VALUES (%s, %s, %s)",
                        (data['bale_user_id'], data['username'], data['bale_user_id'])
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
    data = await request.get_json()
    init_data = data.get('initData')
    
    if not init_data:
        return jsonify({'error': 'Missing initData'}), 400

    is_valid, validation_result = validate_init_data(init_data)
    if not is_valid:
        return jsonify({'error': validation_result}), 400

    try:
        user_data = validation_result.get('user', {})
        if not isinstance(user_data, dict):
            return jsonify({'error': 'Invalid user data'}), 400

        bale_user_id = user_data['id']
        username = user_data.get('username', '')
    except KeyError as e:
        return jsonify({'error': f'Missing field: {e}'}), 400

    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor(DictCursor) as cursor:
                # Check existing user
                await cursor.execute(
                    "SELECT id FROM users WHERE bale_user_id = %s",
                    (bale_user_id,)
                )
                if await cursor.fetchone():
                    return jsonify({'error': 'User already exists'}), 400

                # Insert new user
                await cursor.execute(
                    "INSERT INTO users (bale_user_id, username) VALUES (%s, %s)",
                    (bale_user_id, username)
                )
                user_id = cursor.lastrowid
                await conn.commit()

                return jsonify({
                    'message': 'User registered successfully',
                    'user_id': user_id
                }), 201

    except aiomysql.Error as e:
        await conn.rollback()
        app.logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Database operation failed'}), 500

# Global state management (use Redis in production)
progress_states = {}
completed_jobs = set()
executor = ThreadPoolExecutor(max_workers=4)

# Modified progress state management

async def run_processing(job, progress_queue, job_id, user_id):
    try:
        loop = asyncio.get_event_loop()
        # Ensure process_video_job returns the full path to the final video
        final_video_path = await loop.run_in_executor(
            executor,
            process_video_job,
            job,
            progress_queue
        )

        # --- Defensive Check ---
        if not final_video_path or not os.path.exists(final_video_path):
             app.logger.error(f"Job {job_id}: process_video_job did not return a valid file path or file does not exist: {final_video_path}")
             progress_states[job_id].update({
                 'status': 'failed',
                 'error': 'Processing failed to produce video file.',
                 'end_time': datetime.now().isoformat()
             })
             # Potentially notify the user or handle the failure appropriately
             return # Stop execution if the video file isn't there

        # Update state on completion
        progress_states[job_id].update({
            'status': 'completed',
            'progress': 100,
            'result_url': final_video_path, # Store the path, or generate a URL if applicable
            'end_time': datetime.now().isoformat()
        })

        app.logger.info(f"Job {job_id}: Processing completed. Final video at: {final_video_path}. Preparing to send to user {user_id}.")

        # --- Sending Video using aiohttp.FormData ---
        async with aiohttp.ClientSession() as session:
            # Create a FormData object
            form_data = FormData()

            # Add regular data fields to the FormData object
            # Ensure user_id is converted to a string if it isn't already,
            # as form fields are typically strings.
            form_data.add_field('chat_id', str(user_id))
            print(user_id)
            # Open the video file asynchronously
            try:
                async with aiofiles.open(final_video_path, mode='rb') as video_f:
                    video_filename = os.path.basename(final_video_path)
                    app.logger.info(f"Job {job_id}: Opened file {video_filename} for upload.")

                    # Add the file field to the FormData object
                    # Arguments: field_name, file_object, filename, content_type (optional but recommended)
                    form_data.add_field(
                        'video',                     # The field name expected by the Bale API
                        video_f,                     # The async file handle
                        filename=video_filename,     # The filename to be sent
                        content_type='video/mp4'     # Specify the content type (adjust if needed, e.g., 'video/quicktime')
                    )

                    # Define the Bale API URL
                    # Consider moving the token and base URL to configuration/environment variables
                    bot_token = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"
                    url = f"https://tapi.bale.ai/bot{bot_token}/sendVideo"

                    app.logger.info(f"Job {job_id}: Sending POST request to {url} with video for user {user_id}.")

                    # Make the POST request using the FormData object in the 'data' parameter
                    async with session.post(url, data=form_data) as response:
                        # Log request details for debugging potential API issues
                        app.logger.debug(f"Job {job_id}: Bale API response status: {response.status}")
                        response_text = await response.text() # Read response body regardless of status for logging
                        app.logger.debug(f"Job {job_id}: Bale API response body: {response_text}")

                        if response.status == 200:
                            app.logger.info(
                                f"Job {job_id}: Successfully sent video to Bale for user {user_id}"
                            )
                            # Optionally: Clean up the generated video file after successful sending
                            # try:
                            #     os.remove(final_video_path)
                            #     app.logger.info(f"Job {job_id}: Cleaned up temporary file {final_video_path}")
                            # except OSError as e:
                            #     app.logger.error(f"Job {job_id}: Error deleting file {final_video_path}: {e}")

                        else:
                            # Log the error with more context
                            app.logger.error(
                                f"Job {job_id}: Bale API error sending video for user {user_id}. Status: {response.status}, Response: {response_text}"
                            )
                            # Update job state to reflect API failure
                            progress_states[job_id].update({
                                'status': 'failed',
                                'error': f'Bale API error: {response.status}',
                                'api_response': response_text # Store API response for debugging
                            })

            except FileNotFoundError:
                 app.logger.error(f"Job {job_id}: File not found error when trying to open {final_video_path} for upload.")
                 progress_states[job_id].update({
                     'status': 'failed',
                     'error': 'Processed video file not found during upload attempt.',
                     'end_time': datetime.now().isoformat()
                 })
            except Exception as e:
                 app.logger.error(f"Job {job_id}: An unexpected error occurred during file upload preparation or sending: {e}", exc_info=True)
                 progress_states[job_id].update({
                     'status': 'failed',
                     'error': f'Upload failed: {e}',
                     'end_time': datetime.now().isoformat()
                 })


    except Exception as e:
        # Log the exception traceback for detailed debugging
        app.logger.error(f"Processing failed for job {job_id}: {e}", exc_info=True)
        # Update state on failure
        progress_states[job_id].update({
            'status': 'failed',
            'error': str(e),
            'end_time': datetime.now().isoformat()
        })
        # Optionally re-raise the exception if needed elsewhere, or handle recovery
        # raise e
        # --- NEW CODE END ---
        
    except Exception as e:
        progress_states[job_id].update({
            'status': 'failed',
            'error': str(e),
            'end_time': datetime.now().isoformat()
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
                print(video_output)
                final_video = video_output["video"]
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

        # Create progress queue and set initial progress state
        progress_queue = queue.Queue()  # Thread-safe queue
        job_id = str(uuid.uuid4())

        progress_states[job_id] = {
            'user_id': user.user_id,
            'status': 'queued',
            'progress': 0,
            'message': 'در صف پردازش',
            'start_time': datetime.now().isoformat(),
            'parameters': parameters
        }

        # Start the update_progress coroutine as a background task
        asyncio.create_task(update_progress(progress_queue, job_id))
        # Start running the processing job
        asyncio.create_task(run_processing(job, progress_queue, job_id, user.user_data["bale_user_id"]))

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

        return await jsonify({"username":user.user_data['username'],
                               "videos":videos})

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
