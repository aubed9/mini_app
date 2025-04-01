import uuid
import asyncio
import json
import hmac
import hashlib
import queue
import os
import logging
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Tuple, Union, List

import aiofiles  # For async file operations
import aiohttp   # For async HTTP requests
from aiohttp import FormData # For multipart/form-data uploads
from aiomysql import DictCursor, create_pool, Error as aiomysqlError # Async MySQL
from quart import (
    Quart, request, jsonify, render_template_string, redirect, url_for, session
)
from gradio_client import Client # Assuming this client has async capabilities or is used in threads
# Note: `handle_file` might need async adaptation if used directly in async context

# --- Logging Setup ---
# Configure logging for better debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Initialize Quart App ---
app = Quart(__name__)
app.secret_key = os.environ.get('QUART_SECRET_KEY', 'A1u3b8e0d@#_default_dev_key') # Use env var
app.config['SESSION_COOKIE_SECURE'] = True # Recommended for production (requires HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- Configuration ---
# It's highly recommended to load sensitive info from environment variables
BOT_TOKEN = os.environ.get("BALE_BOT_TOKEN", "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12") # Example placeholder
REQUIRED_FIELDS = ['bale_user_id', 'username', 'chat_id', 'url', 'video_name']
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'annapurna.liara.cloud'),
    'user': os.environ.get('DB_USER', 'root'),
    'port': int(os.environ.get('DB_PORT', 32002)),
    'password': os.environ.get('DB_PASSWORD', '4zjqmEfeRhCqYYDhvkaODXD3'), # Store securely!
    'db': os.environ.get('DB_NAME', 'users'),
    'autocommit': False, # Explicit commits/rollbacks are generally safer
    'minsize': 3,
    'maxsize': 10
}
REQUIRED_VIDEO_SAVE_FIELDS = ['bale_user_id', 'username', 'chat_id', 'url', 'video_name'] # Specific to save_video endpoint

# --- Global State (Consider Redis/external store for production scalability) ---
progress_states: Dict[str, Dict[str, Any]] = {} # Stores job progress {job_id: state_dict}
# completed_jobs = set() # If needed for tracking completed jobs separately
executor = ThreadPoolExecutor(max_workers=int(os.environ.get('THREAD_POOL_WORKERS', 4))) # For running blocking code

# --- User Class ---
class User:
    """Represents an authenticated user."""
    def __init__(self, user_id: int, user_data: Dict[str, Any]):
        self.user_id: int = user_id # Internal DB ID
        self.user_data: Dict[str, Any] = user_data # Other details like bale_user_id, username
        self.is_authenticated: bool = user_id is not None

    def __repr__(self) -> str:
        return f"<User id={self.user_id} bale_id={self.user_data.get('bale_user_id')} username='{self.user_data.get('username')}'>"

# --- Decorators ---
def login_required(f):
    """Decorator to ensure the user is logged in via session."""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logger.warning("Unauthorized access attempt blocked by login_required.")
            return jsonify({'error': 'Unauthorized Access', 'message': 'Please log in.'}), 401
        # Optionally, fetch the user object here if needed universally in protected routes
        # user = await get_current_user()
        # if not user:
        #     session.pop('user_id', None) # Clean up invalid session
        #     return jsonify({'error': 'Unauthorized Access', 'message': 'Invalid session.'}), 401
        # kwargs['current_user'] = user # Pass user object to the route
        return await f(*args, **kwargs)
    return decorated_function

# --- Utility Functions ---

async def get_current_user() -> User | None:
    """Fetches the current user based on session data."""
    user_db_id = session.get('user_id')
    if not user_db_id:
        return None

    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor(DictCursor) as cursor: # Use DictCursor for easier access
                await cursor.execute(
                    "SELECT id, bale_user_id, username FROM users WHERE id = %s",
                    (user_db_id,)
                )
                user_record = await cursor.fetchone()
                if user_record:
                    # Create a User object with fetched data
                    return User(
                        user_id=user_record['id'],
                        user_data={
                            'id': user_record['id'], # Internal ID
                            'bale_user_id': user_record['bale_user_id'],
                            'username': user_record['username']
                            # Add other fields from DB if needed
                        }
                    )
                else:
                    # User ID in session but not in DB (maybe deleted?)
                    logger.warning(f"User ID {user_db_id} found in session but not in database.")
                    session.pop('user_id', None) # Clean up invalid session
                    return None
    except aiomysqlError as db_err:
        logger.error(f"Database error fetching user {user_db_id}: {db_err}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching user {user_db_id}: {e}", exc_info=True)
        return None

# --- Database Setup ---
@app.before_serving
async def setup_db():
    """Initialize database connection pool and ensure tables exist."""
    logger.info("Setting up database connection pool...")
    try:
        app.pool = await create_pool(**DB_CONFIG)
        logger.info(f"Database pool created for {DB_CONFIG['db']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}")

        # Ensure tables are created (safe to run multiple times)
        async with app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                logger.info("Checking/Creating database tables...")
                await cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        bale_user_id BIGINT UNIQUE NOT NULL, -- Use BIGINT for potentially large IDs
                        username VARCHAR(255), -- Specify length
                        chat_id BIGINT, -- Store chat_id if needed, maybe from validation?
                        registration_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login_time TIMESTAMP NULL
                    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; -- Use utf8mb4
                ''')
                logger.debug("`users` table checked/created.")

                await cursor.execute('''
                    CREATE TABLE IF NOT EXISTS videos (
                        id INT PRIMARY KEY AUTO_INCREMENT,
                        user_id INT NOT NULL,
                        -- Consider removing redundant username/chat_id if always derivable from user_id
                        -- username VARCHAR(255),
                        -- chat_id BIGINT,
                        url TEXT NOT NULL, -- URL submitted by user
                        video_name VARCHAR(512), -- Name provided by user
                        processing_job_id VARCHAR(36) UNIQUE, -- Link to progress_states key (UUID)
                        status VARCHAR(50) DEFAULT 'pending', -- e.g., pending, processing, completed, failed
                        result_url TEXT, -- URL/path to the processed video
                        creation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completion_time TIMESTAMP NULL,
                        error_message TEXT, -- Store errors if processing fails
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE -- Cascade delete if user is removed
                    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; -- Use utf8mb4
                ''')
                logger.debug("`videos` table checked/created.")
                await conn.commit() # Commit table creation
        logger.info("Database setup complete.")

    except aiomysqlError as db_err:
        logger.critical(f"FATAL: Database connection/setup failed: {db_err}", exc_info=True)
        # Depending on deployment, might want to exit or retry
        raise SystemExit(f"Database setup failed: {db_err}")
    except Exception as e:
        logger.critical(f"FATAL: Unexpected error during database setup: {e}", exc_info=True)
        raise SystemExit(f"Unexpected error during setup: {e}")

@app.after_serving
async def cleanup_db():
    """Close the database pool when the app shuts down."""
    logger.info("Closing database connection pool...")
    if hasattr(app, 'pool') and app.pool:
        app.pool.close()
        await app.pool.wait_closed()
        logger.info("Database pool closed.")

# --- [NEW] Asynchronous URL Decoding and Parsing ---

async def url_decode(s: str) -> str:
    """
    Asynchronously decodes a URL-encoded string (percent-encoding).
    Handles '+' as space. Replaces errors.
    Note: The core logic is CPU-bound. Declared async primarily to fit into
          an async call chain if required by the caller.
    """
    # logger.debug(f"Async url_decode starting for: '{s[:100]}...'")
    bytes_list = []
    i = 0
    len_s = len(s)
    while i < len_s:
        char = s[i]
        if char == '%':
            if i + 2 < len_s:
                hex_code = s[i+1:i+3]
                try:
                    byte_val = int(hex_code, 16)
                    bytes_list.append(byte_val)
                    i += 3
                except ValueError:
                    # Invalid hex code, treat '%' literally
                    logger.warning(f"Invalid hex sequence '%{hex_code}' found during URL decoding.")
                    bytes_list.append(ord('%'))
                    i += 1
            else:
                # Incomplete escape sequence, treat '%' literally
                logger.warning("Incomplete '%' escape sequence at end of string during URL decoding.")
                bytes_list.append(ord('%'))
                i += 1
        elif char == '+':
            # Decode '+' as space (byte 0x20)
            bytes_list.append(0x20)
            i += 1
        else:
            # Append ASCII/UTF-8 byte value of the character
            # This assumes the original encoding allows direct ord(), which is typical for URL components
            try:
                 bytes_list.append(ord(char))
            except TypeError:
                 # Should not happen with strings, but as safety
                 logger.error(f"Cannot get ord() of character: {char!r}")
                 bytes_list.append(ord('?')) # Replace with placeholder
            i += 1
        # # Uncomment to yield control occasionally if decoding very long strings in a tight loop
        # if i % 1000 == 0: await asyncio.sleep(0)

    decoded_bytes = bytes(bytes_list)
    try:
        # Decode using UTF-8, standard for modern web
        result = decoded_bytes.decode('utf-8')
    except UnicodeDecodeError as ude:
        # Handle cases where bytes are not valid UTF-8
        logger.warning(f"UnicodeDecodeError during URL decoding: {ude}. Replacing invalid bytes.")
        result = decoded_bytes.decode('utf-8', errors='replace')

    # logger.debug(f"Async url_decode finished. Result: '{result[:100]}...'")
    return result

async def parse_qs(query_string):
    """
    Asynchronously parses a query string (e.g., from initData) into a dictionary.
    Handles multiple values for the same key by creating a list.
    Calls the async version of url_decode.
    """
    # logger.debug(f"Async parse_qs starting for: '{query_string[:100]}...'")
    params = {}
    pairs = query_string.split('&')
    for pair in pairs:
        if not pair:
            continue
        parts = pair.split('=', 1)
        key = await url_decode(parts[0])
        value = await url_decode(parts[1]) if len(parts) > 1 else ''
        if key in params:
            if isinstance(params[key], list):
                params[key].append(value)
            else:
                params[key] = [params[key], value]
        else:
            params[key] = value
    return params

# --- [NEW] Asynchronous initData Validation ---
async def validate_init_data(init_data: str, bot_token: str) -> Tuple[bool, Union[str, Dict[str, Any]]]:
    """
    Asynchronously validates Telegram/Bale WebApp initData.

    Args:
        init_data: The raw initData string (URL-encoded query string).
        bot_token: The secret bot token used for HMAC validation.

    Returns:
        A tuple: (is_valid, data_or_error_message)
        If valid: (True, dictionary_of_parsed_and_validated_data (excluding hash))
        If invalid: (False, error_message_string)
    """
    logger.debug("Async validate_init_data starting...")
    if not init_data:
        logger.warning("Validation failed: initData string is empty.")
        return False, "initData string cannot be empty"
    if not bot_token:
         logger.error("Validation check cannot proceed: Bot Token is missing.")
         # Avoid exposing token issues directly to client if possible
         return False, "Validation configuration error."

    try:
        # Step 1: URL Decode the initData string (which is expected to be query string format)
        # This is often implicitly done by frameworks when accessing request data,
        # but Telegram initData is usually passed raw, so explicit decoding is needed.
        # No need to decode here IF init_data comes directly from a source
        # that *already* decoded it (like request.args in some frameworks).
        # However, Bale's `initData` is typically the raw, encoded string.
        # decoded_init_data = await url_decode(init_data) # Decode the whole string first if needed
        # For Telegram/Bale, parse_qs handles the decoding of keys/values internally.

        # Step 2: Parse the query string into key-value pairs
        # parsed_data = await parse_qs(decoded_init_data) # If decoded above
        decoded_init_data = await url_decode(init_data)
        print(decoded_init_data)
        parsed_data = await parse_qs(decoded_init_data)
        print(parsed_data)
        data_dict = {k: v[0] if isinstance(v, list) else v for k, v in parsed_data.items()}
        hash_value = data_dict.pop('hash', None)
        print(hash_value)
        if not hash_value:
            return False, "Missing hash in initData"
        sorted_keys = sorted(data_dict.keys())
        data_check_string = "\n".join([f"{k}={data_dict[k]}" for k in sorted_keys])
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        check_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if check_hash != hash_value:
            return False, "Invalid hash, data may be tampered"
        return True, data_dict
    
    except Exception as e:
        # Catch potential errors during decoding/parsing/validation
        app.logger.error(f"Error during initData validation: {e}", exc_info=True)
        return False, f"Error during validation process: {e}"

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

    is_valid, validation_result = await validate_init_data(init_data, BOT_TOKEN)
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

    is_valid, validation_result = await validate_init_data(init_data, BOT_TOKEN)
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

        return jsonify({
            "username": user.user_data['username'],
            "videos": videos
        })

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
