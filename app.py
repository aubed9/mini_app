
from quart import Quart, request, jsonify, render_template_string, redirect, url_for
from quart_auth import AuthUser, LoginManager, login_user, logout_user, current_user, login_required
import hmac
import hashlib
import json
from aiomysql import create_pool, Error as aiomysqlError
from datetime import datetime
import logging
from typing import Dict, Any

# Initialize Quart app
app = Quart(__name__)
app.secret_key = 'A1u3b8e0d@#'  # Replace with secure key in production

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Quart-Auth setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Bot configuration
BOT_TOKEN = "640108494:Y4Hr2wDc8hdMjMUZPJ5DqL7j8GfSwJIETGpwMH12"
REQUIRED_FIELDS = ['bale_user_id', 'username', 'chat_id', 'url', 'video_name']

class User(AuthUser):
    def __init__(self, auth_id: str, user_data: Dict[str, Any]):
        super().__init__(auth_id)
        self.user_data = user_data

@login_manager.user_loader
async def load_user(auth_id: str) -> User:
    """Async user loader for Quart-Auth"""
    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT id, bale_user_id, username FROM users WHERE id = %s",
                    (auth_id,)
                )
                user_data = await cursor.fetchone()
                
                if user_data:
                    return User(
                        auth_id=str(user_data[0]),
                        user_data={
                            'id': user_data[0],
                            'bale_user_id': user_data[1],
                            'username': user_data[2]
                        }
                    )
    except Exception as e:
        logger.error(f"User load error: {e}")
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
        logger.info("Database initialized successfully")
                
    except Exception as e:
        logger.critical(f"Database setup failed: {e}")
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
            async with conn.cursor() as cursor:
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
                await conn.commit()
                return jsonify({'message': 'User registered successfully'}), 201

    except aiomysqlError as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Database operation failed'}), 500

# Database pool configuration (configure in app startup)
@app.before_serving
async def create_db_pool():
    app.pool = await aiomysql.create_pool(
        host='annapurna.liara.cloud',
        port=32002,
        user='root',
        password='4zjqmEfeRhCqYYDhvkaODXD3',
        db='users',
        cursorclass=aiomysql.DictCursor
    )

# Modified login route
@app.route('/login', methods=['POST'])
async def login():
    """Async user login"""
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
                    user = AuthUser(str(user_record['id']))
                    login_user(user)
                    return jsonify({
                        'status': 'logged_in',
                        'user': {
                            'id': user_record['id'],
                            'username': user_record['username']
                        }
                    })
                else:
                    return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        app.logger.error(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500

# Modified dashboard route
@app.route('/dashboard')
@login_required
async def dashboard():
    try:
        async with app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
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
            <!-- rest of your template remains the same -->
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
        form_data = await request.form
        video_url = form_data.get('video_url')
        # Rest of your processing logic
        
        # Use async sleep instead of blocking sleep
        while not job.done():
            await asyncio.sleep(0.5)
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        app.logger.error(f"Processing error: {e}")
        return redirect(url_for('dashboard'))

# Modified logout route
@app.route('/logout')
@login_required
async def logout():
    logout_user()
    return redirect(url_for('index'))

# Async index route
@app.route('/')
async def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return await render_template_string('''... your index template ...''')

if __name__ == '__main__':
    uvicorn.run("main:app", host="0.0.0.0", port=80)
