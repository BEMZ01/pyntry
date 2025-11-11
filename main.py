VERSION = 0.1
import json
import os
import re
import time
from pprint import pprint
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, DecimalField, RadioField, SelectField, TextAreaField, \
    FileField
from wtforms.fields.datetime import DateField
from wtforms.fields.numeric import IntegerRangeField, IntegerField
from wtforms.validators import InputRequired, Length, Regexp, ValidationError
import sqlite3 as sql
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin

load_dotenv()
if os.getenv("APP_SECRET") is None or os.getenv("APP_SECRET") == "":
    print("APP_SECRET not found in .env file. Generating one...")
    with open('.env', 'a') as f:
        f.write(f'\nAPP_SECRET={os.urandom(32).hex()}\n')
    print("APP_SECRET generated. Please restart the application.")
    exit(1)

app = Flask(__name__)
login_manager = LoginManager()

app.secret_key = os.getenv("APP_SECRET")
# Security configurations
app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_DEBUG", "False").lower() not in ["true", "1"]
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire
app.config['WTF_CSRF_SSL_STRICT'] = os.getenv("FLASK_DEBUG", "False").lower() not in ["true", "1"]

csrf = CSRFProtect(app)
login_manager.init_app(app)
login_manager.login_view = "login"

# Rate limiting storage (in production, use Redis or similar)
login_attempts = {}

# Room templates with predefined chores
ROOM_TEMPLATES = {
    'Kitchen': {
        'color': '#48BB78',  # Green
        'icon': 'utensils',
        'chores': [
            {'name': 'Vacuum floor', 'description': 'Vacuum or sweep the kitchen floor', 'repeat_days': 3, 'points': 5},
            {'name': 'Wipe counters', 'description': 'Clean and disinfect kitchen counters', 'repeat_days': 1, 'points': 3},
            {'name': 'Clean fridge', 'description': 'Clean inside and outside of refrigerator', 'repeat_days': 14, 'points': 8},
            {'name': 'Organize cupboards', 'description': 'Organize kitchen cupboards and shelves', 'repeat_days': 30, 'points': 10},
            {'name': 'Organize drawers', 'description': 'Organize kitchen drawers', 'repeat_days': 30, 'points': 8},
            {'name': 'Organize pantry', 'description': 'Sort and organize pantry items', 'repeat_days': 21, 'points': 10},
            {'name': 'Clean trash can', 'description': 'Clean and sanitize trash can', 'repeat_days': 7, 'points': 5}
        ]
    },
    'Bathroom': {
        'color': '#38B2AC',  # Teal/Turquoise
        'icon': 'bath',
        'chores': [
            {'name': 'Clean shower/tub', 'description': 'Scrub and clean shower or bathtub', 'repeat_days': 7, 'points': 8},
            {'name': 'Clean toilet', 'description': 'Clean and sanitize toilet', 'repeat_days': 3, 'points': 5},
            {'name': 'Wipe counters', 'description': 'Clean bathroom counters and sink', 'repeat_days': 2, 'points': 3},
            {'name': 'Clean mirrors', 'description': 'Clean bathroom mirrors', 'repeat_days': 7, 'points': 3}
        ]
    },
    'Bedroom': {
        'color': '#4299E1',  # Blue
        'icon': 'bed',
        'chores': [
            {'name': 'Change bed linen', 'description': 'Change sheets and pillowcases', 'repeat_days': 14, 'points': 8},
            {'name': 'Dust', 'description': 'Dust surfaces and furniture', 'repeat_days': 7, 'points': 5},
            {'name': 'Vacuum floor', 'description': 'Vacuum or sweep bedroom floor', 'repeat_days': 7, 'points': 5},
            {'name': 'Organize closet', 'description': 'Organize closet and drawers', 'repeat_days': 30, 'points': 10}
        ]
    },
    'Living Room': {
        'color': '#63B3ED',  # Light Blue
        'icon': 'couch',
        'chores': [
            {'name': 'Dust', 'description': 'Dust all surfaces and shelves', 'repeat_days': 7, 'points': 5},
            {'name': 'Vacuum floor', 'description': 'Vacuum carpet or sweep floor', 'repeat_days': 5, 'points': 5},
            {'name': 'Organize items', 'description': 'Tidy up and organize living room items', 'repeat_days': 3, 'points': 3}
        ]
    },
    'Office': {
        'color': '#667EEA',  # Purple-Blue
        'icon': 'briefcase',
        'chores': [
            {'name': 'Dust', 'description': 'Dust desk and shelves', 'repeat_days': 7, 'points': 3},
            {'name': 'Organize desk', 'description': 'Organize and declutter desk', 'repeat_days': 7, 'points': 5},
            {'name': 'Clean surfaces', 'description': 'Wipe down all surfaces', 'repeat_days': 7, 'points': 3}
        ]
    },
    'Garden': {
        'color': '#68D391',  # Light Green
        'icon': 'leaf',
        'chores': [
            {'name': 'Mow lawn', 'description': 'Mow the grass', 'repeat_days': 14, 'points': 10},
            {'name': 'Water plants', 'description': 'Water garden plants', 'repeat_days': 2, 'points': 3},
            {'name': 'General maintenance', 'description': 'Weed, trim, and maintain garden', 'repeat_days': 7, 'points': 8}
        ]
    },
    'Dining Room': {
        'color': '#9F7AEA',  # Purple
        'icon': 'wine-glass',
        'chores': [
            {'name': 'Dust', 'description': 'Dust table and surfaces', 'repeat_days': 7, 'points': 3},
            {'name': 'Vacuum floor', 'description': 'Vacuum or sweep floor', 'repeat_days': 7, 'points': 5},
            {'name': 'Clean table', 'description': 'Clean and polish dining table', 'repeat_days': 3, 'points': 3}
        ]
    },
    'Laundry': {
        'color': '#667EEA',  # Purple-Blue
        'icon': 'tshirt',
        'chores': [
            {'name': 'Do laundry', 'description': 'Wash, dry, and fold laundry', 'repeat_days': 3, 'points': 8},
            {'name': 'Clean machines', 'description': 'Clean washer and dryer', 'repeat_days': 30, 'points': 5},
            {'name': 'Organize', 'description': 'Organize laundry supplies', 'repeat_days': 30, 'points': 3}
        ]
    }
}


def cleanup_old_attempts():
    """Clean up login attempts older than 15 minutes"""
    cutoff_time = datetime.now() - timedelta(minutes=15)
    for ip in list(login_attempts.keys()):
        login_attempts[ip] = [t for t in login_attempts[ip] if t > cutoff_time]
        if not login_attempts[ip]:
            del login_attempts[ip]

def check_rate_limit(ip_address, max_attempts=5, window_minutes=15):
    """Check if IP has exceeded rate limit"""
    cleanup_old_attempts()
    attempts = login_attempts.get(ip_address, [])
    cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
    recent_attempts = [t for t in attempts if t > cutoff_time]
    return len(recent_attempts) < max_attempts

def record_attempt(ip_address):
    """Record a login attempt"""
    if ip_address not in login_attempts:
        login_attempts[ip_address] = []
    login_attempts[ip_address].append(datetime.now())


class User(UserMixin):
    def __init__(self, username=None, given_password=None, id=None):
        if id is None and given_password is not None and username is not None:
            with sql.connect(os.getenv("DB_PATH")) as conn:
                c = conn.cursor()
                c.execute('SELECT password FROM users WHERE username = ?', (username,))
                user = c.fetchone()
                if user is None:
                    raise ValueError("User not found.")
                if not check_password_hash(user[0], given_password):
                    raise ValueError("Password incorrect.")
                c.execute('SELECT id, active FROM users WHERE username = ?', (username,))
                user = c.fetchone()
            self.id = user[0]
            self.username = username
            self.active = True if user[1] else False
            if self.active is False:
                raise ValueError("User is inactive.")
        elif id is not None:
            self.id = id
            with sql.connect(os.getenv("DB_PATH")) as conn:
                c = conn.cursor()
                c.execute('SELECT username, active FROM users WHERE id = ? and username = ?', (id, username))
                user = c.fetchone()
                if user is None:
                    raise ValueError("User not found.")
            self.username = user[0]
            self.active = True if user[1] else False
            if self.username is None:
                raise ValueError("User not found.")
            if self.active is False:
                raise ValueError("User is inactive.")

    def is_active(self):
        return self.active

    def is_authenticated(self):
        return self.active

    def is_anonymous(self):
        # dont allow anonymous logins
        return False

    def update(self):
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE id = ?', (self.id,))
            user = c.fetchone()
            if user is None:
                raise ValueError("User not found.")
        self.id = user[0]
        self.username = user[1]
        self.active = True if user[3] else False


def validate_password_strength(form, field):
    """Validate password meets security requirements"""
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(),
        Length(min=3, max=32, message='Username must be between 3 and 32 characters')
    ])
    password = PasswordField('Password', validators=[InputRequired()])
    persist = BooleanField('Remember Me?', default=True)


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(),
        Length(min=3, max=32, message='Username must be between 3 and 32 characters'),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    password = PasswordField('Password', validators=[
        InputRequired(),
        validate_password_strength
    ])
    password_confirm = PasswordField('Password Confirm', validators=[InputRequired()])


class AddItemForm(FlaskForm):
    name = StringField('Name of product')
    quantity = IntegerField('Quantity', validators=[InputRequired()])
    barcode = IntegerField('Product barcode', id='barcode_input')
    expiry_date = DateField('Date of expiry')
    expire_type = RadioField('Type of expiry', choices=['Best Before', 'Use By', 'Sell By'])


class RoomForm(FlaskForm):
    name = StringField('Room Name', validators=[InputRequired(), Length(min=1, max=100)])
    color = StringField('Color (hex code)', default='#4A90E2')
    icon = StringField('Icon name', default='home')
    use_template = SelectField('Use Template', choices=[('', 'Custom Room')] + [(name, name) for name in ROOM_TEMPLATES.keys()], default='')


class ChoreForm(FlaskForm):
    name = StringField('Chore Name', validators=[InputRequired(), Length(min=1, max=200)])
    description = TextAreaField('Description')
    repeat_days = IntegerField('Repeat every (days)', validators=[InputRequired()], default=7)
    points = IntegerField('Points (awarded on due date)', validators=[InputRequired()], default=5)



@login_manager.user_loader
def load_user(user_id: int) -> User | None:
    try:
        return User(id=user_id, username=session['username'])
    except ValueError as e:
        flash(str(e), 'error')
        print(f"Failed to load user, {e}")
        return None
    except KeyError as e:
        print(f"Failed to load user, {e}")
        return None


def setup_database(c):
    c.execute('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, quantity INTEGER, '
              'barcode VARCHAR(32), expiry_date INT, expire_type VARCHAR(32), image_url VARCHAR(256), '
              'tags LIST)')
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username VARCHAR(32) UNIQUE, '
              'password VARCHAR(128), active BOOLEAN, points INTEGER DEFAULT 0, mascot_points INTEGER DEFAULT 0)')
    c.execute('CREATE TABLE IF NOT EXISTS rooms (id INTEGER PRIMARY KEY, name TEXT NOT NULL, '
              'color VARCHAR(20) DEFAULT "#4A90E2", icon VARCHAR(50) DEFAULT "home")')
    c.execute('CREATE TABLE IF NOT EXISTS chores (id INTEGER PRIMARY KEY, room_id INTEGER NOT NULL, '
              'name TEXT NOT NULL, description TEXT, repeat_days INTEGER, '
              'last_completed DATE, next_due DATE, points INTEGER DEFAULT 5, '
              'FOREIGN KEY (room_id) REFERENCES rooms (id) ON DELETE CASCADE)')
    c.execute('CREATE TABLE IF NOT EXISTS chore_completions (id INTEGER PRIMARY KEY, '
              'chore_id INTEGER NOT NULL, user_id INTEGER NOT NULL, '
              'completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, points_earned INTEGER DEFAULT 10, '
              'FOREIGN KEY (chore_id) REFERENCES chores (id) ON DELETE CASCADE, '
              'FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)')
    
    # Add points column to existing users if it doesn't exist
    try:
        c.execute('SELECT points FROM users LIMIT 1')
    except:
        c.execute('ALTER TABLE users ADD COLUMN points INTEGER DEFAULT 0')
    
    # Add mascot_points column to existing users if it doesn't exist
    try:
        c.execute('SELECT mascot_points FROM users LIMIT 1')
    except:
        c.execute('ALTER TABLE users ADD COLUMN mascot_points INTEGER DEFAULT 0')
    
    # Add points column to existing chores if it doesn't exist
    try:
        c.execute('SELECT points FROM chores LIMIT 1')
    except:
        c.execute('ALTER TABLE chores ADD COLUMN points INTEGER DEFAULT 5')
    
    # Add color and icon columns to existing rooms if they don't exist
    try:
        c.execute('SELECT color FROM rooms LIMIT 1')
    except:
        c.execute('ALTER TABLE rooms ADD COLUMN color VARCHAR(20) DEFAULT "#4A90E2"')
    
    try:
        c.execute('SELECT icon FROM rooms LIMIT 1')
    except:
        c.execute('ALTER TABLE rooms ADD COLUMN icon VARCHAR(50) DEFAULT "home"')
    
    conn.commit()
    conn.close()


def create_room_from_template(template_name):
    """Create a room from a template with all its chores"""
    if template_name not in ROOM_TEMPLATES:
        return None
    
    template = ROOM_TEMPLATES[template_name]
    
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        # Create room
        c.execute('INSERT INTO rooms (name, color, icon) VALUES (?, ?, ?)',
                 (template_name, template['color'], template['icon']))
        room_id = c.lastrowid
        
        # Create chores
        today = datetime.now().date()
        for chore in template['chores']:
            next_due = today.strftime('%Y-%m-%d')
            c.execute('INSERT INTO chores (room_id, name, description, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?, ?)',
                     (room_id, chore['name'], chore['description'], chore['repeat_days'], next_due, chore['points']))
        
        conn.commit()
        return room_id


def __test_populate_db():
    if os.getenv("FLASK_DEBUG", "False").lower() not in ["true", "1"]:
        return
    import random as r
    from datetime import timedelta
    with sql.connect(os.getenv("DB_PATH")) as conn:
        password = generate_password_hash('test')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, active) VALUES (?, ?, ?)', ('test', password, True))
        conn.commit()

        # First, get the total number of products to determine the number of pages
        count_request = requests.get(
            "https://world.openfoodfacts.org/api/v2/search?countries_tags_en=united-kingdom&page_size=1",
            headers={'User-Agent': f'Pyntry/{VERSION}DEV ({os.getenv("CONTACT_EMAIL")})'})
        try:
            count_data = json.loads(count_request.text)
            total_products = count_data['count']
            page_size = 100  # as used in the original request
            max_pages = (total_products // page_size) + (1 if total_products % page_size > 0 else 0)
            random_page = r.randint(1, max_pages)
        except (json.decoder.JSONDecodeError, KeyError):
            print("Failed to get total product count, defaulting to a random page in the first 100 pages.")
            random_page = r.randint(1, 100)

        search = requests.get(
            f"https://world.openfoodfacts.org/api/v2/search?countries_tags_en=united-kingdom&page_size=100&page={random_page}",
            headers={'User-Agent': f'Pyntry/{VERSION}DEV ({os.getenv("CONTACT_EMAIL")})'})
        try:
            products = json.loads(search.text)['products']
        except json.decoder.JSONDecodeError:
            print("Failed to decode JSON.")
            return
        c = conn.cursor()
        for product in products:
            if 'code' in product:
                barcode = product['code']
                if 'product_name' not in product or 'categories' not in product:
                    continue
                name = product['product_name']
                quantity = r.randint(1, 50)
                # generate a random expiry date between -1 and 1 month from now
                expiry_date = (datetime.now().date() + timedelta(days=r.randint(-30, 30))).strftime('%Y-%m-%d')

                expire_type = r.choice(['Best Before', 'Use By', 'Sell By'])
                image_url = product['image_front_small_url'] if 'image_front_small_url' in product else None
                tags = product['categories']
                c.execute('INSERT INTO items (name, quantity, barcode, expiry_date, expire_type, image_url, tags) '
                          'VALUES (?, ?, ?, ?, ?, ?, ?)',
                          (name, quantity, barcode, expiry_date, expire_type, image_url, tags))
            else:
                print("No barcode found.")
        conn.commit()


def get_product_info_from_api(barcode, format=False):
    endpoint = os.getenv("PRODUCT_API_URL").replace("{BARCODE}", str(barcode))
    print(f"Calling API endpoint: {endpoint}")
    # AppName/Version (ContactEmail)
    response = requests.get(endpoint, headers={'User-Agent': f'Pyntry/{VERSION} ({os.getenv("CONTACT_EMAIL")})'})
    if response.status_code != 200 or json.loads(response.text)['status'] != 1:
        return None
    if not format:
        return json.loads(response.text)['product']
    else:
        d = {}
        if 'categories' in json.loads(response.text)['product']:
            d['tags'] = json.loads(response.text)['product']['categories']
        if 'product_name' in json.loads(response.text)['product']:
            d['name'] = json.loads(response.text)['product']['product_name']
        if 'image_front_small_url' in json.loads(response.text)['product']:
            d['image_front_small'] = json.loads(response.text)['product']['image_front_small_url']
        return d


def process_tags(tags: str):
    try:
        return sorted([tag.replace("en:", "").strip() for tag in tags.split(',')])
    except AttributeError:
        return []


def get_all_tags():
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT tags FROM items')
        tags = c.fetchall()
    all_tags = []
    for tag_tuple in tags:
        if tag_tuple[0] is not None:
            tag_list = tag_tuple[0].replace("en:", "").split(',')
            all_tags.extend([tag.strip() for tag in tag_list])
    all_tags = sorted(set(tag for tag in all_tags if tag != ''))  # remove duplicates and empty strings
    return all_tags


if os.getenv("DB_PATH") is None or os.getenv("DB_PATH") == "":
    raise ValueError("DB_PATH not found in .env file. Have you copied the .env.example file to .env?")

if os.path.exists(os.getenv("DB_PATH")):
    conn = sql.connect(os.getenv("DB_PATH"))
    setup_database(conn.cursor())
else:
    print("Database file not found. Creating one...")
    conn = sql.connect(os.getenv("DB_PATH"))
    setup_database(conn.cursor())
    print("A new user has been created. Please login with the following credentials:")
    MASTER_USERNAME = os.urandom(8).hex()
    MASTER_PASSWORD = os.urandom(16).hex()
    print(f"Username: {MASTER_USERNAME}\nPassword: {MASTER_PASSWORD}")
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, active) VALUES (?, ?, ?)',
                  (MASTER_USERNAME, generate_password_hash(MASTER_PASSWORD), True))
        conn.commit()
    print("This account is a temporary account. Please create a new account and delete this one.")
    time.sleep(5)


def get_items():
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM items')
        items = c.fetchall()
    # Convert to dict, process tags through process_tags before inserting into dict
    items = [{'id': item[0], 'name': item[1], 'quantity': item[2], 'barcode': item[3], 'expiry_date': item[4],
              'expire_type': item[5], 'image_url': item[6], 'tags': process_tags(item[7])} for item in items]
    return items


def get_tag_counts(items):
    all_tags = get_all_tags()
    tag_counts = {tag: 0 for tag in all_tags}
    for item in items:
        for tag in item['tags']:
            for intag in tag.replace("en:", "").split(','):
                try:
                    tag_counts[intag.strip()] += 1
                except KeyError:
                    print("Unable to parse tag: ", intag.strip())
    # Filter out tags with a count of 1 or less
    tag_counts = {tag: count for tag, count in tag_counts.items() if count > 1}
    sorted_tag_counts = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_tag_counts


def get_upcoming_chores(days=7):
    """Get chores due within the next N days"""
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        today = datetime.now().date()
        future_date = today + timedelta(days=days)
        c.execute('''SELECT chores.id, chores.name, chores.description, chores.repeat_days, 
                     chores.last_completed, chores.next_due, rooms.name as room_name, rooms.id as room_id
                     FROM chores 
                     JOIN rooms ON chores.room_id = rooms.id
                     WHERE chores.next_due <= ? OR chores.next_due IS NULL
                     ORDER BY chores.next_due ASC''', (future_date.strftime('%Y-%m-%d'),))
        chores = c.fetchall()
    return [{'id': c[0], 'name': c[1], 'description': c[2], 'repeat_days': c[3], 
             'last_completed': c[4], 'next_due': c[5], 'room_name': c[6], 'room_id': c[7]} 
            for c in chores]


def get_upcoming_and_expired_food(days=7):
    """Get food items expiring soon or already expired"""
    items = get_items()
    today = datetime.now().date()
    future_date = today + timedelta(days=days)
    
    upcoming = []
    expired = []
    
    for item in items:
        expiry = datetime.strptime(item['expiry_date'], '%Y-%m-%d').date()
        if expiry < today:
            expired.append(item)
        elif expiry <= future_date:
            upcoming.append(item)
    
    return sorted(upcoming, key=lambda x: x['expiry_date']), sorted(expired, key=lambda x: x['expiry_date'])


def get_leaderboard(period='month', start_date=None, end_date=None):
    """Get user leaderboard for a specific time period"""
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        
        if period == 'month':
            # Current month
            today = datetime.now()
            start_date = today.replace(day=1).strftime('%Y-%m-%d 00:00:00')
            end_date = (today.replace(day=28) + timedelta(days=4)).replace(day=1).strftime('%Y-%m-%d 00:00:00')
            c.execute('''SELECT users.username, SUM(chore_completions.points_earned) as total_points, 
                         COUNT(chore_completions.id) as completions
                         FROM users 
                         LEFT JOIN chore_completions ON users.id = chore_completions.user_id
                         WHERE chore_completions.completed_at >= ? AND chore_completions.completed_at < ?
                         GROUP BY users.id, users.username
                         ORDER BY total_points DESC''', (start_date, end_date))
        elif period == 'all':
            # All time
            c.execute('''SELECT users.username, users.points as total_points, 
                         COUNT(chore_completions.id) as completions
                         FROM users 
                         LEFT JOIN chore_completions ON users.id = chore_completions.user_id
                         GROUP BY users.id, users.username
                         ORDER BY total_points DESC''')
        elif period == 'custom' and start_date and end_date:
            # Custom range
            c.execute('''SELECT users.username, SUM(chore_completions.points_earned) as total_points, 
                         COUNT(chore_completions.id) as completions
                         FROM users 
                         LEFT JOIN chore_completions ON users.id = chore_completions.user_id
                         WHERE chore_completions.completed_at >= ? AND chore_completions.completed_at <= ?
                         GROUP BY users.id, users.username
                         ORDER BY total_points DESC''', (start_date, end_date))
        else:
            return []
        
        results = c.fetchall()
    
    return [{'username': r[0], 'points': r[1] or 0, 'completions': r[2]} for r in results]


@app.route('/')
def index():
    """Dashboard showing upcoming chores and food items"""
    upcoming_chores = get_upcoming_chores(days=7)
    upcoming_food, expired_food = get_upcoming_and_expired_food(days=7)
    leaderboard = get_leaderboard(period='month')
    
    # Count overdue chores
    today = datetime.now().date()
    overdue_chores = [c for c in upcoming_chores if c['next_due'] and 
                      datetime.strptime(c['next_due'], '%Y-%m-%d').date() < today]
    
    # Get user and mascot points for the race
    user_points = 0
    mascot_points = 0
    if current_user.is_authenticated:
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT points, mascot_points FROM users WHERE id = ?', (current_user.id,))
            result = c.fetchone()
            if result:
                user_points = result[0] or 0
                mascot_points = result[1] or 0
    
    # Calculate progress percentages for visual display
    total_points = user_points + mascot_points
    user_progress = (user_points / total_points * 100) if total_points > 0 else 50
    mascot_progress = (mascot_points / total_points * 100) if total_points > 0 else 50
    
    return render_template('dashboard.html', 
                         upcoming_chores=upcoming_chores,
                         overdue_chores_count=len(overdue_chores),
                         upcoming_food=upcoming_food,
                         expired_food=expired_food,
                         leaderboard=leaderboard,
                         user_points=user_points,
                         mascot_points=mascot_points,
                         user_progress=user_progress,
                         mascot_progress=mascot_progress,
                         today=datetime.now())


@app.route('/items')
@login_required
def items_list():
    """View all items (original index page)"""
    items = get_items()
    c_bb = 0
    c_ub = 0
    c_sb = 0
    c_expired = 0
    today = datetime.now().date()
    for item in items:
        if item['expire_type'] == 'Best Before':
            c_bb += item['quantity']
        elif item['expire_type'] == 'Use By':
            c_ub += item['quantity']
        elif item['expire_type'] == 'Sell By':
            c_sb += item['quantity']
        if datetime.strptime(item['expiry_date'], '%Y-%m-%d').date() < today:
            c_expired += item['quantity']
    sorted_tag_counts = get_tag_counts(items)
    return render_template('items.html', items=items, today=datetime.now(), tags=get_all_tags(),
                           c_bb=c_bb, c_ub=c_ub, c_sb=c_sb, c_expired=c_expired, tag_counts=sorted_tag_counts)


def is_safe_url(target):
    """Check if the URL is safe for redirects"""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS filter
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Check rate limit (skip in testing mode)
    if not app.config.get('TESTING', False):
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not check_rate_limit(ip_address):
            flash('Too many login attempts. Please try again later.', 'error')
            return render_template('login.html', form=LoginForm()), 429

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        persist = form.persist.data

        # Record attempt for rate limiting (skip in testing mode)
        if not app.config.get('TESTING', False):
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            record_attempt(ip_address)

        try:
            login_user(User(username, password), remember=persist)
        except ValueError as e:
            print(e)
            flash(str(e), 'error')
            return redirect(url_for('login'))
        session['username'] = username
        session.permanent = persist
        print(f'{username} logged in successfully.')
        flash('Logged in successfully.', 'success')

        next_page = request.args.get('next')
        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        password_confirm = form.password_confirm.data
        if password != password_confirm:
            flash("Passwords do not match.", 'error')
            return redirect(url_for('register'))
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, active) VALUES (?, ?, ?)',
                      (username, generate_password_hash(password), True))
            if 'MASTER_USERNAME' in globals():
                print("Master account exists. Marking it as inactive.")
                c.execute('UPDATE users SET active = ? WHERE username = ?', (False, MASTER_USERNAME))
                logout_user()
                del globals()['MASTER_USERNAME']
                del globals()['MASTER_PASSWORD']
            conn.commit()
        flash('User created successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = AddItemForm()
    if form.validate_on_submit():
        name = form.name.data
        quantity = form.quantity.data
        barcode = form.barcode.data
        expiry_date = form.expiry_date.data
        expire_type = form.expire_type.data
        if barcode is not None:
            print(f"Getting product info for barcode: {barcode}")
            product_info = get_product_info_from_api(barcode)
            if product_info is not None:
                try:
                    image_url = product_info['image_url']
                except KeyError:
                    image_url = None
                tags = product_info['categories'] if 'categories' in product_info else None
            else:
                image_url = None
                tags = None
        else:
            image_url = None
            tags = None
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO items (name, quantity, barcode, expiry_date, expire_type, image_url, tags) '
                      'VALUES (?, ?, ?, ?, ?, ?, ?)', (name, quantity, barcode, expiry_date,
                                                       expire_type, image_url, tags))
            conn.commit()
        flash('Item added successfully.', 'success')
        return redirect(url_for('items_list'))
    return render_template('add_item.html', form=form)


@app.route('/api/get_item', methods=['GET'])
@login_required
def api_item():
    barcode = request.args.get('barcode')
    if not barcode:
        return json.dumps({'error': 'Barcode parameter is required.'}), 400

    # Validate barcode is numeric
    if not barcode.isdigit():
        return json.dumps({'error': 'Invalid barcode format.'}), 400

    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM items WHERE barcode = ?', (barcode,))
        item = c.fetchone()
    if item is None:
        item = get_product_info_from_api(barcode, True)
        if item is None:
            return json.dumps({'error': 'Item not found.'}), 404
        else:
            return json.dumps(item), 200
    return json.dumps(
        dict(zip(['id', 'name', 'quantity', 'barcode', 'expiry_date', 'expire_type', 'image_url', 'tags'], item))), 200


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    form = AddItemForm()
    if request.method == 'GET':
        # set default values
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM items WHERE id = ?', (id,))
            item = c.fetchone()
        if item is None:
            flash('Item not found.', 'error')
            return redirect(url_for('items_list'))
        form.process(data={
            'name': item[1],
            'quantity': item[2],
            'barcode': item[3],
            # convert YYYY-MM-DD to datetime object, remove time (if any)
            'expiry_date': datetime.strptime(item[4], '%Y-%m-%d').date(),
            'expire_type': item[5]
        })

    if form.is_submitted():
        name = form.name.data
        quantity = form.quantity.data
        barcode = form.barcode.data
        expiry_date = form.expiry_date.data
        expire_type = form.expire_type.data
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('UPDATE items SET name = ?, quantity = ?, barcode = ?, expiry_date = ?, expire_type = ? '
                      'WHERE id = ?', (name, quantity, barcode, expiry_date, expire_type, id))
            conn.commit()
        flash('Item updated successfully.', 'success')
        return redirect(url_for('items_list'))
    return render_template('edit_item.html', form=form, id=id)


@app.route('/delete/<int:id>', methods=['GET'])
@login_required
def qdelete(id):
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM items WHERE id = ?', (id,))
        conn.commit()
    flash('Item deleted successfully.', 'success')
    return redirect(url_for('items_list'))


@app.route('/plus1/<int:id>', methods=['GET'])
@login_required
def qplus1(id):
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('UPDATE items SET quantity = quantity + 1 WHERE id = ?', (id,))
        conn.commit()
    flash('Item quantity increased by 1.', 'success')
    return redirect(url_for('items_list'))


@app.route('/minus1/<int:id>', methods=['GET'])
@login_required
def qminus1(id):
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('UPDATE items SET quantity = quantity - 1 WHERE id = ?', (id,))
        conn.commit()
    flash('Item quantity decreased by 1.', 'success')
    return redirect(url_for('items_list'))

@app.route('/delete_expired', methods=['POST'])
@login_required
def delete_expired():
    today = datetime.now().strftime('%Y-%m-%d')
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM items WHERE DATE(expiry_date) < ?', (today,))
        conn.commit()
    flash('Expired items deleted successfully.', 'success')
    return redirect(url_for('items_list'))


# Chores and Rooms Routes
@app.route('/chores')
@login_required
def chores_list():
    """List all rooms"""
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM rooms ORDER BY name')
        rooms = c.fetchall()
    rooms_data = []
    today = datetime.now().date()
    for room in rooms:
        room_id = room[0]
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM chores WHERE room_id = ?', (room_id,))
            chore_count = c.fetchone()[0]
            
            # Get overdue chores count
            c.execute('SELECT COUNT(*) FROM chores WHERE room_id = ? AND next_due < ?', 
                     (room_id, today.strftime('%Y-%m-%d')))
            overdue_count = c.fetchone()[0]
            
        rooms_data.append({
            'id': room[0], 
            'name': room[1], 
            'color': room[2] if len(room) > 2 else '#4A90E2',
            'icon': room[3] if len(room) > 3 else 'home',
            'chore_count': chore_count,
            'overdue_count': overdue_count
        })
    return render_template('chores.html', rooms=rooms_data)


@app.route('/chores/room/add', methods=['GET', 'POST'])
@login_required
def add_room():
    form = RoomForm()
    if form.validate_on_submit():
        use_template = form.use_template.data
        
        # If using a template, create room from template
        if use_template and use_template in ROOM_TEMPLATES:
            room_id = create_room_from_template(use_template)
            if room_id:
                flash(f'Room "{use_template}" created from template with all chores!', 'success')
                return redirect(url_for('room_detail', room_id=room_id))
        else:
            # Custom room
            name = form.name.data
            color = form.color.data or '#4A90E2'
            icon = form.icon.data or 'home'
            
            with sql.connect(os.getenv("DB_PATH")) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO rooms (name, color, icon) VALUES (?, ?, ?)', (name, color, icon))
                conn.commit()
            flash('Room created successfully.', 'success')
            return redirect(url_for('chores_list'))
    return render_template('add_room.html', form=form, templates=ROOM_TEMPLATES)


@app.route('/chores/room/<int:room_id>')
@login_required
def room_detail(room_id):
    """View chores in a specific room"""
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM rooms WHERE id = ?', (room_id,))
        room = c.fetchone()
        if room is None:
            flash('Room not found.', 'error')
            return redirect(url_for('chores_list'))
        
        c.execute('SELECT * FROM chores WHERE room_id = ? ORDER BY next_due ASC', (room_id,))
        chores = c.fetchall()
    
    room_data = {'id': room[0], 'name': room[1]}
    chores_data = []
    today = datetime.now().date()
    
    for chore in chores:
        chore_dict = {
            'id': chore[0],
            'name': chore[2],
            'description': chore[3],
            'repeat_days': chore[4],
            'last_completed': chore[5],
            'next_due': chore[6],
            'points': chore[7] if len(chore) > 7 else 5,
            'is_overdue': False
        }
        if chore[6]:
            due_date = datetime.strptime(chore[6], '%Y-%m-%d').date()
            chore_dict['is_overdue'] = due_date < today
        chores_data.append(chore_dict)
    
    return render_template('room_detail.html', room=room_data, chores=chores_data, today=datetime.now())


@app.route('/chores/room/<int:room_id>/add', methods=['GET', 'POST'])
@login_required
def add_chore(room_id):
    # Verify room exists
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM rooms WHERE id = ?', (room_id,))
        room = c.fetchone()
        if room is None:
            flash('Room not found.', 'error')
            return redirect(url_for('chores_list'))
    
    form = ChoreForm()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        repeat_days = form.repeat_days.data
        points = form.points.data
        next_due = datetime.now().date().strftime('%Y-%m-%d')
        
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, description, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?, ?)',
                     (room_id, name, description, repeat_days, next_due, points))
            conn.commit()
        flash('Chore created successfully.', 'success')
        return redirect(url_for('room_detail', room_id=room_id))
    
    return render_template('add_chore.html', form=form, room={'id': room[0], 'name': room[1]})


@app.route('/chores/complete/<int:chore_id>', methods=['POST'])
@login_required
def complete_chore(chore_id):
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT room_id, repeat_days, next_due, points FROM chores WHERE id = ?', (chore_id,))
        chore = c.fetchone()
        if chore is None:
            flash('Chore not found.', 'error')
            return redirect(url_for('chores_list'))
        
        room_id = chore[0]
        repeat_days = chore[1]
        next_due_str = chore[2]
        max_points = chore[3] if chore[3] else 5
        
        today = datetime.now().date()
        
        # Calculate points based on completion timing
        if next_due_str:
            due_date = datetime.strptime(next_due_str, '%Y-%m-%d').date()
            days_early = (due_date - today).days
            
            if days_early == 0:
                # Completed on due date - full points
                points_earned = max_points
            elif days_early < 0:
                # Completed after due date - still full points (better late than never)
                points_earned = max_points
            else:
                # Completed early - reduce points
                # Calculate percentage: more days early = lower percentage
                # 1 day early = 75%, 2 days = 50%, 3+ days = 25%
                if days_early == 1:
                    percentage = 0.75
                elif days_early == 2:
                    percentage = 0.5
                else:
                    percentage = 0.25
                
                points_earned = max_points * percentage
                # Round to nearest 0.25
                points_earned = round(points_earned * 4) / 4
        else:
            # No due date set, give full points
            points_earned = max_points
        
        new_next_due = (today + timedelta(days=repeat_days)).strftime('%Y-%m-%d')
        
        # Update chore
        c.execute('UPDATE chores SET last_completed = ?, next_due = ? WHERE id = ?',
                 (today.strftime('%Y-%m-%d'), new_next_due, chore_id))
        
        # Award points to user
        c.execute('UPDATE users SET points = points + ? WHERE id = ?', 
                 (points_earned, current_user.id))
        
        # Award points to mascot (between 50-100% of user points for competitive racing)
        import random
        mascot_points = max_points * random.uniform(0.5, 1.0)
        mascot_points = round(mascot_points * 4) / 4
        c.execute('UPDATE users SET mascot_points = mascot_points + ? WHERE id = ?', 
                 (mascot_points, current_user.id))
        
        # Record completion
        c.execute('INSERT INTO chore_completions (chore_id, user_id, points_earned) VALUES (?, ?, ?)',
                 (chore_id, current_user.id, points_earned))
        
        conn.commit()
    
    flash(f'Chore marked as complete! You earned {points_earned} points!', 'success')
    return redirect(url_for('room_detail', room_id=room_id))


@app.route('/chores/delete/<int:chore_id>', methods=['GET'])
@login_required
def delete_chore(chore_id):
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT room_id FROM chores WHERE id = ?', (chore_id,))
        chore = c.fetchone()
        if chore is None:
            flash('Chore not found.', 'error')
            return redirect(url_for('chores_list'))
        room_id = chore[0]
        c.execute('DELETE FROM chores WHERE id = ?', (chore_id,))
        conn.commit()
    flash('Chore deleted successfully.', 'success')
    return redirect(url_for('room_detail', room_id=room_id))


@app.route('/chores/room/delete/<int:room_id>', methods=['GET'])
@login_required
def delete_room(room_id):
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM chores WHERE room_id = ?', (room_id,))
        c.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
    flash('Room and all associated chores deleted successfully.', 'success')
    return redirect(url_for('chores_list'))


@app.route('/leaderboard')
def leaderboard():
    """View leaderboard with different time periods"""
    period = request.args.get('period', 'month')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if period == 'custom' and start_date and end_date:
        leaders = get_leaderboard(period='custom', start_date=start_date, end_date=end_date)
    elif period == 'all':
        leaders = get_leaderboard(period='all')
    else:
        leaders = get_leaderboard(period='month')
    
    return render_template('leaderboard.html', leaderboard=leaders, period=period,
                         start_date=start_date, end_date=end_date)


# Error handlers
@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error_code=400, error_message='Bad Request'), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error_code=403, error_message='Forbidden'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_code=404, error_message='Page Not Found'), 404


@app.errorhandler(429)
def too_many_requests(e):
    return render_template('error.html', error_code=429, error_message='Too Many Requests'), 429


@app.errorhandler(500)
def internal_server_error(e):
    # Log the error but don't expose details to user
    print(f"Internal server error: {e}")
    return render_template('error.html', error_code=500, error_message='Internal Server Error'), 500


with sql.connect(os.getenv("DB_PATH")) as conn:
    c = conn.cursor()
    c.execute('SELECT id FROM users')
    users = c.fetchall()
    c.execute('SELECT id FROM items')
    items = c.fetchall()
    if len(items) == 0 and os.getenv("FLASK_DEBUG", "False").lower() in ["true", "1"]:
        print("TESTING: POPULATING DB")
        __test_populate_db()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "False").lower() in ["true", "1"],
            host='0.0.0.0' if os.getenv("FLASK_DEBUG", "False").lower() in ["true", "1"] else None)
