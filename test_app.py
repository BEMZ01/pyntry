import pytest
import os
import tempfile
from datetime import datetime, timedelta
from main import app, setup_database
from werkzeug.security import generate_password_hash
import sqlite3 as sql


@pytest.fixture
def client():
    """Create a test client with a temporary database"""
    db_fd, db_path = tempfile.mkstemp()
    
    # Set up environment
    os.environ['DB_PATH'] = db_path
    os.environ['APP_SECRET'] = 'test_secret_key_for_testing'
    os.environ['FLASK_DEBUG'] = 'False'
    os.environ['PRODUCT_API_URL'] = 'https://world.openfoodfacts.org/api/v2/product/{BARCODE}'
    os.environ['CONTACT_EMAIL'] = 'test@example.com'
    
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Initialize database manually without calling setup_database
    with sql.connect(db_path) as conn:
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, quantity INTEGER, '
                  'barcode VARCHAR(32), expiry_date INT, expire_type VARCHAR(32), image_url VARCHAR(256), '
                  'tags LIST)')
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username VARCHAR(32) UNIQUE, '
                  'password VARCHAR(128), active BOOLEAN, points INTEGER DEFAULT 0)')
        c.execute('CREATE TABLE IF NOT EXISTS rooms (id INTEGER PRIMARY KEY, name TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS chores (id INTEGER PRIMARY KEY, room_id INTEGER NOT NULL, '
                  'name TEXT NOT NULL, description TEXT, repeat_days INTEGER, '
                  'last_completed DATE, next_due DATE, points INTEGER DEFAULT 5, '
                  'FOREIGN KEY (room_id) REFERENCES rooms (id) ON DELETE CASCADE)')
        c.execute('CREATE TABLE IF NOT EXISTS chore_completions (id INTEGER PRIMARY KEY, '
                  'chore_id INTEGER NOT NULL, user_id INTEGER NOT NULL, '
                  'completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, points_earned INTEGER DEFAULT 10, '
                  'FOREIGN KEY (chore_id) REFERENCES chores (id) ON DELETE CASCADE, '
                  'FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)')
        conn.commit()
    
    with app.test_client() as client:
        yield client
    
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def authenticated_client(client):
    """Create an authenticated test client"""
    # Create test user
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, active, points) VALUES (?, ?, ?, ?)',
                  ('testuser', generate_password_hash('TestPass123'), True, 0))
        conn.commit()
    
    # Login
    client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPass123',
        'persist': True
    }, follow_redirects=True)
    
    return client


class TestAuthentication:
    """Test user authentication and registration"""
    
    def test_login_page_loads(self, client):
        """Test that login page loads successfully"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Login' in response.data
    
    def test_successful_login(self, client):
        """Test successful user login"""
        # Create user
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, active) VALUES (?, ?, ?)',
                      ('testuser', generate_password_hash('TestPass123'), True))
            conn.commit()
        
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'TestPass123',
            'persist': True
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Logged in successfully' in response.data
    
    def test_failed_login_wrong_password(self, client):
        """Test login failure with wrong password"""
        # Create user
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, active) VALUES (?, ?, ?)',
                      ('testuser', generate_password_hash('TestPass123'), True))
            conn.commit()
        
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'WrongPassword',
            'persist': True
        }, follow_redirects=True)
        
        assert b'Password incorrect' in response.data
    
    def test_logout(self, authenticated_client):
        """Test user logout"""
        response = authenticated_client.get('/logout', follow_redirects=True)
        assert response.status_code == 200


class TestRooms:
    """Test room management"""
    
    def test_chores_page_requires_login(self, client):
        """Test that chores page redirects to login when not authenticated"""
        response = client.get('/chores')
        assert response.status_code == 302  # Redirect
    
    def test_view_empty_rooms(self, authenticated_client):
        """Test viewing empty rooms list"""
        response = authenticated_client.get('/chores')
        assert response.status_code == 200
        assert b'No rooms found' in response.data
    
    def test_create_room(self, authenticated_client):
        """Test creating a new room"""
        response = authenticated_client.post('/chores/room/add', data={
            'name': 'Bathroom'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Room created successfully' in response.data
        assert b'Bathroom' in response.data
    
    def test_view_room_detail(self, authenticated_client):
        """Test viewing room details"""
        # Create room
        authenticated_client.post('/chores/room/add', data={
            'name': 'Kitchen'
        }, follow_redirects=True)
        
        response = authenticated_client.get('/chores/room/1')
        assert response.status_code == 200
        assert b'Kitchen' in response.data
    
    def test_delete_room(self, authenticated_client):
        """Test deleting a room"""
        # Create room
        authenticated_client.post('/chores/room/add', data={
            'name': 'Garage'
        }, follow_redirects=True)
        
        response = authenticated_client.get('/chores/room/delete/1', follow_redirects=True)
        assert response.status_code == 200
        assert b'Room and all associated chores deleted successfully' in response.data


class TestChores:
    """Test chore management"""
    
    def test_create_chore(self, authenticated_client):
        """Test creating a new chore"""
        # Create room first
        authenticated_client.post('/chores/room/add', data={
            'name': 'Bathroom'
        }, follow_redirects=True)
        
        response = authenticated_client.post('/chores/room/1/add', data={
            'name': 'Clean Toilet',
            'description': 'Clean and sanitize the toilet',
            'repeat_days': 7,
            'points': 5
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Chore created successfully' in response.data
        assert b'Clean Toilet' in response.data
    
    def test_complete_chore_on_due_date(self, authenticated_client):
        """Test completing a chore on its due date awards full points"""
        # Create room and chore
        authenticated_client.post('/chores/room/add', data={'name': 'Kitchen'})
        
        today = datetime.now().date()
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, description, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?, ?)',
                      (1, 'Wash Dishes', 'Clean all dishes', 7, today.strftime('%Y-%m-%d'), 10))
            conn.commit()
        
        response = authenticated_client.post('/chores/complete/1', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'You earned 10' in response.data  # Full points
        
        # Check user points
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT points FROM users WHERE username = ?', ('testuser',))
            points = c.fetchone()[0]
            assert points == 10
    
    def test_complete_chore_early_reduces_points(self, authenticated_client):
        """Test completing a chore early reduces points"""
        # Create room and chore
        authenticated_client.post('/chores/room/add', data={'name': 'Bedroom'})
        
        # Set due date to 2 days from now
        future_date = datetime.now().date() + timedelta(days=2)
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, description, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?, ?)',
                      (1, 'Vacuum', 'Vacuum the floor', 7, future_date.strftime('%Y-%m-%d'), 10))
            conn.commit()
        
        response = authenticated_client.post('/chores/complete/1', follow_redirects=True)
        
        assert response.status_code == 200
        # Should get 50% = 5 points (2 days early)
        assert b'You earned 5.0' in response.data
        
        # Check user points
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT points FROM users WHERE username = ?', ('testuser',))
            points = c.fetchone()[0]
            assert points == 5.0
    
    def test_complete_chore_updates_next_due(self, authenticated_client):
        """Test that completing a chore updates the next due date"""
        # Create room and chore
        authenticated_client.post('/chores/room/add', data={'name': 'Living Room'})
        
        today = datetime.now().date()
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, description, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?, ?)',
                      (1, 'Dust Shelves', 'Remove dust from shelves', 14, today.strftime('%Y-%m-%d'), 5))
            conn.commit()
        
        authenticated_client.post('/chores/complete/1', follow_redirects=True)
        
        # Check that next_due is updated
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT next_due FROM chores WHERE id = 1')
            next_due = c.fetchone()[0]
            expected_date = (today + timedelta(days=14)).strftime('%Y-%m-%d')
            assert next_due == expected_date
    
    def test_delete_chore(self, authenticated_client):
        """Test deleting a chore"""
        # Create room and chore
        authenticated_client.post('/chores/room/add', data={'name': 'Office'})
        authenticated_client.post('/chores/room/1/add', data={
            'name': 'Organize Desk',
            'description': 'Clean and organize desk',
            'repeat_days': 7,
            'points': 3
        })
        
        response = authenticated_client.get('/chores/delete/1', follow_redirects=True)
        assert response.status_code == 200
        assert b'Chore deleted successfully' in response.data


class TestLeaderboard:
    """Test leaderboard functionality"""
    
    def test_leaderboard_page_loads(self, client):
        """Test that leaderboard page loads"""
        response = client.get('/leaderboard')
        assert response.status_code == 200
        assert b'Leaderboard' in response.data
    
    def test_leaderboard_monthly_filter(self, authenticated_client):
        """Test leaderboard with monthly filter"""
        response = authenticated_client.get('/leaderboard?period=month')
        assert response.status_code == 200
        assert b'This Month' in response.data
    
    def test_leaderboard_all_time_filter(self, authenticated_client):
        """Test leaderboard with all-time filter"""
        response = authenticated_client.get('/leaderboard?period=all')
        assert response.status_code == 200
        assert b'All Time' in response.data
    
    def test_leaderboard_shows_correct_ranking(self, authenticated_client):
        """Test that leaderboard shows users in correct order"""
        # Create additional users with different points
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, active, points) VALUES (?, ?, ?, ?)',
                      ('user2', generate_password_hash('Pass123'), True, 50))
            c.execute('INSERT INTO users (username, password, active, points) VALUES (?, ?, ?, ?)',
                      ('user3', generate_password_hash('Pass123'), True, 100))
            c.execute('UPDATE users SET points = 25 WHERE username = ?', ('testuser',))
            conn.commit()
        
        response = authenticated_client.get('/leaderboard?period=all')
        assert response.status_code == 200
        
        # Check that user3 (100 points) appears before user2 (50 points) before testuser (25 points)
        data = response.data.decode('utf-8')
        pos_user3 = data.find('user3')
        pos_user2 = data.find('user2')
        pos_testuser = data.find('testuser')
        
        assert pos_user3 < pos_user2 < pos_testuser


class TestDashboard:
    """Test dashboard functionality"""
    
    def test_dashboard_loads(self, client):
        """Test that dashboard loads successfully"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Pyntry Dashboard' in response.data
    
    def test_dashboard_shows_upcoming_chores(self, authenticated_client):
        """Test that dashboard shows upcoming chores"""
        # Create room and chore
        authenticated_client.post('/chores/room/add', data={'name': 'Bathroom'})
        
        today = datetime.now().date()
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, description, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?, ?)',
                      (1, 'Clean Mirror', 'Clean bathroom mirror', 7, today.strftime('%Y-%m-%d'), 5))
            conn.commit()
        
        response = authenticated_client.get('/')
        assert response.status_code == 200
        assert b'Clean Mirror' in response.data
        assert b'Bathroom' in response.data
    
    def test_dashboard_shows_leaderboard(self, authenticated_client):
        """Test that dashboard shows leaderboard section"""
        response = authenticated_client.get('/')
        assert response.status_code == 200
        assert b'Leaderboard' in response.data


class TestItems:
    """Test food items functionality"""
    
    def test_items_page_requires_login(self, client):
        """Test that items page requires authentication"""
        response = client.get('/items')
        assert response.status_code == 302  # Redirect to login
    
    def test_add_item_page_loads(self, authenticated_client):
        """Test that add item page loads"""
        response = authenticated_client.get('/add_item')
        assert response.status_code == 200
        assert b'Name of product' in response.data


class TestPointCalculation:
    """Test point calculation logic"""
    
    def test_points_one_day_early(self, authenticated_client):
        """Test points calculation for 1 day early completion (75%)"""
        authenticated_client.post('/chores/room/add', data={'name': 'Test Room'})
        
        future_date = datetime.now().date() + timedelta(days=1)
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?)',
                      (1, 'Test Chore', 7, future_date.strftime('%Y-%m-%d'), 8))
            conn.commit()
        
        authenticated_client.post('/chores/complete/1', follow_redirects=True)
        
        # 8 * 0.75 = 6.0
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT points FROM users WHERE username = ?', ('testuser',))
            points = c.fetchone()[0]
            assert points == 6.0
    
    def test_points_three_days_early(self, authenticated_client):
        """Test points calculation for 3+ days early completion (25%)"""
        authenticated_client.post('/chores/room/add', data={'name': 'Test Room'})
        
        future_date = datetime.now().date() + timedelta(days=5)
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?)',
                      (1, 'Test Chore', 7, future_date.strftime('%Y-%m-%d'), 8))
            conn.commit()
        
        authenticated_client.post('/chores/complete/1', follow_redirects=True)
        
        # 8 * 0.25 = 2.0
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT points FROM users WHERE username = ?', ('testuser',))
            points = c.fetchone()[0]
            assert points == 2.0
    
    def test_points_late_completion(self, authenticated_client):
        """Test that late completion still awards full points"""
        authenticated_client.post('/chores/room/add', data={'name': 'Test Room'})
        
        past_date = datetime.now().date() - timedelta(days=3)
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?)',
                      (1, 'Test Chore', 7, past_date.strftime('%Y-%m-%d'), 10))
            conn.commit()
        
        authenticated_client.post('/chores/complete/1', follow_redirects=True)
        
        # Should still get full 10 points
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT points FROM users WHERE username = ?', ('testuser',))
            points = c.fetchone()[0]
            assert points == 10


class TestChoreCompletions:
    """Test chore completion tracking"""
    
    def test_completion_recorded(self, authenticated_client):
        """Test that chore completion is recorded in database"""
        authenticated_client.post('/chores/room/add', data={'name': 'Test Room'})
        
        today = datetime.now().date()
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO chores (room_id, name, repeat_days, next_due, points) VALUES (?, ?, ?, ?, ?)',
                      (1, 'Test Chore', 7, today.strftime('%Y-%m-%d'), 5))
            conn.commit()
        
        authenticated_client.post('/chores/complete/1', follow_redirects=True)
        
        # Check completion was recorded
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM chore_completions WHERE chore_id = 1')
            count = c.fetchone()[0]
            assert count == 1
            
            # Check points were recorded correctly
            c.execute('SELECT points_earned FROM chore_completions WHERE chore_id = 1')
            points_earned = c.fetchone()[0]
            assert points_earned == 5
