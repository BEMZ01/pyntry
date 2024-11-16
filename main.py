from array import array
from ftplib import all_errors

VERSION = 0.1
import json
import os
import re
import time
from pprint import pprint
from traceback import format_exc
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DecimalField, RadioField, SelectField, TextAreaField, \
    FileField
from wtforms.fields.datetime import DateField
from wtforms.fields.numeric import IntegerRangeField, IntegerField
from wtforms.validators import InputRequired
import aiosqlite as sqlite3
import sqlite3 as sql
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime

load_dotenv()
if os.getenv("APP_SECRET") is None or os.getenv("APP_SECRET") == "":
    print("APP_SECRET not found in .env file. Generating one...")
    with open('.env', 'w+') as f:
        # check if the last character is a newline
        if f.read()[:-1] != '\n':
            f.write('\n')
        f.write(f'APP_SECRET={os.urandom(128).hex()}')
    print("APP_SECRET generated.")
    load_dotenv()

app = Flask(__name__)
login_manager = LoginManager()

app.secret_key = os.getenv("APP_SECRET")
login_manager.init_app(app)
login_manager.login_view = "login"

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
                c.execute('SELECT username, active FROM users WHERE id = ? and username = ?', (id,username))
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


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    persist = BooleanField('remember_me')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    password_confirm = PasswordField('password_confirm', validators=[InputRequired()])


class AddItemForm(FlaskForm):
    name = StringField('Name of product')
    quantity = IntegerField('Quantity', validators=[InputRequired()])
    barcode = IntegerField('Product barcode')
    expiry_date = DateField('Date of expiry')
    expire_type = RadioField('Type of expiry', choices=['Best Before', 'Use By', 'Sell By'])


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
              'password VARCHAR(128), active BOOLEAN)')
    conn.commit()
    conn.close()

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
        pprint(json.loads(response.text)['product'])
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
    all_tags = sorted(list(set(all_tags)))  # Remove duplicates
    return all_tags

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

@app.route('/')
def index():
    items = get_items()
    pprint(items)
    return render_template('index.html', items=items, today=datetime.now(), tags=get_all_tags())


def url_has_allowed_host_and_scheme(next, host):
    print(next, host)
    if next is None:
        return True
    allowed_hosts = os.getenv("ALLOWED_HOSTS").strip().split(',')
    return re.match(r'^https?://[^/]+', next) and next.split('/')[2] in allowed_hosts


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        persist = form.persist.data
        try:
            login_user(User(username, password), remember=persist)
        except ValueError as e:
            print(e)
            flash(str(e), 'error')
            return redirect(url_for('login'))
        session['username'] = username
        print(f'{username} logged in successfully.')
        flash('Logged in successfully.', 'success')
        next = request.args.get('next')
        if not url_has_allowed_host_and_scheme(next, request.host):
            return abort(400)
        return redirect(next or url_for('index'))
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
                image_url = product_info['image_url']
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
        return redirect(url_for('index'))
    return render_template('add_item.html', form=form)

@app.route('/api/get_item', methods=['GET'])
def api_item():
    barcode = request.args.get('barcode')
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM items WHERE barcode = ?', (barcode,))
        item = c.fetchone()
    if item is None:
        item = get_product_info_from_api(barcode, True)
        if item is None:
            return json.dumps({'error': 'Item not found.'})
        else:
            return item
        return item
    return json.dumps(dict(zip(['id', 'name', 'quantity', 'barcode', 'expiry_date', 'expire_type', 'image_url', 'tags'], item)))

@app.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    form = AddItemForm()
    if request.method == 'GET':
        # set default values
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM items WHERE id = ?', (id,))
            item = c.fetchone()
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
        print(name, quantity, barcode, expiry_date, expire_type)
        with sql.connect(os.getenv("DB_PATH")) as conn:
            c = conn.cursor()
            c.execute('UPDATE items SET name = ?, quantity = ?, barcode = ?, expiry_date = ?, expire_type = ? '
                      'WHERE id = ?', (name, quantity, barcode, expiry_date, expire_type, id))
            conn.commit()
        flash('Item updated successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('edit_item.html', form=form, id=id)

@app.route('/delete/<id>', methods=['GET'])
@login_required
def delete(id):
    with sql.connect(os.getenv("DB_PATH")) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM items WHERE id = ?', (id,))
        conn.commit()
    flash('Item deleted successfully.', 'success')
    return redirect(url_for('index'))

app.run(debug=True, host='0.0.0.0', port=5000)
