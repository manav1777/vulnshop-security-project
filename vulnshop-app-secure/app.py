from flask import Flask, render_template, request, redirect, url_for, session
from flask_talisman import Talisman
import sqlite3
import os
import bcrypt
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

csp = {
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
}
Talisman(app, content_security_policy=csp, force_https=False)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = 'vulnshop_secure.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            total_price REAL NOT NULL,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')
    
    cursor.execute('SELECT COUNT(*) FROM products')
    if cursor.fetchone()[0] == 0:
        products = [
            ('Laptop Pro', 'High-performance laptop', 1299.99, 'Electronics'),
            ('Wireless Mouse', 'Ergonomic wireless mouse', 29.99, 'Electronics'),
            ('Coffee Maker', 'Automatic coffee maker', 79.99, 'Appliances'),
            ('Desk Lamp', 'LED desk lamp', 34.99, 'Office'),
            ('Water Bottle', 'Insulated water bottle', 24.99, 'Sports'),
        ]
        cursor.executemany(
            'INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)',
            products
        )
    
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
        cursor.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            ('admin', password_hash, 'admin@vulnshop.com')
        )
        
        password_hash_bob = bcrypt.hashpw('password123'.encode('utf-8'), bcrypt.gensalt())
        cursor.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            ('bob', password_hash_bob, 'bob@example.com')
        )
    
    cursor.execute('SELECT COUNT(*) FROM orders')
    if cursor.fetchone()[0] == 0:
        orders = [
            (1, 1, 2, 2599.98),
            (1, 3, 1, 79.99),
            (2, 2, 3, 89.97),
        ]
        cursor.executemany(
            'INSERT INTO orders (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)',
            orders
        )
    
    conn.commit()
    conn.close()

if not os.path.exists(DATABASE):
    init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/products')
def products():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products')
    products = cursor.fetchall()
    conn.close()
    return render_template('products.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    cursor.execute('SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC', (product_id,))
    reviews = cursor.fetchall()
    conn.close()
    
    if product:
        return render_template('product_detail.html', product=product, reviews=reviews)
    else:
        return "Product not found", 404

@app.route('/product/<int:product_id>/review', methods=['POST'])
def add_review(product_id):
    username = request.form.get('username')
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    
    if not username or not rating or not comment:
        return "All fields required", 400
    
    if not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
        return "Invalid rating", 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO reviews (product_id, username, rating, comment) VALUES (?, ?, ?, ?)',
        (product_id, username, int(rating), comment)
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = "Invalid username or password"
            return render_template('login.html', error=error)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            error = "Invalid username or password"
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    return render_template('dashboard.html', username=session['username'], user_id=session.get('user_id'))

@app.route('/orders')
def orders():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    cursor.execute('''
        SELECT orders.id, products.name, orders.quantity, orders.total_price, orders.order_date
        FROM orders
        JOIN products ON orders.product_id = products.id
        WHERE orders.user_id = ?
        ORDER BY orders.order_date DESC
    ''', (user_id,))
    orders = cursor.fetchall()
    conn.close()
    
    return render_template('orders.html', orders=orders, username=user['username'] if user else 'Unknown', user_id=user_id)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', debug=False, port=port)
