from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_12345'

DATABASE = 'vulnshop.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
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
            password TEXT NOT NULL,
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
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            ('admin', 'admin123', 'admin@vulnshop.com')
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
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products')
    products = cursor.fetchall()
    conn.close()
    return render_template('products.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = sqlite3.connect(DATABASE)
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
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute(
        'INSERT INTO reviews (product_id, username, rating, comment) VALUES (?, ?, ?, ?)',
        (product_id, username, rating, comment)
    )
    
    conn.commit()
    conn.close()
    
    print(f"[DEBUG] Review added - Username: {username}, Comment: {comment}")
    
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # VULNERABILITY 1: SQL Injection (from Week 2)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        print(f"[DEBUG] Executing query: {query}")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                # VULNERABILITY 2: Predictable Session - using user ID directly
                session['user_id'] = user[0]
                session['username'] = user[1]
                print(f"[DEBUG] Session created - user_id: {user[0]}, username: {user[1]}")
                return redirect('/dashboard')
            else:
                # VULNERABILITY 3: Account Enumeration - different error messages
                cursor = sqlite3.connect(DATABASE).cursor()
                cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
                if cursor.fetchone():
                    error = "Incorrect password"
                else:
                    error = "Username does not exist"
                cursor.close()
        except sqlite3.Error as e:
            conn.close()
            error = f"Database error: {str(e)}"
    
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
    
    # VULNERABILITY 4: Broken Access Control
    # Get user_id from URL parameter instead of session
    user_id = request.args.get('user_id', session['user_id'])
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get user info
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    # Get orders for this user
    cursor.execute('''
        SELECT orders.id, products.name, orders.quantity, orders.total_price, orders.order_date
        FROM orders
        JOIN products ON orders.product_id = products.id
        WHERE orders.user_id = ?
        ORDER BY orders.order_date DESC
    ''', (user_id,))
    orders = cursor.fetchall()
    
    conn.close()
    
    print(f"[DEBUG] Viewing orders for user_id: {user_id}")
    
    return render_template('orders.html', orders=orders, username=user[0] if user else 'Unknown', user_id=user_id)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=5000)