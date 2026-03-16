from flask import Flask, render_template, request, redirect, url_for
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        return f"Login attempted for: {username} (not functional yet)"
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)