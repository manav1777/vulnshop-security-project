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
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABLE CODE - DO NOT USE IN REAL APPLICATIONS!
        # This is intentionally vulnerable to SQL injection
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # DANGEROUS: String concatenation allows SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        print(f"[DEBUG] Executing query: {query}")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['username'] = user[1]
                return redirect('/dashboard')
            else:
                error = "Invalid username or password"
        except sqlite3.Error as e:
            conn.close()
            error = f"Database error: {str(e)}"
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=5000)