from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import os
import subprocess
import yaml
import pickle
import base64
import hashlib
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vulnerable-app')

app = Flask(__name__)
app.secret_key = "super_secret_key_1234"  # Hard-coded secret key vulnerability

# Create database and table if not exists
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    ''')
    
    # Add default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ['admin', 'admin123', 'admin'])
    
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # SQL Injection vulnerability
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        logger.info(f"Executing query: {query}")
        
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            session['role'] = user[3]
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials. Please try again.'
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    
    return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect('/login')
    
    query = request.args.get('q', '')
    results = []
    
    if query:
        # Command injection vulnerability
        try:
            # This is vulnerable to command injection through the 'q' parameter
            cmd = f"grep -i '{query}' data.txt || echo 'No results found'"
            output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
            results = output.strip().split('\n')
        except subprocess.CalledProcessError as e:
            results = [f"Error: {str(e)}"]
    
    return render_template('search.html', query=query, results=results)

@app.route('/config', methods=['POST'])
def update_config():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})
    
    config_data = request.get_data(as_text=True)
    
    try:
        # YAML Deserialization vulnerability
        config = yaml.load(config_data, Loader=yaml.Loader)  # Unsafe loader
        return jsonify({'status': 'success', 'config': config})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/import', methods=['POST'])
def import_data():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})
    
    try:
        # Insecure deserialization vulnerability
        data = request.form.get('data', '')
        deserialized_data = pickle.loads(base64.b64decode(data))
        return jsonify({'status': 'success', 'data': str(deserialized_data)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/user/<username>')
def get_user(username):
    # Broken authentication and sensitive data exposure
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # Returning password in the response - sensitive data exposure
        return jsonify({
            'id': user[0],
            'username': user[1],
            'password': user[2],  # Sensitive data exposure!
            'role': user[3]
        })
    else:
        return jsonify({'status': 'error', 'message': 'User not found'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Weak hashing algorithm - security misconfiguration
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                          [username, password_hash, 'user'])
            conn.commit()
            conn.close()
            return redirect('/login')
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', error='Username already exists')
    
    return render_template('register.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('upload.html', error='No file part')
        
        file = request.files['file']
        
        if file.filename == '':
            return render_template('upload.html', error='No selected file')
        
        # Insecure file upload vulnerability - no validation of file type
        # Also path traversal vulnerability with filename
        filename = file.filename
        file.save(os.path.join('uploads', filename))
        
        return render_template('upload.html', message=f'File {filename} uploaded successfully')
    
    return render_template('upload.html')

@app.route('/logs')
def show_logs():
    if 'username' not in session or session['role'] != 'admin':
        return redirect('/login')
    
    # Path traversal vulnerability
    log_path = request.args.get('file', 'app.log')
    
    try:
        with open(log_path, 'r') as f:
            content = f.read()
        return render_template('logs.html', content=content, log_file=log_path)
    except Exception as e:
        return render_template('logs.html', error=str(e), log_file=log_path)

if __name__ == '__main__':
    # Create uploads directory if it doesn't exist
    os.makedirs('uploads', exist_ok=True)
    
    # Create a sample data.txt file for the search function
    with open('data.txt', 'w') as f:
        f.write("Sample data line 1\nAnother line of data\nSecurity vulnerabilities are dangerous\n")
    
    # Running with debug=True is a security risk in production
    app.run(debug=True, host='0.0.0.0', port=5000)
