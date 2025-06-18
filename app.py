import os
import uuid
import sqlite3
import hashlib
from flask import Flask, request, render_template, redirect, url_for, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha256'

SECURE_FOLDER = 'secure_folder'
os.makedirs(SECURE_FOLDER, exist_ok=True)

# first instance 
DATABASE = 'files.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def landing():
    return render_template('home/index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
         username = request.form['username']
         password = request.form['password']
         conn = get_db_connection()
         user = conn.execute("SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
         conn.close()
         if user and check_password_hash(user['password'], password):
             session['user_id'] = user['id']
             session['username'] = username
             return redirect(url_for('dashboard'))
         else:
             return render_template('login.html', error="Invalid username or password.")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
         username = request.form['username']
         password = request.form['password']
         hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
         conn = get_db_connection()
         try:
             conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
             conn.commit()
         except sqlite3.IntegrityError:
             conn.close()
             return render_template('register.html', error="Username already exists. Please choose another.")
         conn.close()
         return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('landing'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part provided.', 400
        
        file = request.files['file']
        if file.filename == '':
            return 'No file selected.', 400

        file_data = file.read()
        file_id = str(uuid.uuid4())
        md5_hash = hashlib.md5(file_data).hexdigest()

        encryption_key = Fernet.generate_key()
        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(file_data)
        encrypted_data = fernet.encrypt(encrypted_data)

        encrypted_filename = f"{file_id}.enc"
        encrypted_path = os.path.join(SECURE_FOLDER, encrypted_filename)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO files (id, user_id, original_filename, encrypted_filename, encryption_key, md5_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, session['user_id'], file.filename, encrypted_filename, encryption_key.decode(), md5_hash)
        )
        conn.commit()
        conn.close()

        return redirect(url_for('upload'))

    conn = get_db_connection()
    files = conn.execute("SELECT id, original_filename, md5_hash FROM files WHERE user_id = ?", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('upload.html', username=session.get('username'), files=files)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    total_files = conn.execute("SELECT COUNT(*) as cnt FROM files WHERE user_id = ?", (session['user_id'],)).fetchone()['cnt']
    storage_used = 150  # in MB
    trend_labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May']
    trend_data = [2, 4, 1, 3, 5]
    file_types_labels = ['PDF', 'Image', 'Video', 'Others']
    file_types_data = [5, 8, 2, 3]
    conn.close()
    return render_template('dashboard.html',
                           username=session.get('username'),
                           total_files=total_files,
                           storage_used=storage_used,
                           trend_labels=trend_labels,
                           trend_data=trend_data,
                           file_types_labels=file_types_labels,
                           file_types_data=file_types_data)



@app.route('/retrieve/<file_id>', methods=['GET'])
def retrieve_file(file_id):
    if 'user_id' not in session:
         return redirect(url_for('login'))
    conn = get_db_connection()
    result = conn.execute("SELECT original_filename, encrypted_filename, encryption_key FROM files WHERE id = ? AND user_id = ?",
                          (file_id, session['user_id'])).fetchone()
    conn.close()

    if not result:
         return 'File not found or access denied.', 404

    encrypted_path = os.path.join(SECURE_FOLDER, result['encrypted_filename'])
    if not os.path.exists(encrypted_path):
         return 'Encrypted file not found on server.', 404

    with open(encrypted_path, 'rb') as f:
         encrypted_data = f.read()

    fernet = Fernet(result['encryption_key'].encode())
    try:
         decrypted_once = fernet.decrypt(encrypted_data)
         decrypted_data = fernet.decrypt(decrypted_once)
    except Exception:
         return 'Decryption failed.', 500

    response = Response(decrypted_data, mimetype='application/octet-stream')
    response.headers.set("Content-Disposition", "attachment", filename=result['original_filename'])
    return response

@app.route('/delete/<file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
         return redirect(url_for('login'))
    conn = get_db_connection()
    file_row = conn.execute("SELECT encrypted_filename FROM files WHERE id = ? AND user_id = ?",
                            (file_id, session['user_id'])).fetchone()
    if file_row:
         encrypted_path = os.path.join(SECURE_FOLDER, file_row['encrypted_filename'])
         if os.path.exists(encrypted_path):
              os.remove(encrypted_path)
         conn.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, session['user_id']))
         conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
