import os
import uuid
import sqlite3
import hashlib
from flask import Flask, request, jsonify, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  

SECURE_FOLDER = 'secure_folder'
os.makedirs(SECURE_FOLDER, exist_ok=True)

# SQLite database file
DATABASE = 'files.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No input data provided"}), 400

    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already exists"}), 400
    conn.close()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No input data provided"}), 400

    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = get_db_connection()
    user = conn.execute("SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = username
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/upload', methods=['POST'])
def api_upload_file():
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

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

    return jsonify({"message": "File uploaded successfully", "file_id": file_id}), 201

@app.route('/api/files', methods=['GET'])
def api_files():
    if 'user_id' not in session:
       return jsonify({"error": "Authentication required"}), 401
    conn = get_db_connection()
    files = conn.execute("SELECT id, original_filename, md5_hash FROM files WHERE user_id = ?", (session['user_id'],)).fetchall()
    conn.close()
    files_list = [dict(file) for file in files]
    return jsonify({"files": files_list}), 200

@app.route('/api/file/<file_id>/download', methods=['GET'])
def api_download_file(file_id):
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401
    conn = get_db_connection()
    result = conn.execute("SELECT original_filename, encrypted_filename, encryption_key FROM files WHERE id = ? AND user_id = ?",
                          (file_id, session['user_id'])).fetchone()
    conn.close()

    if not result:
        return jsonify({"error": "File not found or access denied"}), 404

    encrypted_path = os.path.join(SECURE_FOLDER, result['encrypted_filename'])
    if not os.path.exists(encrypted_path):
        return jsonify({"error": "Encrypted file not found on server"}), 404

    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    fernet = Fernet(result['encryption_key'].encode())
    try:
        decrypted_once = fernet.decrypt(encrypted_data)
        decrypted_data = fernet.decrypt(decrypted_once)
    except Exception:
        return jsonify({"error": "Decryption failed"}), 500

    response = Response(decrypted_data, mimetype='application/octet-stream')
    response.headers.set("Content-Disposition", "attachment", filename=result['original_filename'])
    return response

@app.route('/api/file/<file_id>', methods=['DELETE'])
def api_delete_file(file_id):
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401
    conn = get_db_connection()
    file_row = conn.execute("SELECT encrypted_filename FROM files WHERE id = ? AND user_id = ?", (file_id, session['user_id'])).fetchone()
    if file_row:
        encrypted_path = os.path.join(SECURE_FOLDER, file_row['encrypted_filename'])
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        conn.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({"message": "File deleted successfully"}), 200
    else:
        conn.close()
        return jsonify({"error": "File not found or access denied"}), 404

if __name__ == '__main__':
    app.run(debug=True)
