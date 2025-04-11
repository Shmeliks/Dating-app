from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'static/avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            avatar TEXT DEFAULT 'default.jpg',
            age INTEGER,
            city TEXT,
            gender TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_from TEXT NOT NULL,
            user_to TEXT NOT NULL,
            UNIQUE(user_from, user_to)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'user' in session:
        user = session['user']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''
            SELECT user_from FROM likes
            WHERE user_to = ? AND user_from NOT IN (
                SELECT user_to FROM likes WHERE user_from = ?
            )
        ''', (user, user))
        new_likes = [row[0] for row in c.fetchall()]
        conn.close()
        session['new_likes'] = new_likes
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            role = 'admin' if username == 'admin' else 'user'
            c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Пользователь уже существует!"
        conn.close()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT password, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if not user or not check_password_hash(user[0], password):
            return "Неверный логин или пароль!"

        session['user'] = username
        session['role'] = user[1]
        return redirect(url_for('explore'))

    return render_template('login.html')

@app.route('/explore')
def explore():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username, avatar, age, city, gender FROM users WHERE username != ?', (username,))
    users_data = c.fetchall()
    conn.close()

    users = []
    for u in users_data:
        users.append({
            'username': u[0],
            'avatar': url_for('static', filename=f'avatars/{u[1]}'),
            'age': u[2],
            'city': u[3],
            'gender': u[4]
        })

    return render_template('explore.html', username=username, users=users)

@app.route('/chats')
def chats():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT DISTINCT CASE 
            WHEN sender = ? THEN receiver
            ELSE sender
        END as chat_partner
        FROM messages
        WHERE sender = ? OR receiver = ?
    ''', (username, username, username))
    chat_partners = [row[0] for row in c.fetchall()]
    conn.close()

    return render_template('chats.html', chat_partners=chat_partners)

@app.route('/chat/<with_user>')
def chat(with_user):
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT DISTINCT CASE 
            WHEN sender = ? THEN receiver
            ELSE sender
        END as chat_partner
        FROM messages
        WHERE sender = ? OR receiver = ?
    ''', (username, username, username))
    chat_partners = [row[0] for row in c.fetchall()]

    c.execute('''
        SELECT sender, receiver, message FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY timestamp
    ''', (username, with_user, with_user, username))
    messages = c.fetchall()
    conn.close()

    return render_template('chat.html', username=username, messages=messages, chat_partners=chat_partners, current_chat=with_user)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user' not in session:
        return redirect(url_for('login'))

    sender = session['user']
    receiver = request.form['receiver']
    message = request.form['message']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)', (sender, receiver, message))
    conn.commit()
    conn.close()

    return redirect(url_for('chat', with_user=receiver))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username, avatar, age, city, gender FROM users WHERE username = ?', (session['user'],))
    user = c.fetchone()
    conn.close()

    return render_template('profile.html', user={
        'username': user[0],
        'avatar': url_for('static', filename=f'avatars/{user[1]}'),
        'age': user[2],
        'city': user[3],
        'gender': user[4]
    })

@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'user' not in session:
        return redirect(url_for('login'))

    if 'avatar' not in request.files:
        return redirect(url_for('profile'))

    file = request.files['avatar']
    if file.filename == '' or not allowed_file(file.filename):
        return redirect(url_for('profile'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE users SET avatar = ? WHERE username = ?', (filename, session['user']))
    conn.commit()
    conn.close()

    return redirect(url_for('profile'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    age = request.form.get('age')
    city = request.form.get('city')
    gender = request.form.get('gender')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE users SET age = ?, city = ?, gender = ? WHERE username = ?', (age, city, gender, session['user']))
    conn.commit()
    conn.close()

    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin_panel():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    user_rows = c.fetchall()
    conn.close()

    users = [row[0] for row in user_rows]
    return render_template('admin.html', users=users)

@app.route('/delete_user/<username>')
def delete_user(username):
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    if username == 'admin':
        return "Нельзя удалить администратора!"

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_panel'))

@app.route('/like/<liked_user>', methods=['GET'])
def like(liked_user):
    if 'user' not in session:
        return redirect(url_for('login'))

    user_from = session['user']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM likes WHERE user_from = ? AND user_to = ?', (user_from, liked_user))
    like_exists = c.fetchone()

    if not like_exists:
        c.execute('INSERT INTO likes (user_from, user_to) VALUES (?, ?)', (user_from, liked_user))
        conn.commit()

    conn.close()

    return redirect(url_for('explore'))

if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
