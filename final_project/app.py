import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect, abort, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '3b4b32f6c3a3f85cee1692c8e1e69822d83ae9e1cda63a0e'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_todo(id):
    conn = get_db_connection()
    todo = conn.execute('SELECT * FROM todos WHERE id = ? and user_id = ?', (id, session['user_id'])).fetchone()
    conn.close()

    if todo is None:
        abort(404)
        
    return todo

# @app.errorhandler(404)
# def page_not_found(e):
#     # note that we set the 404 status explicitly
#     return render_template('404.html'), 404

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        hash = generate_password_hash(password)

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user is None:
            conn = get_db_connection()
            todo = conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hash))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        else:
            flash('Username has already been registered!', 'danger')
            return redirect('/register')
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    if request.method == "POST":
        session.clear()

        if not request.form.get("username"):
            flash('Must provide username!', 'danger')
            return redirect(url_for('login'))
        elif not request.form.get("password"):
            flash('Must provide password!', 'danger')
            return redirect(url_for('login'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (request.form.get("username"),)).fetchone()
        conn.close()

        if user is None or not check_password_hash(user['password_hash'], request.form.get('password')):
            flash('Invalid username and/or password!', 'danger')
            return redirect(url_for('login'))

        session["user_id"] = user["id"]

        return redirect(url_for('index'))
    else:
        return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    todos = conn.execute('SELECT * FROM todos WHERE user_id=? AND completed=?', (session['user_id'], 'no')).fetchall()
    conn.close()
    return render_template('index.html', todos=todos)

@app.route('/finished')
@login_required
def finished():
    conn = get_db_connection()
    todos = conn.execute('SELECT * FROM todos WHERE user_id=? AND completed=?', (session['user_id'], 'yes')).fetchall()
    conn.close()
    return render_template('finished.html', todos=todos)


@app.route('/add', methods=('GET', 'POST'))
@login_required
def add():
    if request.method == 'POST':
        task = request.form.get('task').strip()

        if not task:
            flash('Must provide a task!', 'danger')
            return redirect(url_for('add'))

        conn = get_db_connection()
        conn.execute('INSERT INTO todos (task, user_id) VALUES (?, ?)', (task, session['user_id']))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    return render_template('add.html')

@app.route('/<int:id>/edit', methods=('GET', 'POST'))
@login_required
def edit(id):
    todo = get_todo(id)

    if request.method == 'POST':
        task = request.form.get('task')
        complete = request.form.get('completed')
        
        completed = 'yes' if complete else 'no'
        conn = get_db_connection()
        conn.execute('UPDATE todos SET task=?, completed=? WHERE id=? AND user_id=?', (task, completed, id, session['user_id']))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    print(dict(todo))
    return render_template('edit.html', todo=todo)

@app.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    todo = get_todo(id)
    
    conn = get_db_connection()
    conn.execute('DELETE FROM todos WHERE id=? AND user_id=?', (id, session['user_id']))
    conn.commit()
    conn.close()
    
    return redirect(url_for('index'))

@app.route('/<int:id>/completed', methods=('POST',))
@login_required
def completed(id):
    todo = get_todo(id)
    
    complete = request.form.get('completed')
    completed = 'yes' if complete else 'no'

    conn = get_db_connection()
    conn.execute('UPDATE todos SET completed=? WHERE id=? AND user_id=?', (completed, id, session['user_id']))
    conn.commit()
    conn.close()
    
    return redirect(url_for('index'))