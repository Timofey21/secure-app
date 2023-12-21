import os
import sqlite3
from dotenv import load_dotenv
from pydoc import html
from flask_wtf.csrf import CSRFProtect

from flask import Flask, render_template, render_template_string, request, redirect, session, abort
from flask_bcrypt import Bcrypt
from database import init_db

app = Flask(__name__)

bcrypt = Bcrypt(app)

load_dotenv()
app.secret_key = os.getenv("SECRET")    # secret securely stored in .env file (it's not stored in the git repository)

csrf = CSRFProtect()
csrf.WTF_CSRF_SECRET_KEY = os.getenv("CSRF")    # secret for CSRF token

csrf.init_app(app)  # init CSRF token protection


@app.before_request
def require_login():
    allowed_routes = ["login", "register"]
    if request.endpoint not in allowed_routes and 'user' not in session:
        return redirect('/login')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        username = html.escape(username)    # input validation
        password = html.escape(password)

        connection = sqlite3.connect('demo.db')
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))   # parameterized queries
        user = cursor.fetchone()
        connection.close()
        if user:
            hash_pass = user[-1]
            check = bcrypt.check_password_hash(hash_pass, password)

            if check:
                if user[-2] == 'admin':
                    session['user'] = user[-2]
                    session['id'] = user[-3]
                    return redirect('/admin')
                else:
                    session['user'] = user[-2]
                    session['id'] = user[-3]
                    return redirect('/feed')

            else:
                message = "Login failed!"
                return render_template_string(open('templates/login.html').read(), message=message)
    return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':

        connection = sqlite3.connect('demo.db')
        cursor = connection.cursor()

        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        username = html.escape(username)    # input validation
        password1 = html.escape(password1)
        password2 = html.escape(password2)

        if username:
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))   # parameterized queries
            user = cursor.fetchone()
            if user:
                message = "User is already exist"
                return render_template_string(open('templates/register.html').read(), message=message)
            else:
                if username and password1 == password2 and (password1 and password2):
                    hash_pass = bcrypt.generate_password_hash(password1)

                    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hash_pass))   # parameterized queries
                    connection.commit()
                    connection.close()
                else:
                    message = "No password, passwords don't match"
                    return render_template_string(open('templates/register.html').read(), message=message)

                return redirect('/login')

    return render_template("register.html")


@app.route('/', methods=['POST', 'GET'])
def main_page():

    connection = sqlite3.connect('demo.db')
    cursor = connection.cursor()

    if request.method == 'POST':
        logout_button = request.form.get('logout-button')

        if logout_button:
            session.pop('user', default=None)
            return redirect('/login')

    cursor.execute("SELECT blogs.id, message, username FROM blogs INNER JOIN users ON blogs.user_id = users.id")
    connection.commit()
    blogs = cursor.fetchall()
    connection.close()
    return render_template("index.html", blogs=blogs)


@app.route('/admin', methods=['POST', 'GET'])
def admin():
    if session['user'] != 'admin':
        abort(403)

    if request.method == 'POST':
        logout_button = request.form.get('logout-button')
        if logout_button:
            session.pop('user', default=None)
            return redirect('/login')

    return render_template("admin.html")


@app.route('/feed')
def feed():
    connection = sqlite3.connect('demo.db')
    cursor = connection.cursor()

    cursor.execute("SELECT blogs.id, message, username FROM blogs INNER JOIN users ON blogs.user_id = users.id")
    connection.commit()
    blogs = cursor.fetchall()
    connection.close()
    return render_template("feed.html", blogs=blogs)


@app.route('/profile', methods=['POST', 'GET'])
def profile():
    connection = sqlite3.connect('demo.db')
    cursor = connection.cursor()

    if request.method == 'POST':

        message = request.form.get('message')
        if message:
            message = html.escape(message)  # input validation
            data_tuple = (message, session['id'])
            cursor.execute('INSERT INTO blogs (message, user_id) VALUES (?, ?)', (data_tuple))   # parameterized queries
            connection.commit()

        delete_id = request.form.get('delete-btn')

        if delete_id:
            cursor.execute('DELETE FROM blogs WHERE id = ? and user_id = ?', (delete_id, session['id']))   # parameterized queries and check that post is yours
            connection.commit()

        logout_button = request.form.get('logout-button')

        if logout_button:
            session.pop('user', default=None)
            return redirect('/login')

    cursor.execute('SELECT blogs.id, message, username FROM blogs INNER JOIN users ON blogs.user_id = users.id WHERE users.id = ?', (session['id'],))   # parameterized queries
    connection.commit()
    blogs = cursor.fetchall()
    connection.close()
    return render_template("profile.html", blogs=blogs)


@app.route('/change-password', methods=['POST', 'GET'])
def change_password():
    if request.method == 'POST':

        connection = sqlite3.connect('demo.db')
        cursor = connection.cursor()

        password_old = request.form.get('password-old')

        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if password_old:
            cursor.execute('SELECT * FROM users WHERE id = ?', (session['id'],))  # parameterized queries
            connection.commit()
            user = cursor.fetchone()

            if user:
                hash_pass = user[-1]
                check = bcrypt.check_password_hash(hash_pass, password_old)
                if not check:
                    message = "Wrong old password"
                    return render_template_string(open('templates/change-password.html').read(), message=message)
        else:
            message = "Empty password"
            return render_template_string(open('templates/change-password.html').read(), message=message)

        if password1 == password2 and (password1 and password2):
            hash_pass = bcrypt.generate_password_hash(password1)
            cursor.execute('UPDATE users SET password=? WHERE id=?', (hash_pass, session['id']))   # parameterized queries
            connection.commit()
            connection.close()
        else:
            message = "Passwords don't match or empty"
            return render_template_string(open('templates/change-password.html').read(), message=message)

    return render_template("change-password.html")


@app.route('/manage-users', methods=['POST', 'GET'])
def manage_users():
    if session['user'] != 'admin':
        abort(403)

    connection = sqlite3.connect('demo.db')
    cursor = connection.cursor()

    delete_id = request.form.get('delete-btn')

    if delete_id:
        cursor.execute('DELETE FROM users WHERE id = ?', (delete_id,))   # parameterized queries
        connection.commit()

    cursor.execute("SELECT id, username FROM users")
    connection.commit()
    users = cursor.fetchall()
    connection.close()
    return render_template("manage-users.html", blogs=users)


@app.route('/change-password-admin', methods=['POST', 'GET'])
def manage_users_admin():
    if session['user'] != 'admin':
        abort(403)

    if request.method == 'POST':

        connection = sqlite3.connect('demo.db')
        cursor = connection.cursor()

        username = request.form.get('username')

        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if username:
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))   # parameterized queries
            if not cursor.fetchone():
                message = "User doesn't exist"
                return render_template_string(open('templates/admin-change-password.html').read(), message=message)
            if password1 == password2 and (password1 and password2):
                hash_pass = bcrypt.generate_password_hash(password1)
                cursor.execute('UPDATE users SET password=? WHERE username=?', (hash_pass, username))   # parameterized queries
                connection.commit()
                connection.close()
            else:
                message = "Passwords don't match or empty"
                return render_template_string(open('templates/change-password.html').read(), message=message)

    return render_template("admin-change-password.html")


@app.route('/manage-posts', methods=['POST', 'GET'])
def manage_posts():
    if session['user'] != 'admin':
        abort(403)

    connection = sqlite3.connect('demo.db')
    cursor = connection.cursor()

    if request.method == 'POST':

        delete_id = request.form.get('delete-btn')

        if delete_id:
            cursor.execute('DELETE FROM blogs WHERE id = ?', (delete_id,))   # parameterized queries
            connection.commit()

    cursor.execute("SELECT blogs.id, message, username FROM blogs INNER JOIN users ON blogs.user_id = users.id")   # parameterized queries
    connection.commit()
    blogs = cursor.fetchall()
    connection.close()
    return render_template("manage-posts.html", blogs=blogs)


if __name__ == '__main__':
    init_db()
    app.run()
