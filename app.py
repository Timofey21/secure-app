import sqlite3

from flask import Flask, render_template, render_template_string, request, redirect, session, abort
from database import init_db

app = Flask(__name__)

app.secret_key = 'BAD_SECRET_KEY'


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

        connection = sqlite3.connect('demo.db')
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password))
        user = cursor.fetchone()
        connection.close()

        if user:
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

        cursor.execute("SELECT username FROM users WHERE username = '{}'".format(username))
        if cursor.fetchone():
            message = "User is already exist"
            return render_template_string(open('templates/register.html').read(), message=message)
        else:
            if username and password1 == password2:
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password1))
                connection.commit()

            if username == 'admin':
                return redirect('/admin')

            return redirect('/login')

    return render_template("register.html")


@app.route('/', methods=['POST', 'GET'])
def main_page():

    connection = sqlite3.connect('demo.db')
    cursor = connection.cursor()

    if request.method == 'POST':

        message = request.form.get('message')
        data_tuple = message, session['id']

        if message:
            cursor.execute('INSERT INTO blogs (message, user_id) VALUES (?, ?)', (data_tuple))
            connection.commit()

        delete_id = request.form.get('delete-btn')

        if delete_id:
            cursor.execute("DELETE FROM blogs WHERE id = ('{}')".format(delete_id))
            connection.commit()

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
            data_tuple = (message, session['id'])
            cursor.execute('INSERT INTO blogs (message, user_id) VALUES (?, ?)', (data_tuple))
            connection.commit()

        delete_id = request.form.get('delete-btn')

        if delete_id:
            cursor.execute("DELETE FROM blogs WHERE id = ('{}')".format(delete_id))
            connection.commit()

        logout_button = request.form.get('logout-button')

        if logout_button:
            session.pop('user', default=None)
            return redirect('/login')

    cursor.execute("SELECT blogs.id, message, username FROM blogs INNER JOIN users ON blogs.user_id = users.id WHERE users.id = ('{}')".format(session['id']))
    connection.commit()
    blogs = cursor.fetchall()
    connection.close()
    return render_template("profile.html", blogs=blogs)


@app.route('/change-password', methods=['POST', 'GET'])
def change_password():
    if request.method == 'POST':

        connection = sqlite3.connect('demo.db')
        cursor = connection.cursor()

        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if password1 == password2:
            cursor.execute("UPDATE users SET password=('{}') WHERE id=('{}')".format(password1, session['id']))
            connection.commit()

    return render_template("change-password.html")


@app.route('/manage-users', methods=['POST', 'GET'])
def manage_users():
    if session['user'] != 'admin':
        abort(403)

    connection = sqlite3.connect('demo.db')
    cursor = connection.cursor()

    delete_id = request.form.get('delete-btn')

    if delete_id:
        cursor.execute("DELETE FROM users WHERE id = ('{}')".format(delete_id))
        connection.commit()

    cursor.execute("SELECT id, username FROM users")
    connection.commit()
    users = cursor.fetchall()
    connection.close()
    return render_template("manage-users.html", blogs=users)


@app.route('/change-password-admin', methods=['POST', 'GET'])
def manage_users_admin():
    print(session['user'])
    if session['user'] != 'admin':
        abort(403)

    if request.method == 'POST':

        connection = sqlite3.connect('demo.db')
        cursor = connection.cursor()

        username = request.form.get('username')

        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if password1 == password2:
            cursor.execute("UPDATE users SET password=('{}') WHERE username=('{}')".format(password1, username))
            connection.commit()

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
            cursor.execute("DELETE FROM blogs WHERE id = ('{}')".format(delete_id))
            connection.commit()

    cursor.execute("SELECT blogs.id, message, username FROM blogs INNER JOIN users ON blogs.user_id = users.id")
    connection.commit()
    blogs = cursor.fetchall()
    connection.close()
    return render_template("manage-posts.html", blogs=blogs)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
