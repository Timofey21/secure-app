import sqlite3


def init_db():
    try:
        with sqlite3.connect('demo.db') as db:
            db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS blogs (id INTEGER PRIMARY KEY, message TEXT, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))')
    except sqlite3.OperationalError as e:
        print(f"{e}")
