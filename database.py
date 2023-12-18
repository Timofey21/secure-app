import sqlite3


def init_db():
    with sqlite3.connect('demo.db') as db:
        db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS blogs (id INTEGER PRIMARY KEY, message TEXT, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))')

        # db.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123')")
        # db.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('bob', 'bobpass')")
        # db.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('alice', 'alicepass')")
