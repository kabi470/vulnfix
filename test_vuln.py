import os
import sqlite3

def a(uid):
    cur = sqlite3.connect("x.db").cursor()
    cur.execute("SELECT * FROM users WHERE id=" + uid)

def b(name):
    cur = sqlite3.connect("x.db").cursor()
    q = f"SELECT * FROM users WHERE name='{name}'"
    cur.execute(q)

def c(name):
    cur = sqlite3.connect("x.db").cursor()
    cur.execute("SELECT * FROM users WHERE name=?", (name,))

def d(host):
    os.system("ping " + host)
