from flask import Flask, request, render_template, redirect, url_for, make_response, abort, session, current_app
import redis
import hashlib
import os
import bcrypt
import string
import time
import datetime

GET = "GET"
POST = "POST"
SESSION_ID = "session-id"
USERNAME = "username"
USERS = 'users'
NOTE_COUNTER = 'note-counter'
NOTES = 'notes'
UNSUCCESSFUL_LOGINS = 'unsuccessful_logins'

app = Flask(__name__)
db = redis.Redis(host = "redis", port = 6379, decode_responses = True)

password = "test"
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(4)).decode()
#dodanie dwóch użytkowników (test1, test2) o takim samym haśle (test) do bazy
db.hset(USERS, 'test1', password_hash)
db.hset(USERS, 'test2', password_hash)

@app.route('/')
def index():
    session = request.cookies.get(SESSION_ID)
    if session is None:
        return render_template("index.html")
    else:
        return render_template("index.html", session=1)

@app.route('/login', methods = [GET, POST])
def login():
    if(request.method == POST):
        username = request.form["login"]
        password = request.form.get('password')
        if not (checkCredentials(username) and checkCredentials(password)):
            login_counter = db.incr(UNSUCCESSFUL_LOGINS)
            response = make_response(render_template("login.html", error=1, unsuccessful=login_counter))
            return response

        users = db.hkeys(USERS)
        time.sleep(3)
        if username is not None and username in users and bcrypt.checkpw(password.encode(), db.hget(USERS, username).encode()):
            db.set(UNSUCCESSFUL_LOGINS, 0)
            now = datetime.datetime.now()
            db.rpush("log"+username, now.strftime("%Y-%m-%d %H:%M:%S"))
            response = make_response(render_template("index.html", session=1))
            name_hash = bcrypt.hashpw(username.encode(), bcrypt.gensalt()).decode()
            db.set(name_hash, username)
            response.set_cookie(SESSION_ID, name_hash, max_age = 60, secure = True, httponly = True)
            return response
        else:
            login_counter = db.incr(UNSUCCESSFUL_LOGINS)
            response = make_response(render_template("index.html", unsuccessful=login_counter))
            response.set_cookie(SESSION_ID, '', expires=0)
            return response

    return render_template("login.html")


@app.route('/logout', methods = [GET])
def logout(login="login", registered=0, newpass=0, entropy=0):
    response = make_response(render_template("index.html", login=login, registered=registered, newpass=newpass, entropy=entropy))
    session_id = request.cookies.get(SESSION_ID)
    response.set_cookie(SESSION_ID, '', expires=0)
    if session_id is not None:
        db.persist(session_id)
    return response

@app.route("/register", methods = [GET, POST])
def register():
    if(request.method == POST):
        username = request.form["login"]
        password = request.form.get('password')
        if not (checkCredentials(username) and checkCredentials(password)):
            response = make_response(render_template("register.html", error=1))
            return response

        users = db.hkeys(USERS)
        if username in users: #login zajety
            response = make_response(render_template("register.html", taken=1))
            return response
        else:
            password_entropy = entropy(password.encode())
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(4)).decode()
            db.hset(USERS, username, password_hash) #wstawienie do bazy zahashowanego (z solą) hasła
            response = logout(username, 1, 0, password_entropy)
            return response


    return render_template("register.html")

@app.route('/changePassword', methods = [GET, POST])
def changePassword():
    session_id = request.cookies.get(SESSION_ID)
    if(request.method == POST):
        old_password = request.form.get('password')
        new_password = request.form.get('password2')
        confirm_password = request.form.get('password3')

        if new_password != confirm_password:
            response = make_response(render_template("changepass.html", repeat=1))
            return response

        username = db.get(session_id)
        if not (checkCredentials(old_password) and checkCredentials(new_password)):
            response = make_response(render_template("changePassword.html", error=1))
            return response

        if bcrypt.checkpw(old_password.encode(), db.hget(USERS, username).encode()):
            password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(4)).decode()
            db.hset(USERS, username, password_hash)
            response = logout(username, 0, 1)
            return response
        else:
            response = make_response(render_template("changepass.html", oldpass=1, logged=1, login=username))
            response.set_cookie(SESSION_ID, session_id, max_age = 60, secure = True, httponly = True)
            return response

    if session_id is None:
        response = make_response(render_template("changepass.html"))
        return response
    else:
        username = db.get(session_id)
        response = make_response(render_template("changepass.html", logged=1, login=username))
        response.set_cookie(SESSION_ID, session_id, max_age = 60, secure = True, httponly = True)
        return response

@app.route('/notes', methods = [GET, POST])
def notes():
    session_id = request.cookies.get(SESSION_ID)
    if session_id is not None:
        username = db.get(session_id)
    users = db.hkeys(USERS)
    if(request.method == POST):
        note_body = request.form.get('note')
        if not checNoteBody(note_body):
            response = make_response(render_template("index.html", error=1))
            return response
        
        note_counter = str(db.incr(NOTE_COUNTER))
        note_id = 'n' + str(note_counter)
        db.hset(NOTES, note_id, note_body)
        if request.form.get('public'):

            db.rpush('public_notes', note_id)
        else:
            for user in users:
                if request.form.get(user):
                    db.rpush(note_id, user)
            for i in range(0, db.llen(note_id)): #jeśli nie autor nie dał sobie uprawnień, to go dopisz do listy
                if username == db.lindex(note_id, i):
                    break
                else:
                    db.rpush(note_id, username)

    notes = db.hkeys(NOTES)
    privates = []
    publics = []
    for note in notes:
        for i in range(0, db.llen('public_notes')):
            if note == db.lindex('public_notes', i):
                publics.append(note)
                break #jeśli znajdzie notkę na liście publicznej, to kończ pętlę
            if i == (db.llen('public_notes') - 1):
                privates.append(note) #jeśli nie znajdzie, to nie przerwie pętli i notatka wpadnie na listę prywatnych   
    public_notes = []
    for pub in publics:
         public_notes.append(db.hget(NOTES, pub))

    if session_id is None:
        response = make_response(render_template("notes.html", public=public_notes))
        return response
    else:
        private_notes = []

        for priv in privates:
            for i in range(0, db.llen(priv)):
                if username == db.lindex(priv, i):
                    private_notes.append(db.hget(NOTES, priv))
                    break

        response = make_response(render_template("notes.html", session=1, users=users, public=public_notes, private=private_notes))
        response.set_cookie(SESSION_ID, session_id, max_age = 60, secure = True, httponly = True)
        return response

@app.route('/loginlog', methods = [GET])
def loginlog():
    session_id = request.cookies.get(SESSION_ID)
    if session_id is None:
        response = make_response(render_template("loginlog.html"))
        return response
    else:
        username = db.get(session_id)
        logs = []
        for i in range(0, db.llen("log"+username)):
                logs.append(db.lindex("log"+username, i))
        response = make_response(render_template("loginlog.html", session=1, login=username, logs=logs))
        response.set_cookie(SESSION_ID, session_id, max_age = 60, secure = True, httponly = True)
        return response

def checkCredentials(credential):
    if credential.isalnum() and len(credential) >= 4 and len(credential) <= 16:
        return True
    return False

def checNoteBody(body):
    if all(b.isalnum() for b in body.split()) and len(body) >= 2 and len(body) <= 30:
        return True
    return False

def entropy(data: bytes) -> float:
    count = {i: 0 for i in range(256)}
    for b in data: count[b] += 1

    p = lambda b: count[b] / len(data)
    entropy = sum((p(b) * count[b] for b in range(256)))

    return 1 - entropy / len(data)
