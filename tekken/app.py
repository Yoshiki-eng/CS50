from flask import Flask, render_template, redirect, request, session, flash

import sqlite3
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, select, create_engine
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tekken.db'
app.config['SECRET_KEY'] = "secretkey"
db = SQLAlchemy(app)
 
login_manager = LoginManager()
login_manager.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), nullable=False, unique=True)
    password = db.Column(db.String(50))
    email = db.Column(db.String(50))

class Move(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    command = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(5), nullable=False)
    frame = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.errorhandler(404)
def error_404(error):
    return render_template('error.html')

@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/login', methods=['POST', 'GET'])
def login():

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        # Userテーブルからusernameに一致するユーザを取得
        user = User.query.filter_by(username=username).first()
        if user == None:
            return render_template('login.html')
        if check_password_hash(user.password, password):
            login_user(user)
            print('logged in')
            print(session)
            return redirect('/')
    else:
        return render_template('login.html')
       
@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        # Userのインスタンスを作成
        user = User(username=username, password=generate_password_hash(password), email=email)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    else:
        return render_template('register.html')
        
@app.route('/search', methods=['POST', 'GET'])
@login_required
def search():
     if request.method == 'GET':
        return render_template('search.html')
      
     else: 
         frame = request.form.get('frame')
         character = request.form.get('character')
         moveType = request.form.get('move-type')
         
         con = sqlite3.connect('sqlite:////var/app-instance/tekken.db')
         cur = con.cursor()
         moves = cur.execute("SELECT * FROM ? WHERE frame = ? AND type = ?", (character, frame, moveType))
         print(moves)

         return redirect('/')
 
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


