from flask import Flask, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# SQLAlchemy Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
FRONTEND_URL = 'http://frontend_container:8000'
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        response = {'status_code': 401, 'message': "Username already exists"}
    else:
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        response = {'status_code': 200, 'message': "Registration successful"}

    return jsonify(response), response['status_code']


@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        response = {'status_code': 200, 'message': "Login successful", 'user_id': user.id}
    else:
        response = {'status_code': 401, 'message': "Invalid username or password"}

    requests.post(f'{FRONTEND_URL}/login_response', json=response)

    return jsonify(response), response['status_code']


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('frontend_service.home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", debug=True, port=5007)
