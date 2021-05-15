from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy as alchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
# from hashlib import sha1
from base64 import urlsafe_b64encode
import hashlib


app = Flask(__name__)

app.config['SECRET_KEY'] = '1Sec2r4et' #соль
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////linkbasev2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = alchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Links(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    longlink = db.Column(db.String(200), nullable=False)
    shortlink = db.Column(db.String(20), unique=True)
    alterlink = db.Column(db.String(50))
    user_id = db.Column(db.Integer)
    counter = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_idpublic_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(name=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/user', methods=['GET'])
def get_all_users():
    users = Users.query.all()

    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        result.append(user_data)

    return jsonify({'users': result})


@app.route('/links', methods=['GET', 'POST'])
@token_required
def get_links(current_user, public_id):
    links = Links.query.all()

    output = []

    for link in links:
        link_data = {}
        link_data['longlink'] = link.longlink
        link_data['shortlink'] = link.shortlink
        link_data['alterlink'] = link.alterlink
        link_data['counter'] = link.counter
        output.append(link_data)

    return jsonify({'list_of_links': output})


@app.route('/links', methods=['POST', 'GET'])
@token_required
def create_link(current_user):
    data = request.get_json()

    new_links = Links(longlink=data['longlink'], alterlink=data['alterlink'],user_id=current_user.id)
    db.session.add(new_links)
    db.session.commit()

    return jsonify({'message': 'new link created'})


@app.route('/links/<name>', methods=['DELETE'])
@token_required
def delete_link(current_user, name):
    link = Links.query.filter_by(name=name, user_id=current_user.id).first()
    if not link:
        return jsonify({'message': 'link does not exist'})

    db.session.delete(link)
    db.session.commit()

    return jsonify({'message': 'Link deleted'})


@app.route('/makelink', methods=['GET', 'POST'])
def getHash():
    data = request.get_json()
    hashed_data = urlsafe_b64encode(hashlib.sha1(str(data['id']).encode()).digest()).decode()[0:12]

    return hashlib.sha1(hashed_data)

# def check_password(hashed_password, user_password):
#     password, salt = hashed_password.split(':')
#     return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

#print(getHash("http://google.com"))


if __name__ == '__main__':
    app.run(debug=True)