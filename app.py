#Добавляем модули
import flask
from flask import Flask, request, jsonify, make_response
import sqlite3 as lite
from base64 import urlsafe_b64encode
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
# from hashlib import sha1
from base64 import urlsafe_b64encode
from flask_sqlalchemy import SQLAlchemy as alchemy
import bcrypt

app = Flask(__name__)

app.config['SECRET_KEY'] = '1Sec2r4et' #соль в явном виде надо спрятать
# a = bcrypt.hashpw("password".encode(),bcrypt.gensalt()) #передача пароля от пользователя
# b = bcrypt.checkpw("password".encode(), a)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////project_shorter_link/shortlink/linkbase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = alchemy(app)


#Создаем БД
conn = lite.connect("linkbase.db", check_same_thread=False)
cursor = conn.cursor()

#Таблица позователей
cursor.execute("""CREATE TABLE IF NOT EXISTS users (
	id	INTEGER NOT NULL PRIMARY KEY,
	user_name TEXT UNIQUE,
	password TEXT,
	public_id INTERGER,
	admin BLOB,
	tg_id INTEGER)""")

#Класс позователей
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    public_id = db.Column(db.Integer)
    admin = db.Column(db.Boolean)
    tg_id = db.Column(db.Integer)

#Таблица связей ссылок и пользователей
cursor.execute("""CREATE TABLE IF NOT EXISTS user_links (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	links_id INTEGER,
	FOREIGN KEY (links_id) REFERENCES links(id)
	FOREIGN KEY (user_id) REFERENCES users(id)
	)""")

#Таблица ссылок (Длинные, короткие, типы ссылок, счетчик переходов)
cursor.execute("""CREATE TABLE IF NOT EXISTS links (
	id	INTEGER PRIMARY KEY,
	user_id INTEGER,
	longlink TEXT NOT NULL,
	shortlink TEXT UNIQUE,
	counter INTEGER,
	user_name TEXT,
	link_type TEXT,
	FOREIGN KEY (user_id) REFERENCES users(id)
	)""")

#Класс ссылок
class Links(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    longlink = db.Column(db.String(200), nullable=False)
    shortlink = db.Column(db.String(20), unique=True)
    counter = db.Column(db.Integer)
    user_name = db.Column(db.String(50))
    link_type = db.Column(db.String(50))

conn.commit()

#Объявление функций:

#Проверка авторизации
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
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)

    return decorator


#Объявление маршрутов:

#Нерабочий
@app.route('/shortlink/<link>', methods=['GET', 'PUT', 'DELETE'])
def short_link():
    link = 0 #из БД
    return jsonify(link)

#Регистрация пользователя пробная (пароль не хешированнный) (SQL заросы, удалить маршрут после отладки кода)
@app.route('/registration/<user_name>,<password>', methods=['GET', 'POST', 'PUT'])
def registration(user_name = 'guest', password = 'guest'):
    # регистрация
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()
    check_user = ("""SELECT user_name from users
                        WHERE user_name = (?)""", (user_name,))
    if check_user != None:
        cursor.execute("""INSERT INTO users (user_name, password)
                        VALUES ((?), (?))""", (user_name, password))
        conn.commit()
        return jsonify(f'Вы зарегистрированы')
    conn.commit()


#Маршрут (переход по короткой ссылке)
try:
    @app.route('/<shortlink>', methods=['GET', 'PUT', 'DELETE', 'UPDATE'])
    def link_shorter(shortlink):
        # data = request.get_json()
        conn = lite.connect("linkbase.db", check_same_thread=False)
        cursor = conn.cursor()

        get_long_link = cursor.execute("""SELECT longlink FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
        get_long_link = get_long_link[0]
        get_link_type = cursor.execute("""SELECT link_type FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
        get_link_type = get_link_type[0]

        if get_link_type == "shared":
            cursor.execute("""UPDATE links SET counter = counter + 1 WHERE shortlink = (?)""", shortlink)
            return flask.redirect(get_long_link)

        elif get_link_type == "public":
            pass #auth

        elif get_link_type == "private":
            pass #auth+

        return flask.redirect(get_long_link)

except TypeError:
    print("Oops!")

#Маршрут создания ссылок (Доработать проверку одинаковых ссылок)
@app.route('/makelink', methods=['GET', 'POST'])
@token_required
def makelink(public_id):
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()
    data = request.get_json()
    name = data['user_name']
    #password = data['password']
    token_json = data['token']
    longlink = data['link']
    linktype = data['linktype']
    shortlink = str(urlsafe_b64encode(hashlib.sha1(str(data['link']).encode()).digest()).decode()[0:12])
    counter = 0
    #check_user = cursor.execute("""SELECT user_name FROM users WHERE user_name = (?)""", (name,)).fetchall()
    #check_password = cursor.execute("""SELECT password FROM users WHERE user_name = (?)""", (name,)).fetchall()
    #if check_user[0][0] == name and check_password[0][0] == password:
    user_id = cursor.execute("""SELECT id FROM users WHERE user_name = (?)""", (name,)).fetchall()
    user_id = user_id[0][0]

    cursor.execute("""INSERT INTO links (user_id, longlink, counter, shortlink, user_name, link_type) VALUES( (?), (?), (?), (?), (?), (?) )""", (user_id, longlink, counter, shortlink, name, linktype))
    conn.commit()

    return jsonify(data)



#Информация о сервисе



# #Help
# @app.route('/help')
# def help():
#     return render_tamplate('help.html')


#Маршурт для регистрации пользователя (JWT + Alchemy)
@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(public_id=str(uuid.uuid4()), user_name=data['user_name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'registered successfully'})


#Маршрут авторизации пользователя
@app.route('/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(user_name=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

#Маршрут для вывода списка пользователей которые есть в базе
@app.route('/user', methods=['GET'])
def get_all_users():
    users = Users.query.all()

    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['user_name'] = user.user_name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        result.append(user_data)

    return jsonify({'users': result})


#Маршрут для получения ссылок которые есть в базе
@app.route('/links', methods=['GET', 'POST'])
@token_required
def get_links(current_user, public_id):
    links = Links.query.all()

    output = []

    for link in links:
        link_data = {}
        link_data['longlink'] = link.longlink
        link_data['shortlink'] = link.shortlink
        link_data['counter'] = link.counter
        output.append(link_data)

    return jsonify({'list_of_links': output})

# #Маршурт для получения человекочитаемой ссылки
# @app.route('/links', methods=['POST', 'GET'])
# @token_required
# def create_link(current_user):
#     data = request.get_json()
#
#     new_links = Links(longlink=data['longlink'], shortlink=data['shortlink'], user_id=current_user.id)
#     db.session.add(new_links)
#     db.session.commit()
#
#     return jsonify({'message': 'new link created'})


#Маршрут для удаления ссылки
@app.route('/deletelink/<name>', methods=['DELETE'])
@token_required
def delete_link(current_user, name):
    link = Links.query.filter_by(name=name, user_id=current_user.id).first()
    if not link:
        return jsonify({'message': 'link does not exist'})

    db.session.delete(link)
    db.session.commit()

    return jsonify({'message': 'Link deleted'})


# def check_password(hashed_password, user_password):
#     password, salt = hashed_password.split(':')
#     return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

#print(getHash("http://google.com"))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)