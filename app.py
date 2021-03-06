#Добавляем модули
import requests
import flask
from flask import Flask, request, jsonify, make_response, render_template
import datetime
import uuid
import jwt
import sqlite3 as lite
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from base64 import urlsafe_b64encode
from flask_sqlalchemy import SQLAlchemy as alchemy

counter = 10

app = Flask(__name__)

app.config['SECRET_KEY'] = '1Sec2r4et'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////shortlink4/linkbase.db'
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
	admin BLOB)""")

#Класс позователей
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    public_id = db.Column(db.Integer)
    admin = db.Column(db.Boolean)


cursor.execute("""CREATE TABLE IF NOT EXISTS jokes (
	id	INTEGER NOT NULL PRIMARY KEY,
	joke TEXT UNIQUE,
	icon TEXT,
	)""")

class Jokes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    joke = db.Column(db.String(50), unique=True)
    icon = db.Coumn(db.String(50))

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
            return jsonify({'message': 'Валидный токен отсутствует'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
            #cur_user = get_jwt_identity(), 200
        except:
            return jsonify({'message': 'Невалидный токен'})

        return f(current_user, *args, **kwargs)

    return decorator


#Объявление маршрутов:

#Информация о сервисе
# #Help
@app.route('/help')
def help():
    return render_template('help.html')
@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == "POST":
        print(request.form)
    return render_template('index.html')


#Маршурт для регистрации пользователя (JWT + Alchemy)
@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    try:
        new_user = Users(public_id=str(uuid.uuid4()), user_name=data['user_name'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Регистрация прошла успешно!'})
    except:
        return jsonify({'message': 'Пользователь с таким именем уже есть!'})

#Маршрут авторизации пользователя
@app.route('/login', methods=['POST', 'GET'])
def login_user():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Невозможно верифицироваться', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(user_name=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)},
            app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})


    return make_response('Невозможно верифицироваться', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


#Маршрут создания ссылок (Доработать проверку одинаковых ссылок)
@app.route('/makelink', methods=['GET', 'POST'])
@token_required
def makelink(public_id):
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()
    data = request.get_json()
    name = data['user_name']
    longlink = data['link']
    linktype = data['linktype']
    shortlink_word = data['shortlink']
    counter = 0
    user_id = cursor.execute("""SELECT id FROM users WHERE user_name = (?)""", (name,)).fetchall()
    user_id = user_id[0][0]
    if shortlink_word != None:
        shortlink = shortlink_word
        check_shortlink = cursor.execute("""SELECT shortlink FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
        if check_shortlink != None:
            check_shortlink = check_shortlink[0]
        print(check_shortlink)
        if check_shortlink == shortlink:
            return jsonify(f'Такая ссылка уже сущесвует!')


    else:
        shortlink = str(urlsafe_b64encode(hashlib.sha1(str(data['link']).encode()).digest()).decode()[0:12])
        check_shortlink = cursor.execute("""SELECT shortlink FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
        if check_shortlink != None:
            return jsonify(f'Такая ссылка уже сущесвует!')

    cursor.execute("""INSERT INTO links (user_id, longlink, counter, shortlink, user_name, link_type) VALUES( (?), (?), (?), (?), (?), (?) )""", (user_id, longlink, counter, shortlink, name, linktype))
    conn.commit()

    return jsonify(f'Ваша ссылка http://127.0.0.1:8080/{shortlink}')

#Маршрут (переход по короткой ссылке)
@app.route('/<shortlink>', methods=['GET', 'PUT', 'DELETE', 'UPDATE'])
def link_shorter(shortlink):
    # data = request.get_json()
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()

    get_long_link = cursor.execute("""SELECT longlink FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
    get_long_link = get_long_link[0]
    get_link_type = cursor.execute("""SELECT link_type FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
    get_link_type = get_link_type[0]

    if get_link_type == "public":
        cursor.execute("""UPDATE links SET counter = counter + 1 WHERE shortlink = (?)""", (shortlink,))
        conn.commit()
        return flask.redirect(get_long_link)

    else:
        return flask.redirect('/login')

@app.route('/shortlink', methods=['GET', 'POST', 'PUT', 'DELETE', 'UPDATE'])
@token_required
def auth_link_shorter(current_user):
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()

    data = request.get_json()
    shortlink = data['shortlink']

    get_long_link = cursor.execute("""SELECT longlink FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
    get_long_link = get_long_link[0]
    print(get_long_link)
    get_link_type = cursor.execute("""SELECT link_type FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
    get_link_type = get_link_type[0]
    user_id_bd = cursor.execute("""SELECT user_id FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
    user_id_bd = user_id_bd[0]


    if get_link_type == "shared":
        cursor.execute("""UPDATE links SET counter = counter + 1 WHERE shortlink = (?)""", (shortlink,))
        conn.commit()
        return flask.redirect(get_long_link)

    elif get_link_type == "private":
        if current_user.id == user_id_bd:

            cursor.execute("""UPDATE links SET counter = counter + 1 WHERE shortlink = (?)""", (shortlink,))
            conn.commit()
            return flask.redirect(get_long_link)

        else:
            return jsonify(f'У вас нет прав доступа к данной сылке!')



#Маршрут для редактирования ссылок (изменение уровня доступа, удаление)
@app.route('/edit', methods=['GET', 'POST', 'PUT', 'DELETE', 'UPDATE'])
@token_required
def edit_link(current_user):
    data = request.get_json()

    if data == None:
        conn = lite.connect("linkbase.db", check_same_thread=False)
        cursor = conn.cursor()
        user_id = current_user.id
        data_ = cursor.execute("""SELECT id, longlink, shortlink, link_type, counter FROM links WHERE user_id = (?)""",
                               (user_id,)).fetchall()
        return jsonify(data_)

    else:
        shortlink = data['shortlink']
        linktype = data['linktype']
        deletelink = data['deletelink']
        longlink = data['longlink']

    if longlink != None and shortlink != None and shortlink != 'delete':  # Замена хешированной сыллки на человекочитаемую

        try:
            conn = lite.connect("linkbase.db", check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""UPDATE links SET shortlink = (?) WHERE longlink = (?)""", (shortlink, longlink)).fetchone()
            conn.commit()
        except:
            return jsonify("Операция отменена. Проверьте параметры.")

    elif longlink != None and shortlink == 'delete': # Удаление человекоподобной сылки, замена на хэш
        try:
            conn = lite.connect("linkbase.db", check_same_thread=False)
            cursor = conn.cursor()

            shortlink = str(urlsafe_b64encode(hashlib.sha1(longlink.encode()).digest()).decode()[0:12])
            cursor.execute("""UPDATE links SET shortlink = (?) WHERE longlink = (?)""", (shortlink, longlink)).fetcall()
            conn.commit()
        except:
            return  jsonify("Операция отменена. Проверьте параметры.")


    elif longlink != None and linktype == 'public' or linktype == 'shared' or linktype == 'private':  # Изменение уровня доступа
        try:
            conn = lite.connect("linkbase.db", check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""UPDATE links SET link_type = (?) WHERE longlink = (?)""", (linktype, longlink)).fetchone()
            conn.commit()
        except:
            return jsonify("Операция отменена. Проверьте параметры!")

    elif longlink != None and deletelink == 'delete':  # Удаление записи
        try:
            conn = lite.connect("linkbase.db", check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("""DELETE FROM links WHERE longlink = (?)""", (longlink,)).fetchall()
            conn.commit()
        except:
            return jsonify("Операция отменена. Проверьте параметры.!")

    return jsonify(f'Операция выполнена!')


@app.route('/admin/joke', methods=['GET'])
def get_jokes():
    jokes = Jokes.query.all()

    result = []
    response = []


    for i_res in [1,2,3,4,5,6,7,8,9,10]:
        i_res_data = {}
        i_res_data = requests.get('https://api.chucknorris.io/jokes/random').content

        response.append(i_res_data)

    for joke in jokes:
        joke_data = {}
        joke_data['id'] = joke.response.content['id']
        joke_data['joke'] = joke.response.content['value']
        joke_data['icon'] = joke.response.content['icon_url']

        result.append(joke_data)

    return jsonify({'joke': result})




#Маршрут для вывода списка пользователей которые есть в базе
@app.route('/admin/user', methods=['GET'])
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
@app.route('/admin/links', methods=['GET', 'POST'])
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


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)