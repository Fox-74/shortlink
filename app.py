#Добавляем модули
import flask
from flask import Flask, request, jsonify
import sqlite3 as lite
from base64 import urlsafe_b64encode
import hashlib


app = Flask(__name__)

#Создаем БД
conn = lite.connect("linkbase.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""CREATE TABLE IF NOT EXISTS users (
	id	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	user_name TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	tg_id INTEGER)""")

cursor.execute("""CREATE TABLE IF NOT EXISTS user_links (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	links_id INTEGER,
	FOREIGN KEY (links_id) REFERENCES links(id)
	FOREIGN KEY (user_id) REFERENCES users(id)
	)""")

cursor.execute("""CREATE TABLE IF NOT EXISTS links (
	id	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	longlink TEXT NOT NULL,
	shortlink TEXT,
	counter INTEGER,
	user_name TEXT,
	link_type TEXT,
	FOREIGN KEY (user_id) REFERENCES users(id)
	)""")


conn.commit()


@app.route('/shortlink/<link>', methods=['GET', 'PUT', 'DELETE'])
def short_link():
    link = 0 #из БД
    return jsonify(link)
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

@app.route('/registration', methods=['GET', 'POST'])
def non_registration():
    return jsonify(f'Регистрация невозвожна')


#Создание интерфейса
try:
    @app.route('/<shortlink>', methods=['GET', 'PUT', 'DELETE', 'UPDATE'])
    def link_shorter(shortlink):
        # data = request.get_json()
        conn = lite.connect("linkbase.db", check_same_thread=False)
        cursor = conn.cursor()

        get_long_link = cursor.execute("""SELECT longlink FROM links WHERE shortlink = (?)""", (shortlink,)).fetchone()
        get_long_link = get_long_link[0]
        type_link = cursor.execute("""SELECT link_type FROM links WHERE shortlink = (?)""", (shortlink,)).fetchall()
        # if type_link == "public":
        #     cursor.execute("""UPDATE links SET counter = counter + 1 WHERE shortlink = (?)""", shortlink)
        #     return flask.redirect(get_long_link)
        # print(get_long_link)
        return flask.redirect(get_long_link)
        # else:
        #     return ("!!!")

except TypeError:
    print("Oops!")


@app.route('/makelink', methods=['GET', 'POST'])
def makelink():
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()
    data = request.get_json()
    name = data['name']
    password = data['password']
    longlink = data['link']
    linktype = data['linktype']
    shortlink = str(urlsafe_b64encode(hashlib.sha1(str(data['link']).encode()).digest()).decode()[0:12])
    counter = 0
    check_user = cursor.execute("""SELECT user_name FROM users WHERE user_name = (?)""", (name,)).fetchall()
    check_password = cursor.execute("""SELECT password FROM users WHERE user_name = (?)""", (name,)).fetchall()
    if check_user[0][0] == name and check_password[0][0] == password:
        user_id = cursor.execute("""SELECT id FROM users WHERE user_name = (?)""", (name,)).fetchall()
        user_id = user_id[0][0]

        cursor.execute("""INSERT INTO links (user_id, longlink, counter, shortlink, user_name, link_type) VALUES( (?), (?), (?), (?), (?), (?) )""", (user_id, longlink, counter, shortlink, name, linktype))

        conn.commit()


        return jsonify(data)
    return jsonify(data)





    # #Определение типа ссылки (Публичные, Общего доступа, Приватные)
    # if link.[0] == 'p': #Сылка публичная
    #     return jsonify(link)
    # elif link.[0] == 'all' or link.[0] == 'pr':
    #     #Авторизация JWT
    #     return jsonify(link)


# @app.route('/shortlink/<clink>', methods=['GET', 'PUT', 'DELETE'])
# def c_link():
#     link = #из БД
#     return jsonify(link)

#Объявляем функции
    #Генератор коротких ссылок



#Авторизация/Регистрация JWT
    #
    #Запись в БД



#Получение данных от пользователя
    #Получение ссылки (длинной)
    #Создание короткой ссылки при помощи генератора или проверка совпадений с желаемой ссылкой
    #Запись ссылки в БД


#Отправка пользвателю короткой ссылки для использования и запись в БД




#Получение короткой ссылки
    #Проверка наличия короткой ссылки в БД
    #Если ссылка есть, то записать счетчик ссылки +1, перенаправление на адрес
    #из БД(генерировать по короткой ссылке
    #Если ссылки нет, то отправить ошибку



#Информация о сервисе



# #Help
# @app.route('/help')
# def help():
#     return render_tamplate('help.html')

#Дополнения...

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)