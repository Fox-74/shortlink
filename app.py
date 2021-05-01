#Добавляем модули
from flask import Flask, request, jsonify
import sqlite3 as lite
app = Flask(__name__)

#Создаем БД
conn = lite.connect("linkbase.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""CREATE TABLE IF NOT EXISTS users (
	id	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	user_name TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	tg_id INTEGER NOT NULL)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS user_links (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	user_id	INTEGER NOT NULL,
	shortlink_id INTEGER NOT NULL)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS links (
	id	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	longlink TEXT NOT NULL,
	shortlink TEXT UNIQUE,
	counter INTEGER NOT NULL,
	user_name TEXT NOT NULL,
	link_type TEXT)""")


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

@app.route('/registration')
def non_registration():
    return jsonify(f'Регистрация невозвожна')


#Создание интерфейса
@app.route('/<shortlink>,<user_name>,<password>', methods=['GET', 'PUT', 'DELETE', 'UPDATE'])
def link_shorter(shortlink = None, user_name = None, password = None):
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()

    if user_name != None and password != None and shortlink == None:
        user_links = ("""SELECT user_name FROM links
                            WHERE user_name = (?)""", user_name,)
        return user_links

    elif user_name == None and password == None and shortlink != None:
        check_link = ("""SELECT link_type FROM links 
                        WHERE shortlink = (?)""", shortlink,)
        if check_link == None:
            return jsonify(f'Такой ссылки нет')

        elif check_link != None:

            cursor.execute("""UPDATE links SET counter = counter + 1 WHERE shortlink = (?)""", shortlink,)
            conn.commit()

        elif check_link != 'private' and check_link != 'shared':
            return jsonify(f'Ссылка будет тут!')


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