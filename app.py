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
	user_name TEXT NOT NULL)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS link_type (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	type TEXT NOT NULL UNIQUE)""")

conn.commit()


@app.route('/shortlink/<link>', methods=['GET', 'PUT', 'DELETE'])
def short_link():
    link = 0 #из БД
    return jsonify(link)
@app.route('/registration/<user_name>,<password>', methods=['GET', 'POST', 'PUT'])
def registration(user_name = None, password = None):
    # регистрация
    conn = lite.connect("linkbase.db", check_same_thread=False)
    cursor = conn.cursor()
    if user_name == None or password == None:
        return jsonify(f'Регистрация невозвожна')
    check_user = ("""SELECT user_name from users
                        WHERE user_name = (?)""", (user_name,))
    if check_user != None:
        cursor.execute("""INSERT INTO users (user_name, password)
                        VALUES ((?), (?))""", (user_name, password))
        conn.commit()
        return jsonify(f'Вы зарегистрированы, ', {user_name})
conn.commit()



# #Создание интерфейса
# @app.route('/<link>,<user_name>,<password>', methods=['GET', 'PUT', 'DELETE'])
# def short_link(link = None, user_name = None, password = None):
#     link = #из БД
#     if user_name != None and password != None and link == None:
#         user_links = ("""SELECT short""")
#         return user_links
#     #Определение типа ссылки (Публичные, Общего доступа, Приватные)
#     if link.[0] == 'p': #Сылка публичная
#         return jsonify(link)
#     elif link.[0] == 'all' or link.[0] == 'pr':
#         #Авторизация JWT
#         return jsonify(link)


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