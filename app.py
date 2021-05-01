#Добавляем модули
from flask import Flask, request, jsonify
import sqlite3 as lite
app = Flask(__name__)



@app.route('/shortlink/<link>', methods=['GET', 'PUT', 'DELETE'])
def short_link():
    link = #из БД
    return jsonify(link)
#Создаем БД
con = lite.connect('short_link_bd.db', check_same_thread=False)
cur = con.cursor()


#Создание интерфейса
@app.route('/<link>', methods=['GET', 'PUT', 'DELETE'])
def short_link():
    link = #из БД
    #Определение типа ссылки (Публичные, Общего доступа, Приватные)
    if link.[0] == 'p': #Сылка публичная
        return jsonify(link)
    elif link.[0] == 'all' or link.[0] == 'pr':
        #Авторизация JWT
        return jsonify(link)


@app.route('/shortlink/<clink>', methods=['GET', 'PUT', 'DELETE'])
def c_link():
    link = #из БД
    return jsonify(link)

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



#Help
@app.route('/help')
def help():
    return render_tamplate('help.html')

#Дополнения...

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)