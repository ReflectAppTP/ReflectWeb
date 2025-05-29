from django.shortcuts import render

# Create your views here.

def admin_login(request):
    return render(request, 'adminpanel/login.html')

def users_list(request):
    users = [
        {'id': 1, 'username': 'Анна Иванова', 'email': 'anna@mail.ru', 'last_login': '12.05.2024 14:22'},
        {'id': 2, 'username': 'Борис Смирнов', 'email': 'boris@gmail.com', 'last_login': '01.01.2023 09:00'},
        {'id': 3, 'username': 'Виктория Кузнецова', 'email': 'viktoria@ya.ru', 'last_login': '15.03.2024 18:45'},
        {'id': 4, 'username': 'Глеб Петров', 'email': 'gleb@outlook.com', 'last_login': '20.04.2024 11:10'},
        {'id': 5, 'username': 'Дмитрий Соколов', 'email': 'dmitry@mail.ru', 'last_login': '05.02.2024 22:30'},
        {'id': 6, 'username': 'Екатерина Орлова', 'email': 'ekaterina@gmail.com', 'last_login': '28.01.2024 08:15'},
        {'id': 7, 'username': 'Роман Романин', 'email': 'romanroman@gmail.ru', 'last_login': '00.00.0000 00:00'},
    ]
    return render(request, 'adminpanel/users.html', {'users': users})

def complaints_list(request):
    complaints = [
        {'id': 1, 'username': 'Анна Иванова', 'email': 'anna@mail.ru', 'description': 'Неподобающая лексика', 'object': 'Имя пользователя'},
        {'id': 2, 'username': 'Борис Смирнов', 'email': 'boris@gmail.com', 'description': 'Неподобающая лексика', 'object': 'Имя пользователя'},
        {'id': 3, 'username': 'Виктория Кузнецова', 'email': 'viktoria@ya.ru', 'description': 'Неподобающая лексика', 'object': 'Описание'},
        {'id': 4, 'username': 'Глеб Петров', 'email': 'gleb@outlook.com', 'description': 'Неподобающая лексика', 'object': 'Имя пользователя'},
        {'id': 5, 'username': 'Дмитрий Соколов', 'email': 'dmitry@mail.ru', 'description': 'Неподобающая лексика', 'object': 'Описание'},
        {'id': 6, 'username': 'Екатерина Орлова', 'email': 'ekaterina@gmail.com', 'description': 'Неподобающая лексика', 'object': 'Имя пользователя'},
        {'id': 7, 'username': 'Роман Романин', 'email': 'romanroman@gmail.ru', 'description': 'Неподобающая лексика', 'object': 'Имя пользователя'},
    ]
    return render(request, 'adminpanel/complaints.html', {'complaints': complaints})
