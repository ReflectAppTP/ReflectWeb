from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import JsonResponse
from django.contrib import messages # Для отображения сообщений
import requests
from django.views.decorators.csrf import csrf_exempt

API_URL = "http://185.185.71.233"

# Декоратор для проверки, аутентифицирован ли администратор
def admin_auth_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        access_token = request.COOKIES.get('admin_access_token')
        if not access_token:
            return redirect('admin_login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def admin_login(request):
    error = None
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        if not email or not password:
            error = "Email и пароль обязательны."
        else:
            try:
                response = requests.post(
                    f"{API_URL}/api/authReflect/login/",
                    json={"email": email, "password": password}
                )
                if response.status_code == 200:
                    data = response.json()
                    access_token = data.get('access')
                    if access_token:
                        resp = redirect('users_list')
                        resp.set_cookie('admin_access_token', access_token, max_age=86400)
                        return resp
                    else:
                        error = "Не удалось получить токен."
                else:
                    error = "Неверный email или пароль."
            except Exception:
                error = "Ошибка соединения с сервером."
    return render(request, 'adminpanel/login.html', {'error': error})

def admin_logout(request):
    resp = redirect('admin_login')
    resp.delete_cookie('admin_access_token')
    return resp

@admin_auth_required
def users_list(request):
    access_token = request.COOKIES.get('admin_access_token')
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.get(f"{API_URL}/api/reports/admin/users/", headers=headers)
        response.raise_for_status()
        users = response.json() if response.status_code == 200 else []
    except requests.exceptions.HTTPError as e:
        users = []
        if e.response.status_code == 401:
            messages.error(request, "Сессия истекла или недействительна. Пожалуйста, войдите снова.")
            return redirect('admin_logout')
        else:
            messages.error(request, f"Ошибка API при получении пользователей: {e.response.status_code} - {e.response.text}")
    except requests.exceptions.RequestException as e:
        users = []
        messages.error(request, f"Сетевая ошибка при получении пользователей: {e}")
    except ValueError:
        users = []
        messages.error(request, "Неверный формат ответа от API пользователей.")
        
    return render(request, 'adminpanel/users.html', {'users': users})

@admin_auth_required
def complaints_list(request):
    access_token = request.COOKIES.get('admin_access_token')
    headers = {'Authorization': f'Bearer {access_token}'}

    # Получаем список удалённых пользователей из сессии (если есть)
    deleted_users = request.session.get('deleted_users', set())
    if isinstance(deleted_users, list):
        deleted_users = set(deleted_users)

    all_complaints_data = []
    users_dict = {}
    try:
        users_resp = requests.get(f"{API_URL}/api/reports/admin/users/", headers=headers)
        users_resp.raise_for_status()
        users = users_resp.json() if users_resp.status_code == 200 else []
        for u in users:
            users_dict[str(u.get('id'))] = {
                'username': u.get('username', ''),
                'email': u.get('email', '')
            }
    except Exception:
        users_dict = {}

    try:
        response = requests.get(f"{API_URL}/api/reports/admin/reports/", headers=headers)
        response.raise_for_status()
        data = response.json()
        for report in data.get('user_reports', []):
            user_id = str(report.get('reported_user'))
            user_info = users_dict.get(user_id)
            if user_info:
                username = user_info['username']
                email = user_info['email']
            else:
                username = 'Пользователь не найден'
                email = 'Пользователь не найден'
            if user_id in deleted_users:
                username = 'Пользователь удалён'
                email = 'Пользователь удалён'
            all_complaints_data.append({
                'id': report.get('id'),
                'type': 'user_report',
                'user_id': user_id,
                'username': username,
                'email': email,
                'description': report.get('reason'),
                'object': f"Жалоба на пользователя (ID: {user_id})",
                'created_at': report.get('created_at'),
                'is_resolved': report.get('is_resolved'),
                'is_accepted': report.get('is_accepted'),
                'reporter_id': report.get('reporter')
            })
        for report in data.get('state_reports', []):
            all_complaints_data.append({
                'id': report.get('id'),
                'type': 'state_report',
                'state_id': report.get('state'),
                'username': '',
                'email': '',
                'description': report.get('reason'),
                'object': f"Жалоба на карточку (ID: {report.get('state')})",
                'created_at': report.get('created_at'),
                'is_resolved': report.get('is_resolved'),
                'is_accepted': report.get('is_accepted'),
                'reporter_id': report.get('reporter')
            })
    except Exception:
        pass
    return render(request, 'adminpanel/complaints.html', {'complaints': all_complaints_data})

@csrf_exempt
@admin_auth_required
def delete_user(request, user_id):
    access_token = request.COOKIES.get('admin_access_token')
    headers = {'Authorization': f'Bearer {access_token}'}

    if request.method == "POST" or request.method == "DELETE":
        try:
            response = requests.delete(f"{API_URL}/api/reports/admin/user/{user_id}/delete/", headers=headers)
            if response.status_code == 204:
                # Добавляем id удалённого пользователя в сессию
                deleted_users = request.session.get('deleted_users', set())
                if isinstance(deleted_users, list):
                    deleted_users = set(deleted_users)
                deleted_users.add(str(user_id))
                request.session['deleted_users'] = list(deleted_users)
                request.session.modified = True
                return JsonResponse({'success': True}, status=200)
            response.raise_for_status()
            return JsonResponse({'success': False, 'error': f'Неожиданный ответ: {response.status_code}'}, status=response.status_code)
        except requests.exceptions.HTTPError as e:
            error_message = str(e)
            status_code = e.response.status_code if hasattr(e, 'response') else 500
            if status_code == 401:
                response = JsonResponse({'success': False, 'error': 'Не авторизован. Пожалуйста, войдите снова.'}, status=401)
                response.delete_cookie('admin_access_token')
                return response
            return JsonResponse({'success': False, 'error': error_message}, status=status_code)
        except requests.exceptions.RequestException as e:
            return JsonResponse({'success': False, 'error': f'Ошибка сети: {str(e)}'}, status=500)
    return JsonResponse({'success': False, 'error': 'Метод не поддерживается'}, status=405)

@admin_auth_required
def resolve_user_report(request, report_id): # report_id - это ID жалобы на пользователя
    access_token = request.session.get('admin_access_token')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json' # Важно для отправки JSON
    }
    if request.method == "POST":
        # Фронтенд отправляет "accept" как строку "true" или "false" в POST-данных, не JSON
        # API ожидает JSON: {"accept": true/false}
        try:
            accept_str = request.POST.get("accept") # Получаем из POST-данных формы
            if accept_str not in ["true", "false"]:
                return JsonResponse({'success': False, 'error': 'Неверное значение для параметра "accept".'}, status=400)
            accept = accept_str == "true" # Преобразуем строку в boolean
            
            # Используем report_id в URL
            response = requests.post(
                f"{API_URL}/api/admin/user/{report_id}/resolve/", 
                json={"accept": accept}, # Отправляем JSON в теле запроса
                headers=headers
            )
            response.raise_for_status()
            messages.success(request, f"Жалоба (ID: {report_id}) на пользователя обработана.")
            return JsonResponse(response.json(), status=response.status_code)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                return JsonResponse({'success': False, 'error': 'Не авторизован. Пожалуйста, войдите снова.'}, status=401)
            return JsonResponse({'success': False, 'error': str(e)}, status=e.response.status_code)
        except requests.exceptions.RequestException as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
        except Exception as e: # Ловим другие возможные ошибки, например, если request.POST.get отсутствует
            return JsonResponse({'success': False, 'error': f'Внутренняя ошибка: {str(e)}'}, status=500)

    return JsonResponse({'success': False, 'error': 'Неверный метод запроса.'}, status=405)

@admin_auth_required
def resolve_state_report(request, report_id): # report_id - это ID жалобы на карточку
    access_token = request.session.get('admin_access_token')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    if request.method == "POST":
        try:
            accept_str = request.POST.get("accept")
            if accept_str not in ["true", "false"]:
                 return JsonResponse({'success': False, 'error': 'Неверное значение для параметра "accept".'}, status=400)
            accept = accept_str == "true"

            # Используем report_id в URL
            response = requests.post(
                f"{API_URL}/api/admin/state/{report_id}/resolve/", 
                json={"accept": accept},
                headers=headers
            )
            response.raise_for_status()
            messages.success(request, f"Жалоба (ID: {report_id}) на карточку обработана.")
            return JsonResponse(response.json(), status=response.status_code)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                return JsonResponse({'success': False, 'error': 'Не авторизован. Пожалуйста, войдите снова.'}, status=401)
            return JsonResponse({'success': False, 'error': str(e)}, status=e.response.status_code)
        except requests.exceptions.RequestException as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Внутренняя ошибка: {str(e)}'}, status=500)
            
    return JsonResponse({'success': False, 'error': 'Неверный метод запроса.'}, status=405)