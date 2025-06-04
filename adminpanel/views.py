from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import JsonResponse
from django.contrib import messages # Для отображения сообщений
import requests
from django.views.decorators.csrf import csrf_exempt
import json
import sys

API_URL = "http://web:8000"

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
                        resp = redirect('/adminpanel/users/')
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
        # Приводим к нужному формату для таблицы и модалки
        users_for_table = []
        for u in users:
            users_for_table.append({
                'id': u.get('id', ''),
                'username': u.get('username', ''),
                'email': u.get('email', ''),
                'is_admin': 'yes' if u.get('is_admin') else 'no',
                'is_premium': 'yes' if u.get('is_premium') else 'no',
                'is_blocked': 'yes' if u.get('is_blocked') else 'no',
            })
    except requests.exceptions.HTTPError as e:
        users_for_table = []
        if e.response.status_code == 401:
            messages.error(request, "Сессия истекла или недействительна. Пожалуйста, войдите снова.")
            return redirect('admin_logout')
        else:
            messages.error(request, f"Ошибка API при получении пользователей: {e.response.status_code} - {e.response.text}")
    except requests.exceptions.RequestException as e:
        users_for_table = []
        messages.error(request, f"Сетевая ошибка при получении пользователей: {e}")
    except ValueError:
        users_for_table = []
        messages.error(request, "Неверный формат ответа от API пользователей.")
        
    return render(request, 'adminpanel/users.html', {'users': users_for_table})

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
            if report.get('is_resolved'):
                continue
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
            if report.get('is_resolved'):
                continue
            state_id = report.get('state')
            state_details = {}
            try:
                state_resp = requests.get(f"{API_URL}/api/reports/admin/state/{state_id}/details/", headers=headers)
                state_resp.raise_for_status()
                state_details = state_resp.json()
            except Exception:
                state_details = {}
            card_text = state_details.get('description', 'Текст карточки не найден')
            complaint_text = report.get('reason', 'Текст жалобы не найден')
            description = f'"{card_text}" - "{complaint_text}"'
            username = state_details.get('username', '')
            email = state_details.get('email', '')
            all_complaints_data.append({
                'id': report.get('id'),
                'type': 'state_report',
                'state_id': state_id,
                'username': username,
                'email': email,
                'description': description,
                'object': f"Жалоба на карточку (ID: {state_id})",
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

@csrf_exempt
@admin_auth_required
def resolve_user_report(request, report_id):
    access_token = request.COOKIES.get('admin_access_token')
    headers = {'Authorization': f'Bearer {access_token}'}
    if request.method == "POST":
        try:
            response = requests.post(
                f"{API_URL}/api/reports/admin/user/{report_id}/resolve/",
                json={"accept": True},
                headers=headers
            )
            if response.status_code in (200, 204):
                return JsonResponse({'success': True}, status=200)
            return JsonResponse({'success': False, 'error': response.text}, status=response.status_code)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    return JsonResponse({'success': False, 'error': 'Метод не поддерживается'}, status=405)

@csrf_exempt
@admin_auth_required
def resolve_state_report(request, report_id):
    access_token = request.COOKIES.get('admin_access_token')
    headers = {'Authorization': f'Bearer {access_token}'}
    if request.method == "POST":
        try:
            response = requests.post(
                f"{API_URL}/api/reports/admin/state/{report_id}/resolve/",
                json={"accept": True},
                headers=headers
            )
            if response.status_code in (200, 204):
                return JsonResponse({'success': True}, status=200)
            return JsonResponse({'success': False, 'error': response.text}, status=response.status_code)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    return JsonResponse({'success': False, 'error': 'Метод не поддерживается'}, status=405)

@admin_auth_required
def user_details_proxy(request, user_id):
    api_url = f'{API_URL}/api/reports/admin/state/{user_id}/details/'
    try:
        resp = requests.get(api_url)
        return JsonResponse(resp.json(), status=resp.status_code)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@admin_auth_required
def edit_user_field(request, user_id):
    if request.method not in ['PATCH', 'POST']:
        return JsonResponse({'success': False, 'error': 'Метод не поддерживается'}, status=405)
    access_token = request.COOKIES.get('admin_access_token')
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    try:
        if request.method == 'PATCH':
            data = json.loads(request.body.decode('utf-8'))
        else:  # POST
            content_type = request.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                data = json.loads(request.body.decode('utf-8'))
            else:
                data = request.POST.dict()
        if not data:
            return JsonResponse({'success': False, 'error': 'Не переданы данные для редактирования'}, status=400)
        # Определяем, какое поле редактируется
        field = None
        if 'username' in data:
            field = 'username'
        elif 'is_blocked' in data:
            field = 'is_blocked'
        elif 'is_admin' in data:
            field = 'is_admin'
        if not field:
            return JsonResponse({'success': False, 'error': 'Неизвестное поле для редактирования'}, status=400)
        # Отправляем запрос на соответствующий эндпоинт
        resp = requests.patch(
            f"{API_URL}/api/reports/admin/user/{user_id}/edit/{field}/",
            headers=headers,
            json={field: data[field]}
        )
        if resp.status_code == 200:
            return JsonResponse({'success': True, 'data': resp.json()})
        return JsonResponse({'success': False, 'error': resp.text}, status=resp.status_code)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Неверный формат JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
