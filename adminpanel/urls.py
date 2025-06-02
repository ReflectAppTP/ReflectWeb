from django.urls import path
from . import views

urlpatterns = [
    path('', views.admin_login, name='admin_login'),  # Делаем страницу входа главной
    path('login/', views.admin_login, name='admin_login'),
    path('logout/', views.admin_logout, name='admin_logout'),
    path('users/', views.users_list, name='users_list'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    path('complaints/', views.complaints_list, name='complaints_list'),
    path('complaints/user/<int:user_id>/resolve/', views.resolve_user_report, name='resolve_user_report'),
    path('complaints/state/<int:state_id>/resolve/', views.resolve_state_report, name='resolve_state_report'),
] 