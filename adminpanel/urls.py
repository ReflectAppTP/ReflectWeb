from django.urls import path
from . import views

urlpatterns = [
    path('', views.admin_login, name='admin_login'),  # Делаем страницу входа главной
    path('login/', views.admin_login, name='admin_login'),
    path('logout/', views.admin_logout, name='admin_logout'),
    path('users/', views.users_list, name='users_list'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    path('users/<int:user_id>/edit/', views.edit_user_field, name='edit_user_field'),
    path('complaints/', views.complaints_list, name='complaints_list'),
    path('complaints/user/<int:report_id>/resolve/', views.resolve_user_report, name='resolve_user_report'),
    path('complaints/state/<int:report_id>/resolve/', views.resolve_state_report, name='resolve_state_report'),
    path('api/user/<int:user_id>/details/', views.user_details_proxy, name='user_details_proxy'),
] 