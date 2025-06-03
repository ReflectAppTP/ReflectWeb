from .settings import *

DEBUG = False

ALLOWED_HOSTS = ['reflect-app.ru', '185.185.71.233']

# Настройки базы данных PostgreSQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'reflect_db',
        'USER': 'goida',
        'PASSWORD': 'akeruwerawnitu',
        'HOST': '185.185.71.233',
        'PORT': '5438',
    }
}

# Настройки статических файлов
STATIC_ROOT = BASE_DIR / 'static'
STATIC_URL = '/static/'

# Настройки безопасности
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY' 
