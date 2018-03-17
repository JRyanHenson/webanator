from .base import *


# Secret Key
SECRET_KEY = os.environ['SECRET_KEY']


# Debug
DEBUG = True


# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME':'webanatorDB',
        'USER': 'postgres',
        'PASSWORD': os.environ['DB_PASS'],
        'HOST': 'localhost',
        'PORT': '',
    }
}


# Static and media files
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static')
]

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, '/static/')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
