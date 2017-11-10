from .base import *

import os

SECRET_KEY = os.environ['SECRET_KEY']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME':'webanator',
		'USER': 'webanator',
		'PASSWORD': os.environ['DB_PASS'],
		'HOST': 'localhost',
		'PORT': '',
    }
}
