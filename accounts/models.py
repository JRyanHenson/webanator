from django.db import models
from django.conf import settings
from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL)

    def __str__(self):
        return 'Profile for user {}'.format(self.user.username)
