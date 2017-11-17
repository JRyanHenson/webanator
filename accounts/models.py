from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils.translation import ugettext_lazy as _

from .managers import UserManager


# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
	email = models.EmailField(_('email address'), unique=True)
	first_name = models.CharField(_('first name'), max_length=30, blank=True)
	last_name = models.CharField(_('last name'), max_length=30, blank=True)
	date_joined = models.DateTimeField(_('date joined'), auto_now_add=True)
	password_changed = models.BooleanField(_('password changed'), default=False)
	last_login = models.DateTimeField(auto_now=True)
	is_active = models.BooleanField(_('active'), default=True)
	is_superuser = models.BooleanField(_('superuser'), default=False)
	is_staff = models.BooleanField(_('staff'), default=False)

	objects = UserManager()

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['first_name', 'last_name']

	class Meta:
		db_table = "user"
		verbose_name = _('user')
		verbose_name_plural = _('users')

	def get_full_name(self):
		'''Returns the first_name plus the last_name, with a space in between.'''
		full_name = '{} {}'.format(self.first_name, self.last_name)
		return full_name.strip()
