from django.shortcuts import render, redirect, reverse
from django.views import generic
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import IntegrityError

from .models import *


# Create your views here.
class UploadArtifactView(LoginRequiredMixin, generic.FormView):
	template_name = 'poam/upload.html'
	model = Weakness
	form_class = UploadArtifactForm

	def form_valid(self, form):
		print(form)
