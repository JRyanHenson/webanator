from django.shortcuts import render, redirect, reverse
from django.views import generic
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import IntegrityError

from .forms import *
from .models import *


# Create your views here.
class UploadArtifactView(LoginRequiredMixin, generic.FormView):
	template_name = 'poam/upload.html'
	model = Weakness
	# form_class = UploadArtifactForm

	def form_valid(self, form):
		print(form)


class NewSystemView(LoginRequiredMixin, generic.CreateView):
	template_name= 'poam/new_system.html'
	model = System
	form_class = NewSystemForm

	def form_valid(self, form):
		self.object=form.save()
		return redirect(reverse("poam:upload-artifact"))


class NewPOCView(LoginRequiredMixin, generic.CreateView):
	template_name = 'poam/new_poc.html'
	model = PointOfContact
	form_class = NewPOCForm

	def form_valid(self, form):
		self.object=form.save()
		return redirect(reverse("poam:new-system"))