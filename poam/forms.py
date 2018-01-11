from django import forms
from django.forms import ModelForm
from .models import *


# Create the form class.
class NewSystemForm(ModelForm):
    class Meta:
        model = System
        exclude = ['update_date', 'create_date']


class NewPOCForm(ModelForm):
	class Meta:
		model = PointOfContact
		fields = "__all__"


class DocumentModelForm(ModelForm):

    class Meta:
        model = Weakness
        fields = "__all__"


class DocumentForm(forms.Form, ModelForm):

    file = forms.FileField()
    FILE_TYPE_CHOICES = [
        ('stig_checklist_file','STIG Checklist File'),
        ('nessus_scan_file', 'Nessus Scan File'),
        ('rmf_control_review_file', 'RMF Control Review File')
    ]
    file_type = forms.CharField(label='File Type', widget=forms.RadioSelect(choices=FILE_TYPE_CHOICES))

    class Meta:
        model = Weakness
        fields = ['system', 'point_of_contact', 'source_identifying_event', 'source_identifying_tool']