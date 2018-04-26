from django import forms
from django.forms import ModelForm
from .models import *


# Create the form class.
class SystemForm(ModelForm):

    class Meta:
        model = System
        exclude = ['update_date', 'create_date']


class NewPOCForm(ModelForm):

    class Meta:
        model = PointOfContact
        fields = "__all__"


class WeaknessModelForm(ModelForm):

    class Meta:
        model = Weakness
        fields = "__all__"


class DeviceForm(ModelForm):

    class Meta:
        model = Device
        exclude = ['system']


# class DeviceWeaknessForm(ModelForm):
#
# 	class Meta:
# 		model = DeviceWeakness
# 		fields = "__all__"


class DocumentForm(forms.Form, ModelForm):
    file = forms.FileField(widget=forms.ClearableFileInput(attrs={'multiple': True}))
    FILE_TYPE_CHOICES = [
        ('stig_checklist_file','STIG Checklist File'),
        ('nessus_scan_file', 'Nessus Scan File'),
        ('rmf_control_review_file', 'RMF Control Review File')
    ]
    file_type = forms.CharField(label='File Type', widget=forms.RadioSelect(choices=FILE_TYPE_CHOICES))

    class Meta:
        model = Weakness
        fields = ['system', 'point_of_contact', 'source_identifying_event', 'source_identifying_tool', 'source_identifying_date', 'devices']

        widgets = {
            'source_identifying_date': forms.DateInput(attrs={'type': 'date'}, format=('%Y-%m-%d'))
        }

    def __init__(self, system, *args, **kwargs):
        super(DocumentForm, self).__init__(*args, **kwargs)
        self.fields['devices'].queryset = Device.objects.filter(system=system)
        self.fields['devices'].required = False
        self.fields['system'].required = True
        # self.fields['system'].widget = forms.TextInput
        self.fields['system'].initial = system
