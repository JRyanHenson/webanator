from django import forms
from .models import *


# Create the form class.
class SystemForm(forms.ModelForm):

    class Meta:
        model = System
        exclude = ['update_date', 'create_date']


class NewPOCForm(forms.ModelForm):

    class Meta:
        model = PointOfContact
        fields = "__all__"


class WeaknessModelForm(forms.ModelForm):

    class Meta:
        model = Weakness
        exclude = "__all__"


class DeviceForm(forms.ModelForm):

    class Meta:
        model = Device
        fields = ['name', 'type', 'hardware']


# class DeviceWeaknessForm(ModelForm):
#
# 	class Meta:
# 		model = DeviceWeakness
# 		fields = "__all__"


class DocumentForm(forms.Form, forms.ModelForm):
    file = forms.FileField(widget=forms.ClearableFileInput(attrs={'multiple': True}))
    FILE_TYPE_CHOICES = [
        ('stig_checklist_file','STIG Checklist File'),
        ('nessus_scan_file', 'Nessus Scan File'),
        ('rmf_control_review_file', 'RMF Control Review File'),
        # ('cci_list', 'Update to CCI List'),
        ('poam_format', 'POAM Format')
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
        self.fields['system'].required = True
        self.fields['system'].initial = system
        self.fields['devices'].queryset = Device.objects.filter(system=system).order_by('name')
        self.fields['devices'].required = False


class POAMForm(forms.ModelForm):
    file = forms.FileField()

    class Meta:
        model = System
        fields = ['name', 'file']

        widgets = {
            'name': forms.HiddenInput()
        }


class DeviceUploadForm(forms.ModelForm):
    file = forms.FileField()

    class Meta:
        model = System
        fields = ['name', 'file']

        widgets = {
            'name': forms.HiddenInput()
        }
