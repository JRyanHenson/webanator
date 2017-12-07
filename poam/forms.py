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