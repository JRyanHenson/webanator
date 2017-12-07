from django.conf.urls import url

from . import views


urlpatterns = [
	url(r'^upload_artifact/$', views.UploadArtifactView.as_view(), name='upload-artifact'),
	url(r'^new_system/$', views.NewSystemView.as_view(), name='new-system'),
	url(r'^new_poc/$', views.NewPOCView.as_view(), name='new-poc')
]
