from django.conf.urls import url

from . import views


urlpatterns = [
	url(r'^upload_artifact/$', views.UploadArtifactView.as_view(), name='upload-artifact')
]
