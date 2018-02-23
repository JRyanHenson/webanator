from django.conf.urls import url

from . import views


urlpatterns = [
    url(r'^edit_system/(?P<pk>[0-9]+)/$', views.EditSystemView.as_view(), name='edit-system'),
    url(r'^upload_artifact/(?P<pk>[0-9]+)/$', views.UploadArtifactView.as_view(), name='upload-artifact'),
    url(r'^select_system/$', views.SelectSystemView.as_view(), name='select-system'),
    url(r'^add_device/(?P<pk>[0-9]+)/$', views.AddDeviceView.as_view(), name='add-device'),
    url(r'^new_system/$', views.NewSystemView.as_view(), name='new-system'),
    url(r'^new_poc/$', views.NewPOCView.as_view(), name='new-poc'),
]
