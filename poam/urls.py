from django.conf.urls import url

from . import views


urlpatterns = [
    url(r'^upload_poam/(?P<pk>[0-9]+)/$', views.UploadPOAMView.as_view(), name='upload-poam'),
    url(r'^edit_system/(?P<pk>[0-9]+)/$', views.EditSystemView.as_view(), name='edit-system'),
    url(r'^upload_artifact/(?P<pk>[0-9]+)/$', views.UploadArtifactView.as_view(), name='upload-artifact'),
    url(r'^upload_device/(?P<pk>[0-9]+)/$', views.UploadDeviceView.as_view(), name='upload-device'),
    url(r'^export_poam/(?P<pk>[0-9]+)/$', views.ExportPoamView.as_view(), name='export-poam'),
    url(r'^export_hw_sw_list/(?P<pk>[0-9]+)/$', views.ExportHwSwView.as_view(), name='export-hw-sw-list'),
    url(r'^edit_devices/(?P<pk>[0-9]+)/$', views.SelectDeviceView.as_view(), name='select-device'),
    url(r'^edit_device/(?P<pk>[0-9]+)/$', views.EditDeviceView.as_view(), name='edit-device'),
    url(r'^select_system/$', views.SelectSystemView.as_view(), name='select-system'),
    url(r'^add_device/(?P<pk>[0-9]+)/$', views.AddDeviceView.as_view(), name='add-device'),
    url(r'^new_system/$', views.NewSystemView.as_view(), name='new-system'),
    url(r'^new_poc/$', views.NewPOCView.as_view(), name='new-poc'),
]
