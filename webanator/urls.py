from django.conf.urls import include, url
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
	url(r'^poam/', include('poam.urls', namespace='poam')),
    url(r'^account/', include('accounts.urls', namespace='accounts')),
]
