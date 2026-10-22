from django.contrib import admin
from django.urls import include, path

from django_action_permissions.utils import drf_installed

urlpatterns = [path("admin/", admin.site.urls)]

if drf_installed():
    from tests.drf_views import router

    urlpatterns.append(path("api/", include(router.urls)))
