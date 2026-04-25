from django.contrib import admin
from django.urls import path, include

# V15: Default Django admin exposed at /admin/ with default credentials admin/admin123
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('banking.urls')),
]
