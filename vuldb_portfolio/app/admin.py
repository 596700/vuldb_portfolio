from django.contrib import admin
from . import models

# Register your models here.


admin.site.register(models.AppName)
admin.site.register(models.Version)
admin.site.register(models.AppNameVersion)
admin.site.register(models.Vulnerability)