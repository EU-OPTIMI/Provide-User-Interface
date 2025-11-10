from django.contrib import admin
from .models import UploadedFile, OfferAccess, UploadedData, License, OfferAdditionalMetadata
# Register your models here.
admin.site.register(License)
admin.site.register(UploadedFile)
admin.site.register(OfferAccess)
admin.site.register(UploadedData)
admin.site.register(OfferAdditionalMetadata)
