from django.urls import path
from . import views

app_name = 'provide'  # This defines the namespace


urlpatterns = [
    path('', views.handle_metadata, name='handle_metadata'),  # Root path handles incoming metadata
    path('offer/', views.provide_offer, name='provide_offer'),  # Display the offer form
    path('test-access/', views.test_access_endpoint, name='test_access'),
    path('upload/', views.upload_view, name='file_upload'),
    path('upload/<int:file_id>/', views.upload_view, name='file_download'),
    # API endpoint for extracted uploaded data
    path('api/uploaded-data/<int:data_id>/', views.uploaded_data_api, name='uploaded_data_api'),
    # API endpoint for OfferAccess (returns all linked data)
    path('api/offer-access/<uuid:offer_uuid>/', views.offer_access_api, name='offer_access_api'),
    # API endpoint for offer-specific additional metadata
    path('api/offers/<str:offer_id>/extras/', views.offer_additional_metadata_api, name='offer_additional_metadata_api'),
    path('api/auth/profile/', views.auth_profile_proxy, name='auth_profile_proxy'),
]
