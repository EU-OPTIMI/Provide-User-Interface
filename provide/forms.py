# forms.py

from django import forms
from django.core.exceptions import ValidationError
from django.conf import settings


def _build_select_choices(option_list, placeholder):
    """Return select choices with a leading placeholder."""
    normalized = [(opt.strip(), opt.strip()) for opt in option_list if opt and opt.strip()]
    if not normalized:
        return [('', 'No options configured')]
    return [('', placeholder)] + normalized

class UploadMetadataForm(forms.Form):
    offer_title = forms.CharField()
    offer_description = forms.CharField()
    keywords = forms.CharField()
    offer_publisher = forms.CharField()
    offer_language = forms.CharField()
    offer_license = forms.ChoiceField(choices=[])
    accessUrl = forms.URLField()
    start = forms.DateTimeField(required=True, input_formats=['%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M'])
    end = forms.DateTimeField(required=True, input_formats=['%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M'])
    access_policy = forms.ChoiceField(choices=[('', 'Select access policy'), ('between_dates', 'Provide access between dates')], required=True)
    value = forms.CharField(widget=forms.HiddenInput, required=False)
    data_model = forms.ChoiceField(choices=[], required=True)
    purpose_of_use = forms.ChoiceField(choices=[], required=True)
    visibility = forms.ChoiceField(
        choices=(('public', 'Public'), ('private', 'Private')),
        required=True,
        initial='public',
    )
    # Authentication fields for access URL testing and artifact creation
    AUTH_TYPE_CHOICES = (
        ('none', 'None'),
        ('basic', 'Basic (username/password)'),
        ('bearer', 'Bearer (token)'),
    )
    auth_type = forms.ChoiceField(choices=AUTH_TYPE_CHOICES, required=False, initial='none')
    auth_username = forms.CharField(required=False)
    auth_password = forms.CharField(required=False, widget=forms.PasswordInput)
    auth_token = forms.CharField(required=False, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        license_choices = kwargs.pop('license_choices', [])
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
        self.fields['offer_license'].choices = license_choices
        data_model_options = getattr(settings, 'DATA_MODEL_OPTIONS', [])
        purpose_options = getattr(settings, 'PURPOSE_OF_USE_OPTIONS', [])
        self.fields['data_model'].choices = _build_select_choices(data_model_options, 'Select data model')
        self.fields['purpose_of_use'].choices = _build_select_choices(purpose_options, 'Select purpose')
        if self.is_bound:
            mutable = self.data.copy()
            if not mutable.get('offer_license'):
                mutable['offer_license'] = self._first_choice_value('offer_license') or ''
            if not mutable.get('data_model'):
                mutable['data_model'] = self._first_choice_value('data_model') or ''
            if not mutable.get('purpose_of_use'):
                mutable['purpose_of_use'] = self._first_choice_value('purpose_of_use') or ''
            if not mutable.get('visibility'):
                mutable['visibility'] = 'public'
            self.data = mutable

    def _first_choice_value(self, field_name):
        for value, _label in self.fields[field_name].choices:
            if value:
                return value
        return None

    def clean(self):
        cleaned = super().clean()
        auth_type = cleaned.get('auth_type')
        if auth_type == 'basic':
            if not cleaned.get('auth_username') or not cleaned.get('auth_password'):
                raise ValidationError('Username and password are required for basic authentication')
        if auth_type == 'bearer':
            if not cleaned.get('auth_token'):
                raise ValidationError('Token is required for bearer authentication')
        return cleaned

    def clean_accessUrl(self):
        url = self.cleaned_data.get('accessUrl')
        if url and self.request and url.startswith('/'):
            url = self.request.build_absolute_uri(url)
        return url
