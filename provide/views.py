import logging
import uuid
from django import forms
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import os
from .forms import UploadMetadataForm
from .connector import runner
from .connector import test_access_url
from .models import License, UploadedFile
import json
from django.views.decorators.http import require_GET
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django.urls import reverse
from django.core.exceptions import ValidationError

# Add a simple model for extracted data (to be added in models.py)
try:
    from .models import UploadedData
except ImportError:
    UploadedData = None  # Will need to add this model

logger = logging.getLogger(__name__)

# Constants
ALLOWED_FILE_TYPES = ["application/json"]
UPLOAD_DIR = 'uploads'


# Helper Functions
def truncate_to_minutes(date_str):
    """Return an ISO-8601 string trimmed to minute precision."""
    if not date_str:
        return date_str
    from datetime import datetime
    normalized = date_str.strip()
    try:
        normalized = normalized.replace('Z', '+00:00')
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        # allow fallback format without seconds
        try:
            dt = datetime.strptime(normalized, "%Y-%m-%dT%H:%M")
        except ValueError:
            return date_str
    trimmed = dt.replace(second=0, microsecond=0)
    if trimmed.tzinfo:
        return trimmed.isoformat(timespec='minutes')
    return trimmed.strftime("%Y-%m-%dT%H:%M")


def ensure_datetime_with_seconds(date_str):
    """Return ISO-8601 string including seconds (without microseconds)."""
    if not date_str:
        return date_str
    from datetime import datetime
    normalized = date_str.strip()
    # Accept Z or timezone offsets
    normalized = normalized.replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        dt = datetime.strptime(normalized, "%Y-%m-%dT%H:%M")
    dt = dt.replace(microsecond=0)
    return dt.isoformat()


def build_between_dates_permission(start_iso, end_iso):
    """Construct IDS Permission JSON-LD string enforcing a between-dates window."""
    permission = {
        "@context": {
            "ids": "https://w3id.org/idsa/core/",
            "idsc": "https://w3id.org/idsa/code/"
        },
        "@type": "ids:Permission",
        "ids:title": [{
            "@value": "Time-bound access",
            "@type": "http://www.w3.org/2001/XMLSchema#string"
        }],
        "ids:description": [{
            "@value": "Usage permitted only within the configured date interval",
            "@type": "http://www.w3.org/2001/XMLSchema#string"
        }],
        "ids:action": [
            {"@id": "idsc:USE"}
        ],
        "ids:constraint": [
            {
                "@type": "ids:Constraint",
                "ids:leftOperand": {"@id": "idsc:POLICY_EVALUATION_TIME"},
                "ids:operator": {"@id": "idsc:AFTER"},
                "ids:rightOperand": {
                    "@value": start_iso,
                    "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                }
            },
            {
                "@type": "ids:Constraint",
                "ids:leftOperand": {"@id": "idsc:POLICY_EVALUATION_TIME"},
                "ids:operator": {"@id": "idsc:BEFORE"},
                "ids:rightOperand": {
                    "@value": end_iso,
                    "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                }
            }
        ]
    }
    return json.dumps(permission)


def get_fixed_policy_rule():
    """Return the fixed policy rule for validation purposes."""
    return (
        '{\n'
        '    "@context": {\n'
        '        "ids": "https://w3id.org/idsa/core/",\n'
        '        "idsc": "https://w3id.org/idsa/code/"\n'
        '    },\n'
        '    "@type": "ids:Permission",\n'
        '    "@id": "https://w3id.org/idsa/autogen/permission/cf1cb758-b96d-4486-b0a7-f3ac0e289588",\n'
        '    "ids:action": [\n'
        '        {\n'
        '            "@id": "idsc:USE"\n'
        '        }\n'
        '    ],\n'
        '    "ids:description": [\n'
        '        {\n'
        '            "@value": "provide-access",\n'
        '            "@type": "http://www.w3.org/2001/XMLSchema#string"\n'
        '        }\n'
        '    ],\n'
        '    "ids:title": [\n'
        '        {\n'
        '            "@value": "Example Usage Policy",\n'
        '            "@type": "http://www.w3.org/2001/XMLSchema#string"\n'
        '        }\n'
        '    ]\n'
        '}'
    )


def get_license_choices():
    """Retrieve license choices for the form."""
    licenses = License.objects.all()
    return [(license.name, license.name) for license in licenses]


def generate_user_metadata(data, license_url):
    """Generate user metadata for the offer."""
    artifact = {
        'title': data.get('artifact_title', 'Not set'),
        'description': data.get('artifact_description', 'Not set'),
        'accessUrl': data.get('accessUrl', 'Not set'),
        'automatedDownload': data.get('automatedDownload', False),
    }
    # Forward auth fields if present
    for k in ('auth_type', 'auth_token', 'auth_username', 'auth_password'):
        if data.get(k):
            artifact[k] = data.get(k)
    return {
        'catalog': {
            'title': data.get('catalog_title', 'Not set'),
            'description': data.get('catalog_description', 'Not set'),
        },
        'representation': {
            'title': data.get('representation_title', 'Not set'),
            'description': data.get('representation_description', 'Not set'),
            'language': data.get('language', 'Not set'),
            'mediaType': 'text/html',
        },
        'offer': {
            'title': data.get('offer_title'),
            'description': data.get('offer_description'),
            'keywords': data.get('keywords'),
            'paymentMethod': 'undefined',
            'publisher': data.get('offer_publisher'),
            'language': data.get('offer_language'),
            'license': license_url,
        },
        'contract': {
            'title': data.get('contract_title', 'Not set'),
            'description': data.get('contract_description', 'Not set'),
            'start': data.get('start'),
            'end': data.get('end')
        },
        'rule': {
            'title': data.get('rule_title', 'Not set'),
            'description': data.get('rule_description', 'Not set'),
            'value': data.get('value')
        },
        'artifact': artifact
    }


# Views

def handle_metadata(request):
    """Handle incoming metadata and store in session."""
    if request.method == 'POST':
        try:
            metadata = json.loads(request.POST.get('metadata', '{}'))
            logger.debug("Received metadata payload for provide flow", extra={'payload': metadata})
            
            # Extract and store metadata in session
            offer_data = metadata.get('offer', {})
            access_rules = metadata.get('dataAccessRules', {})
            
            # Convert access dates to proper format if they are empty
            start_date = access_rules.get('accessStartDate', '')
            end_date = access_rules.get('accessEndDate', '')
            
            # If dates are empty, set default values (e.g., today and a month from today)
            from datetime import datetime, timedelta
            today = datetime.now()
            if not start_date:
                start_date = today.strftime('%Y-%m-%dT%H:%M')
            if not end_date:
                end_date = (today + timedelta(days=30)).strftime('%Y-%m-%dT%H:%M')
            start_date = truncate_to_minutes(start_date)
            end_date = truncate_to_minutes(end_date)
            policy_start = ensure_datetime_with_seconds(start_date)
            policy_end = ensure_datetime_with_seconds(end_date)
            
            # Create IDS-compliant permission policy based on the dates
            policy_value = build_between_dates_permission(policy_start, policy_end)
            
            initial_data = {
                'offer_title': offer_data.get('title', ''),
                'offer_description': offer_data.get('description', ''),
                'keywords': offer_data.get('keywords', ''),
                'offer_publisher': offer_data.get('publisher', ''),
                'offer_language': offer_data.get('language', ''),
                'accessUrl': offer_data.get('offerAccessUrl', ''),
                'start': start_date,
                'end': end_date,
                'access_policy': 'between_dates',  # Set the policy type
                'value': get_fixed_policy_rule(),  # use fixed policy for validation
                'auth_type': 'none'  # Default auth type
            }
            
            logger.info("Persisting initial provider metadata in session", extra={'offer_title': initial_data.get('offer_title')})
            request.session['initial_metadata'] = initial_data
            return redirect('provide:provide_offer')
            
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON metadata received for provide flow", exc_info=e)
            messages.error(request, 'Invalid metadata format received')
            return redirect('provide:provide_offer')
    return redirect('provide:provide_offer')

def provide_offer(request):
    """Provide an offer with metadata."""
    connector_url = settings.CONNECTOR_URL
    consumer_url = getattr(settings, 'DATA_SPACE_CONSUMER_SERVICE_URL', '')
    license_choices = get_license_choices()
    
    # Get initial data from session if available
    initial_data = request.session.pop('initial_metadata', {
        'offer_title': '',
        'offer_description': '',
        'keywords': '',
        'offer_publisher': '',
        'offer_language': '',
        'offer_license': '',
        'accessUrl': '',
        'start': '',
        'end': '',
        'value': '',
        'auth_type': 'none'
    })

    if request.method == 'POST':
        form = UploadMetadataForm(request.POST, license_choices=license_choices, request=request)
        if form.errors:
            logger.warning("Provide offer form validation errors", extra={'errors': form.errors})
        if form.is_valid():
            data = form.cleaned_data.copy()
            # Convert any datetime objects to ISO strings for session serialization
            for k, v in data.items():
                if hasattr(v, 'isoformat'):
                    data[k] = v.isoformat()
            # Override policy with fixed IDS permission for validation run
            data['value'] = get_fixed_policy_rule()
            # save the last successful metadata to session for publish fallback
            request.session['provide_last_metadata'] = data
            selected_license_name = data.get('offer_license')
            selected_license = License.objects.filter(name=selected_license_name).first()
            license_url = selected_license.access_url if selected_license else ""

            user_metadata = generate_user_metadata(data, license_url)
            logger.debug("Prepared user metadata for connector runner", extra={'offer_title': user_metadata['offer'].get('title')})

            result = runner(user_metadata)
            if result:
                logger.info("Offer successfully published to data space", extra={'offer_title': user_metadata['offer'].get('title')})
                messages.success(request, "The offer was successfully provided to the data space.")
            else:
                logger.error("Offer publishing failed according to connector runner", extra={'offer_title': user_metadata['offer'].get('title')})
                messages.error(request, "Something went wrong with providing the offer.")
        else:
            messages.error(request, "Form is invalid. Please correct the errors and try again.")
    else:
        # For GET requests, initialize form with data from session
        form = UploadMetadataForm(initial=initial_data, license_choices=license_choices, request=request)
        logger.debug("Loaded initial provider form data", extra={'session_keys': list(request.session.keys())})

    def field_value(field_name):
        try:
            return form[field_name].value()
        except KeyError:
            return ''

    keywords_raw = field_value('keywords') or ''
    keyword_list = [k.strip() for k in keywords_raw.split(',') if k.strip()]
    license_value = field_value('offer_license')
    license_label = next((label for value, label in license_choices if value == license_value), license_value or "Select a license")

    offer_snapshot = {
        'title': field_value('offer_title') or 'Untitled offer',
        'description': field_value('offer_description') or 'Add a friendly description to help consumers understand what they get.',
        'keywords': keyword_list,
        'publisher': field_value('offer_publisher'),
        'language': field_value('offer_language'),
        'license': license_label,
        'access_url': field_value('accessUrl'),
        'start': field_value('start'),
        'end': field_value('end'),
    }

    stage_sequence = [
        ("Create", "Sketch the idea"),
        ("Describe", "Add metadata & policy"),
        ("Publish", "Send to the connector"),
        ("Monitor", "Track usage & reassure"),
    ]
    current_stage_label = "Describe"
    current_index = next((idx for idx, (label, _) in enumerate(stage_sequence) if label == current_stage_label), 1)
    progress_steps = []
    for idx, (label, caption) in enumerate(stage_sequence):
        if idx < current_index:
            status = 'completed'
        elif idx == current_index:
            status = 'active'
        else:
            status = 'upcoming'
        progress_steps.append({
            'label': label,
            'caption': caption,
            'status': status
        })

    return render(request, 'provide/provide_offer.html', {
        'form': form,
        'licenses': License.objects.all(),
        'data_space_connector_url': connector_url,
        'data_space_consumer_url': consumer_url,
        'debug_metadata': initial_data,  # Pass to template for debugging
        'offer_snapshot': offer_snapshot,
        'progress_steps': progress_steps,
        'current_stage_label': current_stage_label,
        'license_choices': license_choices,
    })

# in provide/views.py

import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

@csrf_exempt
def test_access_endpoint(request):
    """
    Test the provided access URL with optional auth metadata.

    Returns JSON with a consistent schema:
      - success: {'status': 'success', ...}
      - error:   {'status': 'error', 'error': 'message'}
    """
    access_url = None
    auth_meta = {
        'auth_type': None,
        'auth_username': None,
        'auth_password': None,
        'auth_token': None,
    }

    try:
        # Support GET (query params) and POST (form)
        if request.method == 'GET':
            access_url = request.GET.get('accessUrl') or request.GET.get('accessurl')
            auth_meta.update({
                'auth_type': request.GET.get('auth_type'),
                'auth_username': request.GET.get('auth_username'),
                'auth_password': request.GET.get('auth_password'),
                'auth_token': request.GET.get('auth_token'),
            })
        elif request.method == 'POST':
            access_url = request.POST.get('accessUrl') or request.POST.get('accessurl')
            auth_meta.update({
                'auth_type': request.POST.get('auth_type'),
                'auth_username': request.POST.get('auth_username'),
                'auth_password': request.POST.get('auth_password'),
                'auth_token': request.POST.get('auth_token'),
            })
        else:
            return JsonResponse({'status': 'error', 'error': 'GET or POST required'}, status=400)

        if not access_url:
            return JsonResponse({'status': 'error', 'error': 'accessUrl is required'}, status=400)

        # Call the helper that actually hits the URL
        result = test_access_url(access_url, auth_meta)

        # Normalize result
        if result is None:
            logger.warning("test_access_url returned None for accessUrl=%s auth_meta=%s", access_url, auth_meta)
            return JsonResponse({'status': 'error', 'error': 'no response from target URL'}, status=502)

        if isinstance(result, dict):
            # If helper already returns a dict shaped like {status: 'success' | 'error', ...}
            # return it directly, but ensure we always have a status key
            if 'status' not in result:
                logger.warning("test_access_url returned dict without status for accessUrl=%s auth_meta=%s", access_url, auth_meta)
                result['status'] = 'success'
            return JsonResponse(result)
        else:
            logger.warning("test_access_url returned non-dict for accessUrl=%s auth_meta=%s", access_url, auth_meta)    
            # If helper returns a scalar or non-dict, wrap it
            return JsonResponse({'status': 'success', 'data': result})

    except Exception as exc:
        logger.exception("Error while testing access for %s", access_url)
        return JsonResponse({'status': 'error', 'error': str(exc)}, status=500)

def get_fixed_policy_rule():
    """Return the fixed policy rule for the offer."""
    return (
        '{\n'
        '    "@context": {\n'
        '        "ids": "https://w3id.org/idsa/core/",\n'
        '        "idsc": "https://w3id.org/idsa/code/"\n'
        '    },\n'
        '    "@type": "ids:Permission",\n'
        '    "@id": "https://w3id.org/idsa/autogen/permission/cf1cb758-b96d-4486-b0a7-f3ac0e289588",\n'
        '    "ids:action": [\n'
        '        {\n'
        '            "@id": "idsc:USE"\n'
        '        }\n'
        '    ],\n'
        '    "ids:description": [\n'
        '        {\n'
        '            "@value": "provide-access",\n'
        '            "@type": "http://www.w3.org/2001/XMLSchema#string"\n'
        '        }\n'
        '    ],\n'
        '    "ids:title": [\n'
        '        {\n'
        '            "@value": "Example Usage Policy",\n'
        '            "@type": "http://www.w3.org/2001/XMLSchema#string"\n'
        '        }\n'
        '    ]\n'
        '}'
    )


@csrf_exempt
def upload_view(request, file_id=None):
    """Handle file upload and retrieval."""
    if request.method == "POST":
        return handle_file_upload(request)
    elif request.method == "GET" and file_id:
        return handle_file_download(file_id)
    return JsonResponse({"error": "Invalid request"}, status=400)


def handle_file_upload(request):
    """Handle the file upload process, parse JSON, save data, and return API URL."""
    try:
        files = request.FILES.getlist("file")
        if not files:
            print("No file provided in request.FILES")
            return JsonResponse({"error": "No file provided"}, status=400)
        file_urls = []
        uploaded_data_instances = []
        for uploaded_file in files:
            print(f"Processing file: {uploaded_file.name}, content_type: {uploaded_file.content_type}")
            if uploaded_file.content_type not in ALLOWED_FILE_TYPES:
                print("Invalid file type: " + uploaded_file.content_type)
                return JsonResponse({"error": "Invalid file type. Only JSON files are allowed."}, status=400)

            if not os.path.exists(UPLOAD_DIR):
                os.makedirs(UPLOAD_DIR)

            file_instance = UploadedFile.objects.create(
                file=uploaded_file,
                file_name=uploaded_file.name
            )
            file_urls.append(request.build_absolute_uri(file_instance.file.url))
            # Parse JSON and save to UploadedData
            try:
                with open(file_instance.file.path, 'r', encoding='utf-8') as f:
                    file_data = f.read()
                json_data = json.loads(file_data)
            except Exception as e:
                print(f"Failed to parse JSON: {e}")
                return JsonResponse({"error": f"Failed to parse JSON: {str(e)}"}, status=400)

            if UploadedData is None:
                print("UploadedData model not found.")
                return JsonResponse({"error": "UploadedData model not found. Please add it to models.py."}, status=500)

            data_instance = UploadedData.objects.create(
                file=file_instance,
                data=json_data
            )
            uploaded_data_instances.append(data_instance)
        # Check for existing OfferAccess UUID in POST data
        from .models import OfferAccess
        offer_access_uuid = request.POST.get('offer_access_uuid')
        offer_access = None
        if offer_access_uuid:
            try:
                offer_access = OfferAccess.objects.get(uuid=offer_access_uuid)
                print(f"Reusing existing OfferAccess: {offer_access.uuid}")
            except OfferAccess.DoesNotExist:
                print(f"OfferAccess UUID {offer_access_uuid} not found, creating new OfferAccess.")
        if not offer_access:
            offer_access = OfferAccess.objects.create()
            offer_url = request.build_absolute_uri(reverse('provide:offer_access_api', args=[offer_access.uuid]))
            offer_access.url = offer_url
            offer_access.save()
        else:
            offer_url = offer_access.url
        offer_access.uploaded_data.add(*uploaded_data_instances)
        print(f"OfferAccess used: {offer_access.uuid}, url: {offer_url}")
        return JsonResponse({
            "message": "Files uploaded and data extracted successfully",
            "file_urls": file_urls,
            "offer_access_url": offer_url,
            "offer_access_uuid": str(offer_access.uuid)
        })
    except Exception as e:
        print(f"Unexpected error in handle_file_upload: {e}")
        return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)
# API endpoint to serve all data linked to an OfferAccess
@require_GET
@csrf_exempt
def offer_access_api(request, offer_uuid):
    from .models import OfferAccess
    try:
        offer_access = OfferAccess.objects.get(uuid=offer_uuid)
    except OfferAccess.DoesNotExist:
        return JsonResponse({"error": "OfferAccess not found."}, status=404)
    offer_url = offer_access.url
    all_data = [ud.data for ud in offer_access.uploaded_data.all()]
    return JsonResponse({"offer_access_url": offer_url, "data": all_data}, safe=False)
# Add REST API endpoint for extracted data
@require_GET
@csrf_exempt
def uploaded_data_api(request, data_id):
    """Serve extracted JSON data by unique ID."""
    if UploadedData is None:
        return JsonResponse({"error": "UploadedData model not found."}, status=500)
    try:
        data_instance = UploadedData.objects.get(id=data_id)
    except UploadedData.DoesNotExist:
        return JsonResponse({"error": "Data not found."}, status=404)
    return JsonResponse(data_instance.data, safe=False)


def handle_file_download(file_id):
    """Handle file download request."""
    file_instance = get_object_or_404(UploadedFile, id=file_id)
    with open(file_instance.file.path, 'rb') as f:
        file_data = f.read()

    response = HttpResponse(file_data, content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="{file_instance.file_name}"'
    return response
