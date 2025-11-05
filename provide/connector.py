import logging
from django.http import JsonResponse
import requests
import urllib3
from datetime import datetime, timezone
import urllib.parse
from django.conf import settings 


connector_url = settings.CONNECTOR_URL

logger = logging.getLogger(__name__)


def convert_date_format(date_str):
    if isinstance(date_str, datetime):
        date_object = date_str
    else:
        try:
            # Try full ISO 8601 parsing (Python 3.7+)
            date_object = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            try:
                # Fallback: try without seconds
                date_object = datetime.strptime(date_str, "%Y-%m-%dT%H:%M")
                date_object = date_object.replace(tzinfo=timezone.utc)
            except Exception as e:
                logger.error("Invalid date format provided to connector", extra={'input': date_str}, exc_info=e)
                raise ValueError("Invalid date format")
    # Always output in connector format: YYYY-MM-DDTHH:MM:SS.sss+0000
    formatted_date_str = date_object.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    return formatted_date_str

def _build_auth_components(auth_meta):
    """Return (auth_header_dict, requests_auth) tuple based on auth_meta."""
    if not auth_meta:
        return {}, None
    auth_type = auth_meta.get('auth_type')
    headers = {}
    auth = None
    if auth_type == 'basic':
        username = auth_meta.get('auth_username')
        password = auth_meta.get('auth_password')
        from requests.auth import HTTPBasicAuth
        auth = HTTPBasicAuth(username, password)
    elif auth_type == 'bearer':
        token = auth_meta.get('auth_token')
        headers['Authorization'] = f'Bearer {token}'
    return headers, auth


def make_request(url, headers=None, body=None, method='post', auth_meta=None):
    try:
        auth_headers, auth_obj = _build_auth_components(auth_meta)
        final_headers = dict(headers or {})
        final_headers.update(auth_headers)
        # Determine SSL verification behavior from settings
        verify_ssl = bool(getattr(settings, 'ENFORCE_CONNECTOR_SSL', True))
        if not verify_ssl:
            # Suppress noisy urllib3 insecure request warnings when verification is intentionally disabled
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if method.lower() == 'get':
            logger.debug("Dispatching connector GET request", extra={'url': url})
            response = requests.get(url, headers=final_headers, params=body, auth=auth_obj, verify=verify_ssl)
        else:
            logger.debug("Dispatching connector POST request", extra={'url': url})
            response = requests.post(url, headers=final_headers, json=body, auth=auth_obj, verify=verify_ssl)
        try:
            response_json = response.json()
        except ValueError:
            response_json = None
        if response.status_code in [200, 201]:
            logger.debug("Connector request succeeded", extra={'url': url, 'status_code': response.status_code})
            return {
                'status': 'success',
                'data': response_json
            }
        else:
            logger.warning(
                "Connector request returned non-success status",
                extra={'url': url, 'status_code': response.status_code, 'reason': response.reason}
            )
            return {
                'status': 'error',
                'status_code': response.status_code,
                'reason': response.reason,
                'data': response_json,
                'text': response.text
            }
    except requests.RequestException as e:
        logger.exception("Connector request failed", extra={'url': url})
        return {
            'status': 'error',
            'message': str(e)
        }


def test_access_url(access_url, auth_meta=None, timeout=10, method='get'):
    """Perform a lightweight request to the access_url using the provided auth metadata.
    Returns a dict with status and minimal response info.
    """
    try:
        headers, auth = _build_auth_components(auth_meta)
        # perform a GET request by default
        verify_ssl = bool(getattr(settings, 'ENFORCE_CONNECTOR_SSL', True))
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = requests.request(method.upper(), access_url, headers=headers, auth=auth, timeout=timeout, verify=verify_ssl)
        try:
            data = resp.json()
        except ValueError:
            data = None
        # Include ssl_verified in response so caller knows whether verification was used
        result = {'status_code': resp.status_code, 'reason': resp.reason, 'data': data, 'ssl_verified': verify_ssl}
        if resp.status_code >= 200 and resp.status_code < 300:
            result.update({'status': 'success'})
            return result
        else:
            result.update({'status': 'error', 'text': resp.text})
            return result
    except requests.RequestException as e:
        return {'status': 'error', 'message': str(e), 'ssl_verified': getattr(settings, 'ENFORCE_CONNECTOR_SSL', True)}

def create_catalog(metadata):
    url = settings.CONNECTOR_URL.rstrip('/') + '/api/catalogs'
    logger.info("Creating catalog in connector", extra={'url': url, 'title': metadata.get("title")})
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    title = metadata.get("title")
    description = metadata.get("description")

    data = {
        "title": title,
        "description": description 
    }
    return make_request(url, headers=headers, body=data)

def create_representation(metadata):
    url = settings.CONNECTOR_URL.rstrip('/') + '/api/representations'
    logger.info("Creating representation in connector", extra={'url': url, 'title': metadata.get("title")})
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    title = metadata.get("title")
    description = metadata.get("description")
    language = metadata.get("language")
    mediaType = metadata.get("mediaType")
    data = {
        "title": title,
        "description": description,
        "language": language,
        "mediaType": mediaType
    }
    return make_request(url, headers=headers, body=data)


def create_offer(metadata):
    url = settings.CONNECTOR_URL.rstrip('/') + '/api/offers'
    logger.info("Creating offer in connector", extra={'url': url, 'title': metadata.get("title")})
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    title = metadata.get("title")
    description = metadata.get("description")
    keywords = metadata.get("keywords")
    keywords_list = keywords.split(',')
    license = metadata.get("license")
    publisher = metadata.get("publisher")
    
    paymentMethod = metadata.get("paymentMethod")
    data = {
        "title": title,
        "description": description,
        "keywords": keywords_list,
        "paymentMethod": paymentMethod,  # TODO: paymentMethod 'free' or 'undefined'
        "license": license,
        "publisher": publisher
    }
    return make_request(url, headers=headers, body=data)


def _build_self_link(entity, identifier):
    """Construct connector self link for a given entity using its identifier or URL."""
    base = settings.CONNECTOR_URL.rstrip('/')
    if not identifier:
        return None
    if isinstance(identifier, str) and identifier.startswith('http'):
        return identifier
    return f"{base}/api/{entity}/{identifier}"


def add_resource_to_catalog(created_catalog_id, created_resource_id):
    url = f"{settings.CONNECTOR_URL.rstrip('/')}/api/catalogs/{created_catalog_id}/offers"
    logger.debug(
        "Linking offer to catalog",
        extra={'catalog_id': created_catalog_id, 'resource_ref': created_resource_id}
    )
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    offer_ref = _build_self_link('offers', created_resource_id)
    data = [offer_ref] if offer_ref else []
    return make_request(url, headers=headers, body=data)

def add_representation_to_resource(created_resource_id, created_representation_id):
    url = f"{settings.CONNECTOR_URL.rstrip('/')}/api/offers/{created_resource_id}/representations"
    logger.debug(
        "Linking representation to offer",
        extra={'offer_id': created_resource_id, 'representation_ref': created_representation_id}
    )
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    representation_ref = _build_self_link('representations', created_representation_id)
    data = [representation_ref] if representation_ref else []
    return  make_request(url, headers=headers, body=data)

def create_contract(metadata):
    url = settings.CONNECTOR_URL.rstrip('/') + '/api/contracts'
    logger.info("Creating contract in connector", extra={'url': url, 'title': metadata.get("title")})
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    title = metadata.get("title")
    description = metadata.get("description")
    start = metadata.get("start")
    end = metadata.get("end")
    data = {
        "title": title,
        "description": description,
        "start": convert_date_format(start), 
        "end": convert_date_format(end)  
    }

    return  make_request(url, headers=headers, body=data)

def create_rule(metadata):
    url = settings.CONNECTOR_URL.rstrip('/') + '/api/rules'
    logger.info("Creating rule in connector", extra={'url': url, 'title': metadata.get("title")})
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    title = metadata.get("title")
    description = metadata.get("description")
    policy = metadata.get("value")

    data = {
        "title": title,
        "description": description,
        "value": policy
    }
    
    return  make_request(url, headers=headers, body=data)

def add_rule_to_contract(created_contract_id, created_rule_id):
    url = f"{settings.CONNECTOR_URL.rstrip('/')}/api/contracts/{created_contract_id}/rules"
    logger.debug(
        "Linking rule to contract",
        extra={'contract_id': created_contract_id, 'rule_ref': created_rule_id}
    )
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    rule_ref = _build_self_link('rules', created_rule_id)
    data = [rule_ref] if rule_ref else []

    return  make_request(url, headers=headers, body=data)

def add_contract_to_resource(created_resource_id, created_contract_id):
    url = f"{settings.CONNECTOR_URL.rstrip('/')}/api/offers/{created_resource_id}/contracts"
    logger.debug(
        "Linking contract to offer",
        extra={'offer_id': created_resource_id, 'contract_ref': created_contract_id}
    )
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    contract_ref = _build_self_link('contracts', created_contract_id)
    data = [contract_ref] if contract_ref else []
    return  make_request(url, headers=headers, body=data)

def create_artifact(metadata):
    url = settings.CONNECTOR_URL.rstrip('/') + '/api/artifacts'
    logger.info("Creating artifact in connector", extra={'url': url, 'title': metadata.get("title")})
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    title = metadata.get("title")
    description = metadata.get("description")
    accessUrl = metadata.get("accessUrl")
    logger.debug(
        "Preparing artifact metadata for connector",
        extra={'title': title, 'access_url': accessUrl, 'auth_type': metadata.get('auth_type')}
    )
    automatedDownload = metadata.get("automatedDownload")
    data = {
        "title": title,
        "description": description,
        "accessUrl": accessUrl,
        "automatedDownload": automatedDownload
    }
    # If Bearer token is present, add apiKey field
    if metadata.get('auth_type') == 'bearer' and metadata.get('auth_token'):
        data['apiKey'] = {
            "key": "Authorization",
            "value": f"Bearer {metadata.get('auth_token')}"
        }
    # If Basic auth is present, optionally add apiKey (not standard, but for completeness)
    if metadata.get('auth_type') == 'basic' and metadata.get('auth_username') and metadata.get('auth_password'):
        import base64
        user = metadata.get('auth_username')
        pw = metadata.get('auth_password')
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        data['apiKey'] = {
            "key": "Authorization",
            "value": f"Basic {token}"
        }
    # forward any auth metadata if present so artifact can carry access credentials
    if metadata.get('auth'):
        data['auth'] = metadata.get('auth')
    # legacy fields
    for k in ('auth_type', 'auth_username', 'auth_password', 'auth_token'):
        if metadata.get(k):
            data[k] = metadata.get(k)
    
    return  make_request(url, headers=headers, body=data)

def add_artifact_to_representation(created_representation_id, created_artifact_id):
    url = f"{settings.CONNECTOR_URL.rstrip('/')}/api/representations/{created_representation_id}/artifacts"
    logger.debug(
        "Linking artifact to representation",
        extra={'representation_id': created_representation_id, 'artifact_ref': created_artifact_id}
    )
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
    }
    artifact_ref = _build_self_link('artifacts', created_artifact_id)
    data = [artifact_ref] if artifact_ref else []
    return  make_request(url, headers=headers, body=data)

def process_creation(create_function, metadata, name):
    result = create_function(metadata)
    status = result.get('status')
    logger.debug("Connector creation response received", extra={'entity': name, 'status': status})

    # Initialize variables to avoid UnboundLocalError
    url = None
    item_id = None

    # Check if creation was successful
    if result.get('status') == 'success':
        data = result.get('data', {})
        # Extract and print URL and ID
        url = data.get('_links', {}).get('self', {}).get('href')
        if url:
            item_id = url.split('/')[-1]
            logger.info("Connector entity created", extra={'entity': name, 'id': item_id})
        else:
            logger.warning("Connector response missing expected self link", extra={'entity': name})
    else:
        logger.error("Connector entity creation failed", extra={'entity': name, 'response': result})
    
    # Final check
    if url and item_id:
        logger.debug("Connector entity identifiers validated", extra={'entity': name, 'id': item_id})
    else:
        logger.warning("Connector entity identifiers missing", extra={'entity': name})
    return url, item_id

def process_addition(operation_name, add_function, *args):
    result = add_function(*args)
    status = result.get('status')
    logger.debug("Connector relation update result", extra={'operation': operation_name, 'status': status})
    return status


def runner(user_metadata):
    logger.info(
        "Starting connector provisioning run",
        extra={'offer_title': user_metadata.get('offer', {}).get('title')}
    )
    # Catalog
    catalog_metadata = user_metadata.get('catalog', {})
    created_catalog_url, created_catalog_id = process_creation(create_catalog, catalog_metadata, "Catalog")
    

    # Representation
    representation_metadata = user_metadata.get('representation', {})
    created_representation_url, created_representation_id = process_creation(create_representation, representation_metadata, "Representation")
    
    
    # Offer
    offer_metadata = user_metadata.get('offer', {})
    created_resource_url, created_resource_id = process_creation(create_offer, offer_metadata, "Offer")

    # Adding Resource to Catalog
    process_addition("Add Resource to Catalog", add_resource_to_catalog, created_catalog_id, created_resource_id)
  
    # Adding Representation to Resource
    process_addition("Add Representation to Resource", add_representation_to_resource, created_resource_id, created_representation_id)

    # Contract
    contract_metadata = user_metadata.get('contract', {})
    created_contract_url, created_contract_id = process_creation(create_contract, contract_metadata, "Contract")

    # Rule
    rule_metadata = user_metadata.get('rule', {})
    created_rule_url, created_rule_id = process_creation(create_rule, rule_metadata, "Rule")

    # Adding rule to contract
    process_addition("Add Rule to Contract", add_rule_to_contract, created_contract_id, created_rule_id)

    # Adding contract to resource
    process_addition("Add Contract to Resource", add_contract_to_resource, created_resource_id, created_contract_id)
    
    # Artifact
    artifact_metadata = user_metadata.get('artifact', {})
    created_artifact_url, created_artifact_id = process_creation(create_artifact, artifact_metadata, "Artifact")

    # Adding artifact to representation
    
    offer_created_successfully = process_addition("Add Artifact to Representation", add_artifact_to_representation, created_representation_id, created_artifact_id)
    
    if offer_created_successfully == 'success':
        logger.info(
            "Provisioning workflow completed successfully",
            extra={'offer_id': created_resource_id}
        )
        return True
    else:
        logger.error(
            "Provisioning workflow failed during artifact linkage",
            extra={'offer_id': created_resource_id}
        )
        return False
