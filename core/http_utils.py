import logging


def _body_preview(response, limit=200):
    content = response.content or b""
    return content[:limit].decode("utf-8", errors="replace")


def parse_json_response(response, *, expected_statuses=None, logger_obj=None, context="HTTP response"):
    """
    Safely parse JSON only when status and content-type are appropriate.
    Returns (payload, error_message). payload is None on any validation/parsing failure.
    """
    log = logger_obj or logging.getLogger(__name__)
    status_code = getattr(response, "status_code", None)
    headers = dict(getattr(response, "headers", {}) or {})
    content_type = (headers.get("Content-Type") or headers.get("content-type") or "").lower()

    if expected_statuses is not None and status_code not in set(expected_statuses):
        preview = _body_preview(response)
        log.warning(
            "%s returned unexpected status=%s content-type=%s headers=%s body_preview=%r",
            context,
            status_code,
            content_type,
            headers,
            preview,
        )
        return None, f"unexpected_status_{status_code}"

    if "json" not in content_type:
        preview = _body_preview(response)
        log.warning(
            "%s returned non-JSON content-type=%s status=%s headers=%s body_preview=%r",
            context,
            content_type or "<missing>",
            status_code,
            headers,
            preview,
        )
        return None, "invalid_content_type"

    try:
        return response.json(), None
    except ValueError:
        preview = _body_preview(response)
        log.warning(
            "%s JSON parse failed status=%s content-type=%s headers=%s body_preview=%r",
            context,
            status_code,
            content_type,
            headers,
            preview,
        )
        return None, "invalid_json"
