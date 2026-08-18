"""
core/signatures.py — Product Content-Signature Registry
=========================================================
Maps probe paths / product names to required content markers.
A response must match at least ONE marker from must_contain to be reported as
a genuine product finding (as opposed to a 200-OK SPA catch-all).

Usage:
    from scanners.core.signatures import matches_signature
    if not matches_signature("jenkins", body, headers):
        return  # not really Jenkins
"""

# Registry: key -> {"must_contain": [...], "must_contain_header": [...optional...]}
# must_contain: any ONE of these strings must appear in the response body (case-insensitive)
# must_contain_header: any ONE of these must appear in response headers (key:value prefix)
SIGNATURES: dict[str, dict] = {
    # ── CI/CD ────────────────────────────────────────────────────────────
    "jenkins": {
        "must_contain": [
            "Dashboard [Jenkins]",
            "X-Jenkins",
            "Jenkins</title>",
            "jenkins.js",
            "plugin/credentials",
        ],
        "must_contain_header": ["x-jenkins:"],
    },
    "gitlab": {
        "must_contain": [
            "GitLab",
            "gitlab-rails",
            "users/sign_in",
            "gl-field-error",
        ],
    },
    "sonarqube": {
        "must_contain": [
            "SonarQube",
            "sonar-ws.js",
            "sonar.js",
        ],
    },
    # ── Monitoring / Observability ────────────────────────────────────────
    "grafana": {
        "must_contain": [
            "grafana",
            "GrafanaTheme",
            "grafana-login",
            "Grafana</title>",
        ],
    },
    "kibana": {
        "must_contain": [
            "kibana",
            "kbn-",
            "Elastic",
        ],
        "must_contain_header": ["kbn-name:"],
    },
    "prometheus": {
        "must_contain": [
            "Prometheus",
            "prometheus_",
            "# HELP",
            "# TYPE",
        ],
    },
    # ── Databases ─────────────────────────────────────────────────────────
    "phpmyadmin": {
        "must_contain": [
            "phpMyAdmin",
            "pma_",
            "phpmyadmin",
        ],
    },
    "adminer": {
        "must_contain": [
            "Adminer",
            "adminer",
            "db_select",
        ],
    },
    "elasticsearch": {
        "must_contain": [
            '"cluster_name"',
            '"number_of_nodes"',
            '"status"',
            'tagline',
        ],
    },
    # ── Spring / Java ─────────────────────────────────────────────────────
    "spring_actuator": {
        "must_contain": [
            '"status"',
            '"components"',
            '"diskSpace"',
            '"ping"',
        ],
    },
    "spring_actuator_env": {
        "must_contain": [
            '"activeProfiles"',
            '"propertySources"',
            '"systemProperties"',
        ],
    },
    # ── PHP Tooling ───────────────────────────────────────────────────────
    "phpinfo": {
        "must_contain": [
            "phpinfo()",
            "PHP Version",
            "php.ini",
            "PHP Extension",
        ],
    },
    # ── WordPress ─────────────────────────────────────────────────────────
    "wp_login": {
        "must_contain": [
            "wp-submit",
            "wp-login",
            "WordPress",
            "user_login",
        ],
    },
    "wp_config": {
        "must_contain": [
            "DB_NAME",
            "DB_PASSWORD",
            "DB_HOST",
            "define(",
        ],
    },
    "wp_xmlrpc": {
        "must_contain": [
            "XML-RPC server accepts POST requests only",
            "xmlrpc",
        ],
    },
    # ── API Documentation ─────────────────────────────────────────────────
    "swagger_ui": {
        "must_contain": [
            "swagger-ui",
            "SwaggerUI",
            "Swagger UI",
            "api-docs",
        ],
    },
    "openapi_spec": {
        "must_contain": [
            '"swagger"',
            '"openapi"',
            '"paths"',
        ],
    },
    "redoc": {
        "must_contain": [
            "ReDoc",
            "redoc",
        ],
    },
    # ── Source Control ────────────────────────────────────────────────────
    "git_head": {
        "must_contain": [
            "ref: refs/heads/",
        ],
    },
    "git_config": {
        "must_contain": [
            "[core]",
            "[remote",
            "repositoryformatversion",
        ],
    },
    "env_file": {
        "must_contain": [
            "=",  # at least one KEY=VALUE line
        ],
        "_min_matches": 2,  # require 2+ KEY=VALUE patterns (avoid single-line pages)
    },
    # ── Containers / Infra ────────────────────────────────────────────────
    "portainer": {
        "must_contain": [
            "Portainer",
            "portainer",
        ],
    },
    "kubernetes_dashboard": {
        "must_contain": [
            "Kubernetes Dashboard",
            "kube-dashboard",
        ],
    },
    # ── Messaging ─────────────────────────────────────────────────────────
    "rabbitmq": {
        "must_contain": [
            "RabbitMQ",
            "rabbitmq",
        ],
    },
    # ── Generic Admin ─────────────────────────────────────────────────────
    "generic_admin_form": {
        "must_contain": [
            "<form",
            "password",
        ],
        "_all_required": True,  # ALL must_contain must be present
    },
}


def matches_signature(
    sig_key: str,
    body: str,
    headers: dict | None = None,
    *,
    log_fn=None,
    url: str = "",
) -> bool:
    """
    Return True if `body` (and optionally `headers`) satisfy the signature for `sig_key`.

    Args:
        sig_key:   Key in SIGNATURES dict.
        body:      Response body text.
        headers:   Optional dict of response headers (lowercase keys preferred).
        log_fn:    Optional callable(msg) for debug logging of rejections.
        url:       URL being probed (for logging only).

    Returns:
        True  → response contains the product signature → report it.
        False → response does NOT match → suppress (log at DEBUG).
    """
    sig = SIGNATURES.get(sig_key)
    if not sig:
        # No signature defined for this key → pass through (don't suppress).
        return True

    body_lower = body.lower()
    must_contain = sig.get("must_contain", [])
    must_contain_header = sig.get("must_contain_header", [])
    all_required = sig.get("_all_required", False)
    min_matches = sig.get("_min_matches", 1)

    # ── Header check ──────────────────────────────────────────────────────
    if must_contain_header and headers:
        hdrs_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        for hdr_prefix in must_contain_header:
            hdr_key = hdr_prefix.rstrip(":").lower()
            if hdr_key in hdrs_lower:
                return True  # Header match is sufficient

    # ── Body check ────────────────────────────────────────────────────────
    if all_required:
        matched = all(term.lower() in body_lower for term in must_contain)
    else:
        matched_count = sum(1 for term in must_contain if term.lower() in body_lower)
        matched = matched_count >= min_matches

    if not matched:
        if log_fn:
            log_fn(
                f"[Signatures] SUPPRESSED {url!r}: 200 but no {sig_key!r} signature "
                f"(checked {len(must_contain)} markers)"
            )
        return False

    return True
