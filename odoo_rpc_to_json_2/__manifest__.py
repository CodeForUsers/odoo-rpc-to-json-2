# -*- coding: utf-8 -*-
{
    'name': "JSON/2 API – Odoo 19 Compatibility Layer",

    'summary': "Exposes Odoo 19 compatible /json/2 and /jsonrpc2 endpoints in Odoo 16/17/18 with advanced security",

    'description': """
        Module that exposes two external API endpoints compatible with 
        the Odoo 19 schema:

        1. **POST /json/2/<model>/<method>**
           - Modern REST API identical to Odoo 19's /json/2.
           - Authentication via ``Authorization: Bearer <api_key>``.
           - Database selection via ``X-Odoo-Database`` HTTP header.
           - Responses with semantic HTTP codes (200/400/401/403/404/429/500).

        2. **POST /jsonrpc2**
           - JSON-RPC 2.0 compatibility layer (classic envelope).
           - Authentication via credentials or API key in the JSON body.

        Security & Advanced Features:
        - API key comparison using timing-safe hmac.compare_digest with SHA-256 indexed lookup.
        - Granular model restriction per API key (allowed_model_ids).
        - Granular method restriction per API key (allowed_methods).
        - IP whitelisting with CIDR subnet support per API key (allowed_ips).
        - Configurable rate limiting per API key (rate_limit_requests).
        - Full CORS and OPTIONS preflight support for web dashboards and SPAs.
        - OpenAPI 3.0 specification endpoint (/json/2/openapi.json).
        - Postman Collection endpoint (/json/2/postman_collection.json).
        - Automated daily log cleanup action with configurable retention.
        - Blocking of private methods (_method).
        - Audit trail logging execution time (ms), caller IP, and error tracebacks.
    """,

    'author': "David Carreres Gómez",
    'maintainer': "David Carreres Gómez",
    'website': "https://www.carreres.es/",
    'support': "david@carreres.es",

    'category': 'Technical',
    'version': '18.0.2.1.0',
    'license': 'LGPL-3',

    'images': [
        'static/description/icon.png',
        'static/description/screenshot_api_keys.png',
        'static/description/screenshot_api_key_wizard.png',
        'static/description/screenshot_api_logs.png',
    ],

    'depends': ['base'],

    'data': [
        'security/jsonrpc2_security.xml',
        'security/ir.model.access.csv',
        'data/ir_cron_data.xml',
        'views/api_key_views.xml',
        'views/api_log_views.xml',
        'views/menu.xml',
    ],

    'installable': True,
    'application': False,
    'auto_install': False,
}
