# -*- coding: utf-8 -*-
{
    'name': "JSON/2 API – Odoo 19 Compatibility Layer",

    'summary': "Exposes Odoo 19 compatible /json/2 and /jsonrpc2 endpoints in Odoo 16/17/18",

    'description': """
        Module that exposes two external API endpoints compatible with 
        the Odoo 19 schema:

        1. **POST /json/2/<model>/<method>**
           - Modern REST API identical to Odoo 19's /json/2.
           - Authentication via ``Authorization: Bearer <api_key>``.
           - Database selection via ``X-Odoo-Database`` HTTP header.
           - Responses with semantic HTTP codes (200/400/401/403/404/500).

        2. **POST /jsonrpc2**
           - JSON-RPC 2.0 compatibility layer (classic envelope).
           - Authentication via credentials in the JSON body.

        Security:
        - API key comparison using timing-safe hmac.compare_digest.
        - Keys stored as SHA-256 hash (never in plain text).
        - Optional API key expiration.
        - Blocking of private methods (_method).
        - Logging and auditing of all requests.
        - Request body size limit (10 MB).
    """,

    'author': "David Carreres Gómez",
    'maintainer': "David Carreres Gómez",
    'website': "https://www.carreres.es/",
    'support': "david@carreres.es",

    'category': 'Technical',
    'version': '16.0.2.0.1',
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
        'views/api_key_views.xml',
        'views/api_log_views.xml',
        'views/menu.xml',
    ],

    'installable': True,
    'application': False,
    'auto_install': False,
}
