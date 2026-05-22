# -*- coding: utf-8 -*-
{
    'name': "JSON/2 API – Odoo 19 Compatibility Layer",

    'summary': "Expone /json/2 y /jsonrpc2 compatibles con Odoo 19 en Odoo 16/17/18",

    'description': """
        Módulo que expone dos endpoints de API externos compatibles con
        el esquema de Odoo 19:

        1. **POST /json/2/<model>/<method>**
           - API REST moderna idéntica al /json/2 de Odoo 19.
           - Autenticación via ``Authorization: Bearer <api_key>``.
           - Base de datos via ``X-Odoo-Database`` (header HTTP).
           - Respuestas con códigos HTTP semánticos (200/400/401/403/404/500).

        2. **POST /jsonrpc2**
           - Capa de compatibilidad JSON-RPC 2.0 (envelope clásico).
           - Autenticación via credenciales en el body JSON.

        Seguridad:
        - Comparación de API keys con timing-safe hmac.compare_digest.
        - Keys almacenadas como hash SHA-256 (nunca en texto plano).
        - Expiración opcional de API keys.
        - Bloqueo de métodos privados (_method).
        - Logging y auditoría de todas las llamadas.
        - Límite de tamaño de cuerpo de petición (10 MB).
    """,

    'author': "David Carreres Gómez",
    'maintainer': "David Carreres Gómez",
    'website': "https://www.carreres.es/",
    'support': "david@carreres.es",

    'category': 'Technical',
    'version': '17.0.2.0.0',
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
