# -*- coding: utf-8 -*-
"""
Controlador API JSON/2 compatible con Odoo 19 + JSON-RPC 2.0.

Expone:
  - POST /json/2/<model>/<method>       API REST Odoo 19
  - OPTIONS /json/2/<model>/<method>    Preflight CORS
  - POST /jsonrpc2                      Envolvente JSON-RPC 2.0
  - OPTIONS /jsonrpc2                   Preflight CORS
  - GET /json/2/docs                    Documentación interactiva y Swagger UI
  - GET /json/2/schema/<model>          Generación dinámica de esquema JSON por modelo
  - GET /json/2/models                  Lista de modelos accesibles
  - GET /json/2/openapi.json            Especificación OpenAPI 3.0 dinámica
  - GET /json/2/postman_collection.json Colección Postman v2.1
"""

import json
import logging
import os

from odoo import http
from odoo.http import request, Response

from ..services import jsonrpc2_service as svc

_logger = logging.getLogger(__name__)

# Tamaño máximo del cuerpo de la petición (10 MB por defecto)
MAX_BODY_BYTES = int(os.environ.get('JSONRPC2_MAX_BODY_BYTES', 10 * 1024 * 1024))

CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Odoo-Database, Accept',
    'Access-Control-Max-Age': '86400',
}


def _is_debug_mode(httprequest):
    """Detecta si el cliente solicitó depuración o el servidor está en modo debug."""
    return bool(request.session.debug if hasattr(request, 'session') else False)


def _get_client_ip(httprequest):
    """Obtiene la IP del cliente considerando cabeceras de proxy inverso."""
    forwarded = httprequest.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return httprequest.remote_addr or ''


class JsonOdoo19Controller(http.Controller):
    """Endpoint REST compatible con Odoo 19: POST /json/2/<model>/<method>"""

    @http.route(
        '/json/2/<string:model_name>/<string:method_name>',
        type='http',
        auth='none',
        methods=['POST', 'OPTIONS'],
        csrf=False,
        cors='*',
        save_session=False,
    )
    def json2_endpoint(self, model_name, method_name, **_kw):
        """Maneja peticiones REST /json/2/ y preflight OPTIONS."""
        if request.httprequest.method == 'OPTIONS':
            return Response(status=200, headers=CORS_HEADERS)

        client_ip = _get_client_ip(request.httprequest)

        content_length = request.httprequest.content_length
        if content_length and content_length > MAX_BODY_BYTES:
            return self._rest_error(
                413, 'builtins.ValueError',
                'Request body too large.', []
            )

        try:
            raw = request.httprequest.get_data(as_text=True)
            if len(raw.encode('utf-8')) > MAX_BODY_BYTES:
                return self._rest_error(
                    413, 'builtins.ValueError',
                    'Request body too large.', []
                )
            params = json.loads(raw) if raw.strip() else {}
        except (ValueError, TypeError) as exc:
            return self._rest_error(400, 'builtins.ValueError',
                                    f'Invalid JSON body: {exc}', [str(exc)])

        if not isinstance(params, dict):
            return self._rest_error(400, 'builtins.ValueError',
                                    'Request body must be a JSON object.', [])

        db, uid, auth_err = svc.authenticate_from_headers(
            request.httprequest.headers,
            client_ip=client_ip,
            model_name=model_name,
            method_name=method_name,
        )
        if auth_err:
            http_code, exc_name, err_msg = auth_err
            return self._rest_error(http_code, exc_name, err_msg, [err_msg])

        debug = _is_debug_mode(request.httprequest)
        result, exc_info = svc.execute_orm(
            db, uid, model_name, method_name, params, client_ip, debug
        )
        if exc_info is not None:
            http_code, exc_name, message, arguments, tb = exc_info
            error_body = {
                'name': exc_name,
                'message': message,
                'arguments': arguments,
                'context': {},
            }
            if debug and tb:
                error_body['debug'] = tb
            return self._rest_error_body(http_code, error_body)

        return self._rest_success(result)

    # ------------------------------------------------------------------
    # Documentación Interactiva & Esquemas Dinámicos
    # ------------------------------------------------------------------

    @http.route(
        '/json/2/docs',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
        save_session=False,
    )
    def api_documentation_ui(self, **_kw):
        """Página de documentación interactiva y explorador de APIs."""
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Odoo JSON/2 API Documentation & Explorer</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fafafa; }
        .topbar-custom { background: #111827; color: white; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
        .topbar-custom h1 { margin: 0; font-size: 20px; font-weight: 700; }
        .topbar-custom .links a { color: #a5b4fc; margin-left: 16px; text-decoration: none; font-size: 14px; font-weight: 600; }
        .topbar-custom .links a:hover { text-decoration: underline; }
        .schema-tester { max-width: 1200px; margin: 20px auto; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .schema-tester input, .schema-tester button { padding: 8px 12px; font-size: 14px; border: 1px solid #d1d5db; border-radius: 6px; }
        .schema-tester button { background: #2563eb; color: white; border: none; cursor: pointer; font-weight: 600; }
        .schema-tester button:hover { background: #1d4ed8; }
        #schema-output { margin-top: 15px; background: #111827; color: #e5e7eb; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 12px; max-height: 400px; overflow: auto; display: none; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="topbar-custom">
        <h1>Odoo JSON/2 API — Interactive Explorer</h1>
        <div class="links">
            <a href="/json/2/openapi.json" target="_blank">&#128196; OpenAPI 3.0 Spec</a>
            <a href="/json/2/postman_collection.json" target="_blank">&#128640; Postman Collection</a>
        </div>
    </div>

    <div class="schema-tester">
        <h3 style="margin-top: 0;">&#128269; Real-Time Model Schema Introspector</h3>
        <p style="color: #6b7280; font-size: 14px; margin-bottom: 12px;">Inspect fields, types, and sample payloads for any Odoo model in real time.</p>
        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <input type="text" id="model-input" placeholder="Model (e.g. res.partner, sale.order)" value="res.partner" style="flex: 1; min-width: 200px;">
            <input type="text" id="api-key-input" placeholder="API Key (jrpc2_...)" style="flex: 1; min-width: 250px;">
            <input type="text" id="db-input" placeholder="Database Name (optional)" style="width: 180px;">
            <button onclick="fetchSchema()">Inspect Model Schema</button>
        </div>
        <pre id="schema-output"></pre>
    </div>

    <div id="swagger-ui"></div>

    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/json/2/openapi.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ]
            });
        };

        async function fetchSchema() {
            const model = document.getElementById('model-input').value.trim();
            const apiKey = document.getElementById('api-key-input').value.trim();
            const db = document.getElementById('db-input').value.trim();
            const out = document.getElementById('schema-output');

            if (!model) { alert('Please enter a model name'); return; }
            out.style.display = 'block';
            out.textContent = 'Fetching schema for ' + model + '...';

            const headers = {};
            if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;
            if (db) headers['X-Odoo-Database'] = db;

            try {
                const res = await fetch('/json/2/schema/' + model, { headers: headers });
                const data = await res.json();
                out.textContent = JSON.stringify(data, null, 2);
            } catch (err) {
                out.textContent = 'Error: ' + err.message;
            }
        }
    </script>
</body>
</html>"""
        return Response(html_content, status=200, content_type='text/html; charset=utf-8')

    @http.route(
        '/json/2/schema/<string:model_name>',
        type='http',
        auth='none',
        methods=['GET', 'OPTIONS'],
        csrf=False,
        cors='*',
        save_session=False,
    )
    def model_schema_endpoint(self, model_name, **_kw):
        """Generación dinámica del esquema y metadatos de un modelo específico."""
        if request.httprequest.method == 'OPTIONS':
            return Response(status=200, headers=CORS_HEADERS)

        client_ip = _get_client_ip(request.httprequest)

        # Autenticación opcional o con clave
        db, uid, auth_err = svc.authenticate_from_headers(
            request.httprequest.headers,
            client_ip=client_ip,
            model_name=model_name,
            method_name='fields_get',
        )
        if auth_err:
            http_code, exc_name, err_msg = auth_err
            return self._rest_error(http_code, exc_name, err_msg, [err_msg])

        try:
            schema = svc.get_model_schema(db, uid, model_name)
            return self._rest_success(schema)
        except Exception as exc:
            return self._rest_error(400, 'builtins.ValueError', str(exc), [str(exc)])

    @http.route(
        '/json/2/models',
        type='http',
        auth='none',
        methods=['GET', 'OPTIONS'],
        csrf=False,
        cors='*',
        save_session=False,
    )
    def list_models_endpoint(self, **_kw):
        """Devuelve la lista de modelos accesibles."""
        if request.httprequest.method == 'OPTIONS':
            return Response(status=200, headers=CORS_HEADERS)

        client_ip = _get_client_ip(request.httprequest)
        db, uid, auth_err = svc.authenticate_from_headers(
            request.httprequest.headers,
            client_ip=client_ip,
        )
        if auth_err:
            http_code, exc_name, err_msg = auth_err
            return self._rest_error(http_code, exc_name, err_msg, [err_msg])

        try:
            models_list = svc.list_accessible_models(db, uid)
            return self._rest_success(models_list)
        except Exception as exc:
            return self._rest_error(500, 'builtins.Exception', str(exc), [str(exc)])

    @http.route(
        '/json/2/openapi.json',
        type='http',
        auth='none',
        methods=['GET', 'OPTIONS'],
        csrf=False,
        cors='*',
        save_session=False,
    )
    def openapi_spec(self, **_kw):
        """Devuelve la especificación OpenAPI 3.0 para los endpoints JSON/2."""
        if request.httprequest.method == 'OPTIONS':
            return Response(status=200, headers=CORS_HEADERS)

        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "Odoo JSON/2 API (Odoo 19 Compatibility Layer)",
                "description": "RESTful JSON API matching the Odoo 19 /json/2/ specification with Bearer token authentication.",
                "version": "2.1.0"
            },
            "servers": [{"url": "/"}],
            "components": {
                "securitySchemes": {
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "API-Key",
                        "description": "API Key token (e.g. jrpc2_...)"
                    },
                    "DatabaseHeader": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-Odoo-Database",
                        "description": "Target Odoo Database Name"
                    }
                }
            },
            "security": [
                {"BearerAuth": [], "DatabaseHeader": []}
            ],
            "paths": {
                "/json/2/{model}/{method}": {
                    "post": {
                        "summary": "Execute ORM method on Model",
                        "description": "Direct invocation of Odoo ORM methods (e.g. search_read, create, write, unlink).",
                        "parameters": [
                            {"name": "model", "in": "path", "required": True, "schema": {"type": "string"}},
                            {"name": "method", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "requestBody": {
                            "required": True,
                            "content": {"application/json": {"schema": {"type": "object"}}}
                        },
                        "responses": {
                            "200": {"description": "Successful ORM execution"},
                            "400": {"description": "Bad Request / Validation Error"},
                            "401": {"description": "Unauthorized / Invalid Key"},
                            "403": {"description": "Forbidden / Model or Method Restricted"},
                            "429": {"description": "Too Many Requests (Rate Limit Exceeded)"},
                            "500": {"description": "Internal Server Error"}
                        }
                    }
                },
                "/json/2/schema/{model}": {
                    "get": {
                        "summary": "Get dynamic JSON Schema for Model",
                        "description": "Returns field definitions, types, descriptions, and sample payloads for the given model.",
                        "parameters": [
                            {"name": "model", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {"description": "Model JSON schema and method definitions"}
                        }
                    }
                },
                "/json/2/models": {
                    "get": {
                        "summary": "List Accessible Models",
                        "description": "Returns all installed Odoo models available in this instance.",
                        "responses": {
                            "200": {"description": "List of models"}
                        }
                    }
                },
                "/jsonrpc2": {
                    "post": {
                        "summary": "JSON-RPC 2.0 Legacy Envelope",
                        "requestBody": {
                            "required": True,
                            "content": {"application/json": {"schema": {"type": "object"}}}
                        },
                        "responses": {
                            "200": {"description": "JSON-RPC 2.0 Response Envelope"}
                        }
                    }
                }
            }
        }
        return Response(
            json.dumps(spec, indent=2, ensure_ascii=False),
            status=200,
            headers={**CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8'}
        )

    @http.route(
        '/json/2/postman_collection.json',
        type='http',
        auth='none',
        methods=['GET', 'OPTIONS'],
        csrf=False,
        cors='*',
        save_session=False,
    )
    def postman_collection(self, **_kw):
        """Devuelve una colección de Postman v2.1 lista para importar."""
        if request.httprequest.method == 'OPTIONS':
            return Response(status=200, headers=CORS_HEADERS)

        collection = {
            "info": {
                "name": "Odoo JSON/2 API",
                "_postman_id": "odoo-json2-api-collection",
                "description": "Postman Collection for testing Odoo JSON/2 REST and JSON-RPC 2.0 endpoints.",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "variable": [
                {"key": "base_url", "value": "http://localhost:8069", "type": "string"},
                {"key": "api_key", "value": "jrpc2_your_api_key_here", "type": "string"},
                {"key": "database", "value": "your_db_name", "type": "string"}
            ],
            "item": [
                {
                    "name": "1. Search & Read Partners",
                    "request": {
                        "method": "POST",
                        "header": [
                            {"key": "Authorization", "value": "Bearer {{api_key}}", "type": "text"},
                            {"key": "X-Odoo-Database", "value": "{{database}}", "type": "text"},
                            {"key": "Content-Type", "value": "application/json", "type": "text"}
                        ],
                        "body": {
                            "mode": "raw",
                            "raw": "{\n  \"domain\": [[\"is_company\", \"=\", true]],\n  \"fields\": [\"name\", \"email\", \"phone\"],\n  \"limit\": 5\n}"
                        },
                        "url": {"raw": "{{base_url}}/json/2/res.partner/search_read"}
                    }
                },
                {
                    "name": "2. Create Partner",
                    "request": {
                        "method": "POST",
                        "header": [
                            {"key": "Authorization", "value": "Bearer {{api_key}}", "type": "text"},
                            {"key": "X-Odoo-Database", "value": "{{database}}", "type": "text"},
                            {"key": "Content-Type", "value": "application/json", "type": "text"}
                        ],
                        "body": {
                            "mode": "raw",
                            "raw": "{\n  \"name\": \"Integration Partner Corp\",\n  \"email\": \"api@example.com\"\n}"
                        },
                        "url": {"raw": "{{base_url}}/json/2/res.partner/create"}
                    }
                },
                {
                    "name": "3. Inspect Model Schema",
                    "request": {
                        "method": "GET",
                        "header": [
                            {"key": "Authorization", "value": "Bearer {{api_key}}", "type": "text"},
                            {"key": "X-Odoo-Database", "value": "{{database}}", "type": "text"}
                        ],
                        "url": {"raw": "{{base_url}}/json/2/schema/res.partner"}
                    }
                },
                {
                    "name": "4. JSON-RPC 2.0 Envelope",
                    "request": {
                        "method": "POST",
                        "header": [
                            {"key": "Content-Type", "value": "application/json", "type": "text"}
                        ],
                        "body": {
                            "mode": "raw",
                            "raw": "{\n  \"jsonrpc\": \"2.0\",\n  \"method\": \"call\",\n  \"id\": 1,\n  \"params\": {\n    \"db\": \"{{database}}\",\n    \"api_key\": \"{{api_key}}\",\n    \"model\": \"res.partner\",\n    \"method\": \"search_read\",\n    \"args\": [[]],\n    \"kwargs\": {\"fields\": [\"name\"], \"limit\": 5}\n  }\n}"
                        },
                        "url": {"raw": "{{base_url}}/jsonrpc2"}
                    }
                }
            ]
        }
        return Response(
            json.dumps(collection, indent=2, ensure_ascii=False),
            status=200,
            headers={**CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8'}
        )

    # ------------------------------------------------------------------
    # Auxiliares de respuesta
    # ------------------------------------------------------------------

    @staticmethod
    def _rest_success(data):
        body = json.dumps(data, default=str, ensure_ascii=False)
        return Response(
            body,
            status=200,
            headers={**CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8'}
        )

    @staticmethod
    def _rest_error(status, exc_name, message, arguments, debug_tb=None):
        body = {
            'name': exc_name,
            'message': message,
            'arguments': arguments,
            'context': {},
        }
        if debug_tb:
            body['debug'] = debug_tb
        return Response(
            json.dumps(body, ensure_ascii=False),
            status=status,
            headers={**CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8'}
        )

    @staticmethod
    def _rest_error_body(status, body):
        return Response(
            json.dumps(body, ensure_ascii=False),
            status=status,
            headers={**CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8'}
        )


class JsonRpc2LegacyController(http.Controller):
    """Endpoint envolvente JSON-RPC 2.0: POST /jsonrpc2"""

    @http.route(
        '/jsonrpc2',
        type='http',
        auth='none',
        methods=['POST', 'OPTIONS'],
        csrf=False,
        cors='*',
        save_session=False,
    )
    def jsonrpc2_endpoint(self, **_kw):
        """Maneja peticiones JSON-RPC 2.0 y preflight OPTIONS."""
        if request.httprequest.method == 'OPTIONS':
            return Response(status=200, headers=CORS_HEADERS)

        client_ip = _get_client_ip(request.httprequest)

        content_length = request.httprequest.content_length
        if content_length and content_length > MAX_BODY_BYTES:
            return self._json_response(
                svc.build_error_response(svc.INVALID_REQUEST,
                                         'Request body too large.'))

        try:
            raw = request.httprequest.get_data(as_text=True)
            if len(raw.encode('utf-8')) > MAX_BODY_BYTES:
                return self._json_response(
                    svc.build_error_response(svc.INVALID_REQUEST,
                                             'Request body too large.'))
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            _logger.warning('JSON-RPC 2.0: malformed JSON body – %s', exc)
            return self._json_response(
                svc.build_error_response(svc.PARSE_ERROR,
                                          'Parse error: invalid JSON.'))

        if isinstance(payload, list):
            return self._handle_batch(payload, client_ip)
        return self._handle_single(payload, client_ip)

    def _handle_single(self, payload, client_ip):
        ok, err = svc.validate_request(payload)
        if not ok:
            return self._json_response(err)
        debug = _is_debug_mode(request.httprequest)
        return self._json_response(
            svc.dispatch(payload, client_ip=client_ip, debug=debug)
        )

    def _handle_batch(self, payloads, client_ip):
        if not payloads:
            return self._json_response(
                svc.build_error_response(svc.INVALID_REQUEST,
                                          'Batch request must not be empty.'))
        results = []
        debug = _is_debug_mode(request.httprequest)
        for payload in payloads:
            if not isinstance(payload, dict):
                results.append(svc.build_error_response(
                    svc.INVALID_REQUEST,
                    'Each batch item must be a JSON object.'))
                continue
            ok, err = svc.validate_request(payload)
            if not ok:
                results.append(err)
                continue
            results.append(svc.dispatch(payload, client_ip=client_ip, debug=debug))
        return self._json_response(results)

    @staticmethod
    def _json_response(data, status=200):
        body = json.dumps(data, default=str, ensure_ascii=False)
        return Response(
            body,
            status=status,
            headers={**CORS_HEADERS, 'Content-Type': 'application/json; charset=utf-8'}
        )
