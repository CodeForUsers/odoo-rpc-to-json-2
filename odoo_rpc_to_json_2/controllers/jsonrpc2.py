# -*- coding: utf-8 -*-
"""
Controlador API JSON/2 compatible con Odoo 19 + JSON-RPC 2.0.

Expone:
  - POST /json/2/<model>/<method>       API REST Odoo 19
  - OPTIONS /json/2/<model>/<method>    Preflight CORS
  - POST /jsonrpc2                      Envolvente JSON-RPC 2.0
  - OPTIONS /jsonrpc2                   Preflight CORS
  - GET /json/2/openapi.json            Especificación OpenAPI 3.0
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
        # -- Preflight CORS -----------------------------------------------
        if request.httprequest.method == 'OPTIONS':
            return Response(status=200, headers=CORS_HEADERS)

        client_ip = _get_client_ip(request.httprequest)

        # -- Guardia de Content-Length ------------------------------------
        content_length = request.httprequest.content_length
        if content_length and content_length > MAX_BODY_BYTES:
            return self._rest_error(
                413, 'builtins.ValueError',
                'Request body too large.', []
            )

        # -- Parsear cuerpo -----------------------------------------------
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

        # -- Autenticación vía cabecera Bearer + X-Odoo-Database ----------
        db, uid, auth_err = svc.authenticate_from_headers(
            request.httprequest.headers,
            client_ip=client_ip,
            model_name=model_name,
            method_name=method_name,
        )
        if auth_err:
            http_code, exc_name, err_msg = auth_err
            return self._rest_error(http_code, exc_name, err_msg, [err_msg])

        # -- Despachar llamada ORM ----------------------------------------
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
    # Endpoints de Documentación & Herramientas
    # ------------------------------------------------------------------

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
                "version": "2.0.1"
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
                    "name": "3. JSON-RPC 2.0 Envelope",
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

        # -- Guardia de tamaño del cuerpo ---------------------------------
        content_length = request.httprequest.content_length
        if content_length and content_length > MAX_BODY_BYTES:
            return self._json_response(
                svc.build_error_response(svc.INVALID_REQUEST,
                                         'Request body too large.'))

        # -- Parsear cuerpo -----------------------------------------------
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

        # -- Lote (batch) o individual ------------------------------------
        if isinstance(payload, list):
            return self._handle_batch(payload, client_ip)
        return self._handle_single(payload, client_ip)

    # ------------------------------------------------------------------

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
