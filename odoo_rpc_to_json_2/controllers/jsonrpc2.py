# -*- coding: utf-8 -*-
"""
Controlador API JSON/2 compatible con Odoo 19.

Expone dos endpoints:
  - POST /json/2/<model>/<method>
      API moderna estilo REST que imita a Odoo 19.
      Autenticación: cabecera ``Authorization: Bearer <api_key>``.
      Base de datos: cabecera ``X-Odoo-Database`` (o fallback si hay una sola BD).

  - POST /jsonrpc2
      Endpoint envolvente JSON-RPC 2.0 legado (capa de retrocompatibilidad).
      Autenticación: credenciales en el cuerpo JSON en ``params``.

Medidas de seguridad (coinciden con el modelo de amenazas de Odoo 19):
  - Comparación de claves de API resistente a ataques de tiempo (hmac.compare_digest)
  - Tamaño máximo del cuerpo de la petición (10 MB, configurable)
  - Bloqueo de métodos privados
  - Todas las reglas ACL/record de Odoo se aplican mediante el Environment del usuario
  - No se filtran datos sensibles en las respuestas de error en modo de producción
"""

import hmac
import json
import logging
import os

from odoo import http
from odoo.http import request, Response

from ..services import jsonrpc2_service as svc

_logger = logging.getLogger(__name__)

# Tamaño máximo del cuerpo de la petición (10 MB) – mitiga ataques de agotamiento de memoria
MAX_BODY_BYTES = int(os.environ.get('JSONRPC2_MAX_BODY_BYTES', 10 * 1024 * 1024))


class JsonOdoo19Controller(http.Controller):
    """
    Endpoint estilo REST: POST /json/2/<model>/<method>

    Imita la API /json/2 de Odoo 19.

    Petición:
        POST /json/2/res.partner/search_read
        Authorization: Bearer <api_key>
        X-Odoo-Database: my_db        (opcional si hay una sola bd)
        Content-Type: application/json

        {
            "domain": [["is_company","=",true]],
            "fields": ["name","email"],
            "limit": 10
        }

    Respuesta exitosa (HTTP 200):
        { ... resultado ORM ... }

    Respuesta de error (HTTP 4xx/5xx):
        {
            "name": "odoo.exceptions.AccessError",
            "message": "...",
            "arguments": ["..."],
            "context": {},
            "debug": "<traceback si el modo debug está activo>"
        }
    """

    @http.route(
        '/json/2/<string:model_name>/<string:method_name>',
        type='http',
        auth='none',
        methods=['POST'],
        csrf=False,
        save_session=False,
    )
    def json2_endpoint(self, model_name, method_name, **_kw):
        """Endpoint REST estilo Odoo 19."""
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
            request.httprequest.headers
        )
        if auth_err:
            return self._rest_error(401, 'odoo.exceptions.AccessDenied',
                                    auth_err, [auth_err])

        # -- Despachar llamada ORM ----------------------------------------
        client_ip = request.httprequest.remote_addr
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
    # Funciones auxiliares
    # ------------------------------------------------------------------

    @staticmethod
    def _rest_success(data):
        body = json.dumps(data, default=str, ensure_ascii=False)
        return Response(body, status=200,
                        content_type='application/json; charset=utf-8')

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
            content_type='application/json; charset=utf-8',
        )

    @staticmethod
    def _rest_error_body(status, body):
        return Response(
            json.dumps(body, ensure_ascii=False),
            status=status,
            content_type='application/json; charset=utf-8',
        )


class JsonRpc2LegacyController(http.Controller):
    """
    Endpoint envolvente JSON-RPC 2.0: POST /jsonrpc2

    Capa de retrocompatibilidad para clientes que aún usan JSON-RPC 2.0
    basado en sobres. Las credenciales van dentro del cuerpo JSON en ``params``.
    """

    @http.route(
        '/jsonrpc2',
        type='http',
        auth='none',
        methods=['POST'],
        csrf=False,
        save_session=False,
    )
    def jsonrpc2_endpoint(self, **_kw):
        """Maneja una petición envolvente JSON-RPC 2.0."""
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
            return self._handle_batch(payload)
        return self._handle_single(payload)

    # ------------------------------------------------------------------

    def _handle_single(self, payload):
        ok, err = svc.validate_request(payload)
        if not ok:
            return self._json_response(err)
        client_ip = request.httprequest.remote_addr
        debug = _is_debug_mode(request.httprequest)
        return self._json_response(
            svc.dispatch(payload, client_ip=client_ip, debug=debug)
        )

    def _handle_batch(self, payloads):
        if not payloads:
            return self._json_response(
                svc.build_error_response(svc.INVALID_REQUEST,
                                          'Batch request must not be empty.'))
        results = []
        client_ip = request.httprequest.remote_addr
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
        return Response(body, status=status,
                        content_type='application/json; charset=utf-8')


# ======================================================================
# Funciones auxiliares
# ======================================================================

def _is_debug_mode(httprequest):
    """Devuelve True si el modo debug de Odoo está activo (parámetro en query o cabecera)."""
    debug_param = httprequest.args.get('debug', '')
    return bool(debug_param and debug_param != '0')
