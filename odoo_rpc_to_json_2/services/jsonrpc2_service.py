# -*- coding: utf-8 -*-
"""
Capa de servicio para JSON/2 + JSON-RPC 2.0.

Provee:
  - authenticate_from_headers()  – Autenticación estilo REST Odoo 19 con control de acceso avanzado
  - execute_orm()                – Despacho ORM seguro para endpoint REST
  - dispatch()                   – Despachador de envolventes JSON-RPC 2.0
  - build_success_response()
  - build_error_response()
  - validate_request()

Diseño de seguridad:
  - Claves almacenadas en SHA-256 e indexadas para búsqueda instantánea
  - Comparación segura con hmac.compare_digest
  - Listas blancas de IPs y subredes CIDR por clave
  - Restricciones de modelos y métodos ORM por clave
  - Rate limiting configurable por clave con respuesta HTTP 429
  - Bloqueo de métodos ORM privados
  - Todas las operaciones se ejecutan en un cursor limpio con el uid autenticado
  - Los errores nunca filtran detalles internos en producción
"""

import hashlib
import hmac
import logging
import time
import traceback

import odoo
from odoo import api, fields as odoo_fields, models as odoo_models, SUPERUSER_ID
from odoo.exceptions import (
    AccessDenied,
    AccessError,
    MissingError,
    UserError,
    ValidationError,
)

_logger = logging.getLogger(__name__)

# ======================================================================
# Códigos de error estándar JSON-RPC 2.0
# ======================================================================
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# Errores personalizados del servidor
AUTH_ERROR = -32000
ODOO_ACCESS_ERROR = -32001
ODOO_VALIDATION_ERROR = -32002
ODOO_MISSING_ERROR = -32003
ODOO_USER_ERROR = -32004
RATE_LIMIT_ERROR = -32005

# Métodos ORM explícitamente permitidos para llamantes externos
_PUBLIC_ORM_METHODS = frozenset({
    'read', 'search', 'search_read', 'search_count',
    'create', 'write', 'unlink',
    'name_get', 'name_search', 'fields_get',
    'default_get', 'onchange', 'read_group',
    'copy', 'action_archive', 'action_unarchive',
})


# ======================================================================
# Constructores de respuestas (JSON-RPC 2.0)
# ======================================================================

def build_success_response(result, request_id):
    return {'jsonrpc': '2.0', 'result': result, 'id': request_id}


def build_error_response(code, message, data=None, request_id=None):
    error = {'code': code, 'message': message}
    if data is not None:
        error['data'] = data
    return {'jsonrpc': '2.0', 'error': error, 'id': request_id}


def validate_request(payload):
    """Valida la estructura mínima de JSON-RPC 2.0.

    Devuelve (True, None) o (False, error_response_dict).
    """
    if not isinstance(payload, dict):
        return False, build_error_response(
            INVALID_REQUEST, 'Request body must be a JSON object.')
    if payload.get('jsonrpc') != '2.0':
        return False, build_error_response(
            INVALID_REQUEST,
            'Missing or invalid "jsonrpc" field (must be "2.0").',
            request_id=payload.get('id'))
    if 'method' not in payload:
        return False, build_error_response(
            INVALID_REQUEST, 'Missing "method" field.',
            request_id=payload.get('id'))
    if 'id' not in payload:
        return False, build_error_response(
            INVALID_REQUEST, 'Missing "id" field.',
            request_id=payload.get('id'))
    return True, None


# ======================================================================
# Estilo Odoo 19: autenticación mediante cabeceras HTTP
# ======================================================================

def authenticate_from_headers(headers, client_ip=None, model_name=None, method_name=None):
    """Analiza el token Bearer + X-Odoo-Database de las cabeceras HTTP.

    Devuelve (db, uid, None) en caso de éxito o (None, None, (http_code, exc_name, mensaje_error)).
    """
    # -- Extraer token Bearer -------------------------------------------
    auth_header = headers.get('Authorization') or headers.get('authorization', '')
    raw_key = None
    if auth_header:
        parts = auth_header.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            raw_key = parts[1].strip()

    if not raw_key:
        return None, None, (
            401, 'odoo.exceptions.AccessDenied',
            'Missing or malformed Authorization header. Expected: Authorization: Bearer <api_key>'
        )

    # -- Extraer base de datos ------------------------------------------
    db = (headers.get('X-Odoo-Database')
          or headers.get('x-odoo-database', '').strip())
    if not db:
        # Fallback: intentar usar la única base de datos disponible
        try:
            dbs = odoo.service.db.list_dbs(force=True)
            if len(dbs) == 1:
                db = dbs[0]
            else:
                return None, None, (
                    400, 'builtins.ValueError',
                    'Missing X-Odoo-Database header. Required when multiple databases are available.'
                )
        except Exception:
            return None, None, (
                400, 'builtins.ValueError',
                'Missing X-Odoo-Database header.'
            )

    # -- Validar clave y restricciones de seguridad ---------------------
    uid, auth_error = _validate_api_key_and_rules(
        db, raw_key, client_ip=client_ip, model_name=model_name, method_name=method_name
    )
    if auth_error:
        http_code, msg = auth_error
        exc_type = 'odoo.exceptions.AccessError' if http_code == 403 else (
            'odoo.exceptions.RateLimitError' if http_code == 429 else 'odoo.exceptions.AccessDenied'
        )
        return None, None, (http_code, exc_type, msg)

    return db, uid, None


def _validate_api_key_and_rules(db, raw_key, client_ip=None, model_name=None, method_name=None):
    """Valida la clave API contra la base de datos aplicando reglas de IP, modelo, método y rate limiting.

    Retorna:
        (uid, None) en éxito, o (None, (http_status, error_message)) en error.
    """
    if not raw_key:
        return None, (401, 'Invalid or expired API key.')

    key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    try:
        registry = odoo.registry(db)
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            # Búsqueda optimizada O(1) por hash indexado
            key_rec = env['jsonrpc2.api.key'].sudo().search([
                ('key_hash', '=', key_hash),
                ('active', '=', True)
            ], limit=1)

            if not key_rec:
                return None, (401, 'Invalid or expired API key.')

            # Doble comprobación timing-safe
            if not hmac.compare_digest(key_rec.key_hash or '', key_hash):
                return None, (401, 'Invalid or expired API key.')

            # Comprobar fecha de caducidad
            if key_rec.expires_at and key_rec.expires_at < odoo_fields.Datetime.now():
                return None, (401, 'Invalid or expired API key.')

            # Comprobar lista blanca de IPs
            if client_ip and not key_rec.check_ip_allowed(client_ip):
                _logger.warning("API key '%s' rejected for unauthorized IP %s", key_rec.name, client_ip)
                return None, (403, f'IP address {client_ip} is not authorized for this API key.')

            # Comprobar modelos permitidos
            if model_name and not key_rec.check_model_allowed(model_name):
                _logger.warning("API key '%s' rejected for unauthorized model %s", key_rec.name, model_name)
                return None, (403, f'Access to model "{model_name}" is not permitted for this API key.')

            # Comprobar métodos ORM permitidos
            if method_name and not key_rec.check_method_allowed(method_name):
                _logger.warning("API key '%s' rejected for unauthorized method %s", key_rec.name, method_name)
                return None, (403, f'Calling method "{method_name}" is not permitted for this API key.')

            # Comprobar límite de tasa (Rate Limiting)
            rate_ok, rate_msg = key_rec.check_rate_limit()
            if not rate_ok:
                return None, (429, rate_msg)

            uid = key_rec.user_id.id
            # Actualizar fecha de último uso
            try:
                key_rec.sudo().write({'last_used': odoo_fields.Datetime.now()})
                cr.commit()
            except Exception:
                cr.rollback()

            return uid, None

    except Exception:
        _logger.warning('Error validating API key', exc_info=True)
        return None, (401, 'Authentication error.')


# ======================================================================
# Estilo Odoo 19: ejecutar llamada ORM (endpoint REST)
# ======================================================================

_VALS_FIRST_METHODS = frozenset({'create', 'new'})


def _call_rest_method(fn, method_name, params):
    """Despacho inteligente para llamadas estilo REST."""
    if not isinstance(params, dict):
        params = {}

    if method_name in _VALS_FIRST_METHODS:
        return fn(params)

    if method_name in ('search', 'search_read', 'search_count'):
        kw = dict(params)
        domain = kw.pop('domain', [])
        return fn(domain, **kw)

    # Métodos a nivel de registro que toman ids vía la clave 'ids' en el cuerpo
    if 'ids' in params and isinstance(params['ids'], list):
        ids = params['ids']
        kw = {k: v for k, v in params.items() if k != 'ids'}
        model = fn.__self__.browse(ids)
        bound_fn = getattr(model, method_name)
        return bound_fn(**kw) if kw else bound_fn()

    # Caso general: pasar como **kwargs
    try:
        return fn(**params)
    except TypeError:
        return fn(params)


def execute_orm(db, uid, model_name, method_name, params, client_ip, debug):
    """Ejecuta model_name.method_name(**params) como uid."""
    # Seguridad: bloquear métodos privados
    if method_name.startswith('_'):
        exc_info = (
            403,
            'odoo.exceptions.AccessError',
            f'Calling private method "{method_name}" is not allowed.',
            [method_name],
            None,
        )
        _log_call(db, uid, 'api_key', None, 'call', model_name, method_name,
                  'error', exc_info[2], 0, client_ip)
        return None, exc_info

    t0 = time.time()
    try:
        registry = odoo.registry(db)
        with registry.cursor() as cr:
            env = api.Environment(cr, uid, {})

            if model_name not in env:
                raise UserError(f'Model "{model_name}" not found.')

            model = env[model_name]
            fn = getattr(model, method_name, None)
            if fn is None or not callable(fn):
                raise UserError(
                    f'Method "{method_name}" not found on model "{model_name}".')

            result = _call_rest_method(fn, method_name, params)

            # Convertir recordsets → serializables JSON
            if isinstance(result, odoo_models.BaseModel):
                ids = result.ids
                result = ids[0] if len(ids) == 1 else ids

            cr.commit()

        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, 'api_key', None, 'call', model_name, method_name,
                  'success', None, elapsed, client_ip)
        return result, None

    except AccessError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, 'api_key', None, 'call', model_name, method_name,
                  'error', str(exc), elapsed, client_ip)
        return None, (403, 'odoo.exceptions.AccessError',
                      str(exc), list(exc.args),
                      traceback.format_exc() if debug else None)

    except ValidationError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, 'api_key', None, 'call', model_name, method_name,
                  'error', str(exc), elapsed, client_ip)
        return None, (400, 'odoo.exceptions.ValidationError',
                      str(exc), list(exc.args),
                      traceback.format_exc() if debug else None)

    except MissingError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, 'api_key', None, 'call', model_name, method_name,
                  'error', str(exc), elapsed, client_ip)
        return None, (404, 'odoo.exceptions.MissingError',
                      str(exc), list(exc.args),
                      traceback.format_exc() if debug else None)

    except UserError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, 'api_key', None, 'call', model_name, method_name,
                  'error', str(exc), elapsed, client_ip)
        return None, (400, 'odoo.exceptions.UserError',
                      str(exc), list(exc.args),
                      traceback.format_exc() if debug else None)

    except Exception as exc:
        elapsed = (time.time() - t0) * 1000
        _logger.exception('JSON/2 internal error – %s.%s', model_name, method_name)
        _log_call(db, uid, 'api_key', None, 'call', model_name, method_name,
                  'error', str(exc), elapsed, client_ip)
        return None, (500, type(exc).__module__ + '.' + type(exc).__qualname__,
                      'Internal server error.',
                      [str(exc)] if debug else [],
                      traceback.format_exc() if debug else None)


# ======================================================================
# Despachador JSON-RPC 2.0 (legado)
# ======================================================================

class _AuthError(Exception):
    def __init__(self, message, code=AUTH_ERROR):
        super().__init__(message)
        self.code = code


def _authenticate_password(db, login, password):
    """Autentica con usuario/contraseña; devuelve uid o False."""
    try:
        uid = odoo.registry(db)['res.users'].authenticate(
            db, login, password, {'interactive': False})
    except AccessDenied:
        uid = False
    return uid


def _resolve_legacy_auth(params, client_ip=None):
    """Resuelve credenciales del cuerpo de parámetros JSON-RPC."""
    db = params.get('db')
    if not db:
        raise _AuthError('Missing "db" in params.')

    model_name = params.get('model')
    method_name = params.get('method')

    # Ruta API Key
    raw_key = params.get('api_key')
    if raw_key:
        uid, auth_error = _validate_api_key_and_rules(
            db, raw_key, client_ip=client_ip, model_name=model_name, method_name=method_name
        )
        if auth_error:
            http_code, msg = auth_error
            code = RATE_LIMIT_ERROR if http_code == 429 else (
                ODOO_ACCESS_ERROR if http_code == 403 else AUTH_ERROR
            )
            raise _AuthError(msg, code=code)
        return db, uid, 'api_key'

    # Ruta de contraseña
    login = params.get('login')
    password = params.get('password')
    if not login or not password:
        raise _AuthError('Provide "login"+"password" or "api_key" in params.')
    uid = _authenticate_password(db, login, password)
    if not uid:
        raise _AuthError('Invalid login or password.')
    return db, uid, 'password'


def dispatch(payload, client_ip=None, debug=False):
    """Despachador de envolventes JSON-RPC 2.0."""
    request_id = payload.get('id')
    params = payload.get('params') or {}
    method = payload.get('method')
    t0 = time.time()

    # -- Autenticación ----------------------------------------------------
    try:
        db, uid, auth_method = _resolve_legacy_auth(params, client_ip=client_ip)
    except _AuthError as exc:
        return build_error_response(exc.code, str(exc), request_id=request_id)

    # -- Despacho ---------------------------------------------------------
    model_name = params.get('model', '')
    model_method = params.get('method', '')

    try:
        if method == 'call':
            result = _handle_call(db, uid, params, debug=debug)
        elif method == 'authenticate':
            result = {'uid': uid}
            model_method = 'authenticate'
        else:
            return build_error_response(
                METHOD_NOT_FOUND,
                f'Unknown RPC method "{method}". Supported: "call", "authenticate".',
                request_id=request_id)

    except AccessError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, auth_method, request_id, method, model_name,
                  model_method, 'error', str(exc), elapsed, client_ip)
        return build_error_response(
            ODOO_ACCESS_ERROR, str(exc),
            data={'type': 'access_error', 'exception_type': 'odoo.exceptions.AccessError'},
            request_id=request_id)

    except ValidationError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, auth_method, request_id, method, model_name,
                  model_method, 'error', str(exc), elapsed, client_ip)
        return build_error_response(
            ODOO_VALIDATION_ERROR, str(exc),
            data={'type': 'validation_error'},
            request_id=request_id)

    except MissingError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, auth_method, request_id, method, model_name,
                  model_method, 'error', str(exc), elapsed, client_ip)
        return build_error_response(
            ODOO_MISSING_ERROR, str(exc),
            data={'type': 'missing_error'},
            request_id=request_id)

    except UserError as exc:
        elapsed = (time.time() - t0) * 1000
        _log_call(db, uid, auth_method, request_id, method, model_name,
                  model_method, 'error', str(exc), elapsed, client_ip)
        return build_error_response(
            ODOO_USER_ERROR, str(exc),
            data={'type': 'user_error'},
            request_id=request_id)

    except Exception as exc:
        elapsed = (time.time() - t0) * 1000
        _logger.exception('JSON-RPC 2.0 internal error')
        _log_call(db, uid, auth_method, request_id, method, model_name,
                  model_method, 'error', str(exc), elapsed, client_ip)
        error_data = {'type': 'internal_error'}
        if debug:
            error_data['traceback'] = traceback.format_exc()
        return build_error_response(
            INTERNAL_ERROR, 'Internal server error.',
            data=error_data, request_id=request_id)

    elapsed = (time.time() - t0) * 1000
    _log_call(db, uid, auth_method, request_id, method, model_name,
              model_method, 'success', None, elapsed, client_ip)
    return build_success_response(result, request_id)


def _handle_call(db, uid, params, debug=False):
    """Ejecuta el método ORM especificado en los parámetros JSON-RPC."""
    model_name = params.get('model')
    model_method = params.get('method')

    if not model_name:
        raise UserError('Missing "model" in params.')
    if not model_method:
        raise UserError('Missing "method" in params.')

    args = params.get('args') or []
    kwargs = params.get('kwargs') or {}
    extra_context = params.get('context') or {}

    # Bloquear métodos privados
    if model_method.startswith('_'):
        raise AccessError(
            f'Calling private method "{model_method}" is not allowed.')

    registry = odoo.registry(db)
    with registry.cursor() as cr:
        ctx = dict(extra_context)
        env = api.Environment(cr, uid, ctx)

        if model_name not in env:
            raise UserError(f'Model "{model_name}" not found.')

        model = env[model_name]

        if (args
                and isinstance(args[0], list)
                and all(isinstance(x, int) for x in args[0])):
            model = model.browse(args[0])
            args = args[1:]

        fn = getattr(model, model_method, None)
        if fn is None or not callable(fn):
            raise UserError(
                f'Method "{model_method}" not found on model "{model_name}".')

        result = fn(*args, **kwargs)

        if isinstance(result, odoo_models.BaseModel):
            ids = result.ids
            result = ids[0] if len(ids) == 1 else ids

        cr.commit()

    return result


# ======================================================================
# Registro de auditoría
# ======================================================================

def _log_call(db, uid, auth_method, request_id, rpc_method,
              model_name, model_method, state, error_message,
              duration_ms, client_ip):
    """Emite una línea de registro en Python y persiste una fila de auditoría."""
    _logger.info(
        'JSONRPC2 | db=%s uid=%s rpc=%s model=%s.%s state=%s '
        'duration=%.1fms id=%s ip=%s',
        db, uid, rpc_method, model_name, model_method,
        state, duration_ms, request_id, client_ip,
    )
    try:
        registry = odoo.registry(db)
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            env['jsonrpc2.api.log'].create({
                'database': db,
                'user_id': uid,
                'auth_method': auth_method,
                'jsonrpc_id': str(request_id) if request_id is not None else '',
                'rpc_method': rpc_method or '',
                'model_name': model_name or '',
                'model_method': model_method or '',
                'state': state,
                'error_message': error_message or '',
                'duration_ms': duration_ms,
                'client_ip': client_ip or '',
            })
            cr.commit()
    except Exception:
        _logger.warning(
            'Failed to persist JSON-RPC 2.0 audit log', exc_info=True)


# ======================================================================
# Introspección Dinámica y Esquemas de Modelos
# ======================================================================

def get_model_schema(db, uid, model_name):
    """Genera el esquema JSON y metadatos de campos para model_name."""
    registry = odoo.registry(db)
    with registry.cursor() as cr:
        env = api.Environment(cr, uid, {})
        if model_name not in env:
            raise UserError(f'Model "{model_name}" not found.')

        model = env[model_name]
        fields_info = model.fields_get()

        type_mapping = {
            'char': 'string',
            'text': 'string',
            'html': 'string',
            'integer': 'integer',
            'float': 'number',
            'monetary': 'number',
            'boolean': 'boolean',
            'date': 'string (YYYY-MM-DD)',
            'datetime': 'string (YYYY-MM-DD HH:MM:SS)',
            'binary': 'string (base64)',
            'selection': 'string (selection)',
            'many2one': 'integer (id)',
            'one2many': 'array of integers/commands',
            'many2many': 'array of integers/commands',
        }

        properties = {}
        for fname, finfo in sorted(fields_info.items()):
            ftype = finfo.get('type')
            prop = {
                'type': type_mapping.get(ftype, ftype),
                'odoo_type': ftype,
                'string': finfo.get('string', fname),
                'required': finfo.get('required', False),
                'readonly': finfo.get('readonly', False),
            }
            if finfo.get('help'):
                prop['help'] = finfo['help']
            if finfo.get('selection'):
                prop['selection'] = finfo['selection']
            if finfo.get('relation'):
                prop['relation'] = finfo['relation']
            properties[fname] = prop

        methods = {
            'search_read': {
                'description': 'Search records and return selected field values.',
                'example_payload': {
                    'domain': [['id', '>', 0]],
                    'fields': list(properties.keys())[:6],
                    'limit': 10,
                    'order': 'id desc'
                }
            },
            'create': {
                'description': 'Create a new record in this model.',
                'example_payload': {
                    fname: f"Sample {prop['string']}"
                    for fname, prop in list(properties.items())[:3]
                    if not prop['readonly'] and prop['odoo_type'] in ('char', 'text')
                }
            },
            'write': {
                'description': 'Update one or multiple records by ID.',
                'example_payload': {
                    'ids': [1],
                    'vals': {
                        fname: "Updated value"
                        for fname, prop in list(properties.items())[:1]
                        if not prop['readonly'] and prop['odoo_type'] in ('char', 'text')
                    }
                }
            },
            'unlink': {
                'description': 'Delete records by ID list.',
                'example_payload': {
                    'ids': [1]
                }
            },
            'fields_get': {
                'description': 'Inspect raw field definitions and metadata.',
                'example_payload': {}
            }
        }

        return {
            'model': model_name,
            'description': getattr(model, '_description', model_name),
            'fields_count': len(properties),
            'properties': properties,
            'supported_methods': methods,
        }


def list_accessible_models(db, uid):
    """Devuelve la lista de modelos disponibles en la base de datos."""
    registry = odoo.registry(db)
    with registry.cursor() as cr:
        env = api.Environment(cr, uid, {})
        models = env['ir.model'].search_read(
            [('transient', '=', False)],
            ['model', 'name', 'state'],
            order='model'
        )
        return models

