# -*- coding: utf-8 -*-
"""
Capa de servicio para JSON/2 + JSON-RPC 2.0.

Provee:
  - authenticate_from_headers()  – Autenticación estilo REST Odoo 19
  - execute_orm()                – Despacho ORM seguro para endpoint REST
  - dispatch()                   – Despachador de envolventes JSON-RPC 2.0
  - build_success_response()
  - build_error_response()
  - validate_request()

Diseño de seguridad:
  - Comparación de claves resistente a ataques de tiempo con hmac.compare_digest
  - Claves almacenadas en SHA-256 (nunca en texto plano)
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

def authenticate_from_headers(headers):
    """Analiza el token Bearer + X-Odoo-Database de las cabeceras HTTP.

    Devuelve (db, uid, None) en caso de éxito o (None, None, mensaje_error).
    Utiliza comparación resistente a ataques de tiempo para prevenir ataques de oráculo.
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
            'Missing or malformed Authorization header. '
            'Expected: Authorization: Bearer <api_key>'
        )

    # -- Extraer base de datos ------------------------------------------
    db = (headers.get('X-Odoo-Database')
          or headers.get('x-odoo-database', '').strip())
    if not db:
        # Fallback: intentar usar la única base de datos disponible
        dbs = odoo.service.db.list_dbs(force=True)
        if len(dbs) == 1:
            db = dbs[0]
        else:
            return None, None, (
                'Missing X-Odoo-Database header. '
                'Required when multiple databases are available.'
            )

    # -- Validar clave (timing-safe) ------------------------------------
    uid = _validate_api_key(db, raw_key)
    if not uid:
        # Mismo mensaje para clave inválida o caducada para evitar enumeración
        return None, None, 'Invalid or expired API key.'

    return db, uid, None


def _validate_api_key(db, raw_key):
    """Devuelve el uid para *raw_key* o False.

    Utiliza hmac.compare_digest para comparación resistente a timing-attacks.
    La comprobación se realiza con SUPERUSER para que las ACLs no interfieran.
    """
    if not raw_key:
        return False
    key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    try:
        registry = odoo.registry(db)
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            # Obtener todas las claves activas; iterar SIEMPRE TODAS por seguridad de tiempos
            keys = env['jsonrpc2.api.key'].sudo().search(
                [('active', '=', True)], order='id')
            matched = None
            for key_rec in keys:
                stored = key_rec.key_hash or ''
                # Timing-safe: siempre comparar cada clave, nunca romper el bucle anticipadamente
                if hmac.compare_digest(stored, key_hash) and matched is None:
                    matched = key_rec
            if matched is None:
                return False
            # Comprobar caducidad
            if (matched.expires_at
                    and matched.expires_at < odoo_fields.Datetime.now()):
                return False
            uid = matched.user_id.id
            # Actualizar last_used
            try:
                matched.sudo().write(
                    {'last_used': odoo_fields.Datetime.now()})
                cr.commit()
            except Exception:
                cr.rollback()
            return uid
    except Exception:
        _logger.warning('Error validating API key', exc_info=True)
    return False



# ======================================================================
# Estilo Odoo 19: ejecutar llamada ORM (endpoint REST)
# ======================================================================

# Métodos que toman un único diccionario posicional (vals) en convención Odoo
_VALS_FIRST_METHODS = frozenset({'create', 'new'})
# Métodos que toman ids como primer argumento vía browse (manejados por _handle_call)
# NO son necesarios aquí ya que el endpoint REST no usa la convención ids-primero


def _call_rest_method(fn, method_name, params):
    """Despacho inteligente para llamadas estilo REST.

    Odoo 19 /json/2 pasa el cuerpo JSON como **kwargs.
    Pero los métodos ORM clásicos tienen varias convenciones de llamada.

    Convenciones de cuerpo soportadas:
      - create:              body = {campo: val, ...}         → create(body)
      - search/search_read:  body = {domain: [...], ...}      → search(domain, **rest)
      - unlink/write:        body = {ids: [id,...], ...}      → browse(ids).unlink()
      - todos los demás:     body = {kwarg: val, ...}         → fn(**body)
    """
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
    """Ejecuta model_name.method_name(**params) como uid.

    Devuelve (result, None) en éxito o (None, exc_info_tuple) en caso de error
    donde exc_info_tuple = (http_status, exc_name, mensaje, argumentos, traceback_str).
    """
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

            # Convención REST de Odoo 19: el cuerpo JSON se pasa como **kwargs.
            # Sin embargo, algunos métodos ORM toman argumentos posicionales (ej. create(vals),
            # search(domain)). Usamos un despacho inteligente:
            #
            #  1. Si params tiene una clave posicional conocida para este método → posicional
            #  2. De lo contrario intenta **params; si hay TypeError, recae en posicional
            result = _call_rest_method(fn, method_name, params)

            # Convertir recordsets → serializables JSON
            if isinstance(result, odoo_models.BaseModel):
                ids = result.ids
                # Resultado de un solo registro (ej. create) → entero limpio como Odoo 19
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
    """Centinela para fallos de autenticación."""


def _authenticate_password(db, login, password):
    """Autentica con usuario/contraseña; devuelve uid o False."""
    try:
        uid = odoo.registry(db)['res.users'].authenticate(
            db, login, password, {'interactive': False})
    except AccessDenied:
        uid = False
    return uid


def _resolve_legacy_auth(params):
    """Resuelve credenciales del cuerpo de parámetros JSON-RPC.

    Soporta:
      1. db + login + password
      2. db + api_key  (Clave Bearer en parámetros)
    """
    db = params.get('db')
    if not db:
        raise _AuthError('Missing "db" in params.')

    # Ruta API Key
    raw_key = params.get('api_key')
    if raw_key:
        uid = _validate_api_key(db, raw_key)
        if not uid:
            raise _AuthError('Invalid or expired API key.')
        return db, uid, 'api_key'

    # Ruta de contraseña
    login = params.get('login')
    password = params.get('password')
    if not login or not password:
        raise _AuthError(
            'Provide "login"+"password" or "api_key" in params.'
        )
    uid = _authenticate_password(db, login, password)
    if not uid:
        raise _AuthError('Invalid login or password.')
    return db, uid, 'password'


def dispatch(payload, client_ip=None, debug=False):
    """Despachador de envolventes JSON-RPC 2.0.

    Devuelve un diccionario serializable en JSON.
    """
    request_id = payload.get('id')
    params = payload.get('params') or {}
    method = payload.get('method')
    t0 = time.time()

    # -- Autenticación ----------------------------------------------------
    try:
        db, uid, auth_method = _resolve_legacy_auth(params)
    except _AuthError as exc:
        return build_error_response(AUTH_ERROR, str(exc), request_id=request_id)

    # -- Despacho ---------------------------------------------------------
    model_name = params.get('model', '')
    model_method = params.get('method', '')  # Método ORM (dentro de call)

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

        # Convención Odoo XMLRPC/JSON-RPC 2.0:
        # Cuando args[0] es una lista de enteros (ids de registros), buscar esos registros
        # primero y llamar al método sobre el recordset resultante.
        # Ejemplos:
        #   write:  args=[[id1, id2], {vals}] → model.browse([id1,id2]).write({vals})
        #   unlink: args=[[id1, id2]]         → model.browse([id1,id2]).unlink()
        #   read:   args=[[id], [fields]]     → model.browse([id]).read([fields])
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

        # Convert recordsets → JSON-serialisable
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
