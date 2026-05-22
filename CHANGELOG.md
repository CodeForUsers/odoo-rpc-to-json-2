# Changelog

Todas las novedades, cambios y correcciones de `odoo-rpc-to-json-2`.

## [1.0.0] - 2026-05-22

### Added
- Primera versión estable del módulo `odoo_rpc_to_json_2` para Odoo 16.0, 17.0 y 18.0.
- Endpoint REST moderno compatible con Odoo 19:
  - `POST /json/2/<model>/<method>` con cabeceras:
    - `Authorization: Bearer <api_key>`
    - `X-Odoo-Database: <db_name>` (opcional en entornos monobase).
- Endpoint legacy JSON-RPC 2.0:
  - `POST /jsonrpc2` con:
    - Autenticación por `api_key` en los parámetros.
    - Autenticación clásica por `db`, `login`, `password`.
- Capa de seguridad avanzada:
  - Almacenamiento seguro de claves de API mediante hash SHA-256 (nunca en texto plano).
  - Comparación de claves con `hmac.compare_digest` en recorrido completo O(N) sin salidas tempranas (mitigación de ataques de temporización).
  - Límite de tamaño de cuerpo de petición configurable por `JSONRPC2_MAX_BODY_BYTES` (por defecto 10 MB).
  - Expiración configurable de claves de API.
  - Bloqueo explícito de métodos ORM privados (que empiezan por `_`).
- UI administrativa centralizada:
  - Menú **JSON-RPC 2.0** para generar, gestionar y revocar claves de API.
  - Asistente para crear claves asociadas a usuarios, con nombre descriptivo y fecha de caducidad.
  - Vista de **API Logs** con trazas de auditoría (IP, BD, usuario, método, duración, estado y detalle de errores).
- Manejo de errores:
  - Respuestas JSON consistentes con el formato de errores de Odoo 19 para el endpoint `/json/2`, usando códigos HTTP semánticos (400, 401, 403, 404, 500).
  - Inclusión opcional del traceback (`debug`) solo en modo debug de Odoo.
- Documentación:
  - README detallado con ejemplos de uso para `/json/2` y `/jsonrpc2` usando `curl`.
  - Instrucciones de instalación y requisitos (carpeta `odoo_rpc_to_json_2`, versiones soportadas, licencia LGPL-3).
