# Capa de Compatibilidad API JSON/2 (Odoo 19) para Odoo 16, 17 y 18

Este módulo actúa como una capa de compatibilidad avanzada y un "traductor" de API que implementa de forma anticipada la especificación de la nueva API **JSON/2** y el protocolo **JSON-RPC 2.0** nativos de **Odoo 19** para su uso en entornos **Odoo 16.0, 17.0 y 18.0**.

Permite que integraciones modernas orientadas a Odoo 19 interactúen con versiones anteriores sin necesidad de reescribir código de integración ni recurrir al protocolo legacy XML-RPC.

---

## ✨ Características Principales

* **Compatibilidad Paritaria con Odoo 19:**
  * Implementación del endpoint REST moderno: `POST /json/2/<model>/<method>`
  * Autenticación robusta usando tokens estándar: `Authorization: Bearer <api_key>`
  * Soporte multi-base de datos con cabecera: `X-Odoo-Database`
* **Capa JSON-RPC 2.0 (Envolvente Legacy):**
  * Soporte del endpoint clásico unificado: `POST /jsonrpc2`
  * Admite credenciales (usuario/contraseña o API Key) directamente en los parámetros del cuerpo JSON.
* **Seguridad Criptográfica de Nivel Industrial (Igual a Odoo 19):**
  * **Almacenamiento Seguro:** Las claves de API nunca se guardan en texto plano en la base de datos (solo se almacena su hash criptográfico SHA-256).
  * **Resistencia a Ataques de Temporización (Timing-Safe):** La validación de las claves Bearer utiliza `hmac.compare_digest` evaluando todas las claves activas en un tiempo constante $O(N)$ sin salidas tempranas (*short-circuiting*), eliminando la posibilidad de ataques de temporización por oráculo.
  * **Protección Anti-DoS:** Tamaño máximo de cuerpo de petición limitado mediante la variable de entorno `JSONRPC2_MAX_BODY_BYTES` (por defecto 10 MB).
  * **Control de Expiración:** Soporte para asignar fechas de caducidad automática a los tokens.
  * **Seguridad ORM:** Bloqueo explícito de métodos ORM privados (aquellos que comienzan con guion bajo `_`).
* **UI Administrativa Centralizada:**
  * Menú administrativo **JSON-RPC 2.0** para la creación, asignación y revocación (archivado) ágil de claves de API.
  * Registro integrado y visor de **Logs de Auditoría (API Logs)** en la UI para monitorear peticiones en tiempo real (IP de origen, base de datos, usuario, método ejecutado, duración en ms, estado y mensajes de error detallados).

---

## 🛠️ Cómo Utilizar la API

### 🚀 1. Endpoint REST Moderno (Estilo Odoo 19)

* **URL:** `POST /json/2/<model>/<method>`
* **Cabeceras HTTP Obligatorias:**
  * `Content-Type: application/json`
  * `Authorization: Bearer <TU_API_KEY>`
  * `X-Odoo-Database: <NOMBRE_BASE_DATOS>` *(opcional si el servidor solo tiene una BD activa)*

#### Ejemplo de Consulta (`search_read` en Partners usando `curl`):
```bash
curl -X POST https://tu-servidor-odoo.com/json/2/res.partner/search_read \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer jrpc2_vuestra_clave_secreta_aqui" \
  -H "X-Odoo-Database: odoo_prod" \
  -d '{
    "domain": [["is_company", "=", true]],
    "fields": ["name", "email", "phone"],
    "limit": 5
  }'
```

#### Ejemplo de Creación de Registro (`create` en Partners usando `curl`):
```bash
curl -X POST https://tu-servidor-odoo.com/json/2/res.partner/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer jrpc2_vuestra_clave_secreta_aqui" \
  -H "X-Odoo-Database: odoo_prod" \
  -d '{
    "name": "Cliente de Integración S.L.",
    "email": "contacto@clienteintegracion.com"
  }'
```

---

### 📥 2. Endpoint Envolvente Legacy (JSON-RPC 2.0)

* **URL:** `POST /jsonrpc2`
* **Cabeceras HTTP:**
  * `Content-Type: application/json`

#### Ejemplo usando Clave de API en los parámetros (`curl`):
```bash
curl -X POST https://tu-servidor-odoo.com/jsonrpc2 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call",
    "params": {
      "db": "odoo_prod",
      "api_key": "jrpc2_vuestra_clave_secreta_aqui",
      "model": "res.partner",
      "method": "search_read",
      "args": [[["is_company", "=", true]]],
      "kwargs": {
        "fields": ["name", "email"],
        "limit": 3
      }
    }
  }'
```

#### Ejemplo usando Credenciales Clásicas (`curl`):
```bash
curl -X POST https://tu-servidor-odoo.com/jsonrpc2 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call",
    "params": {
      "db": "odoo_prod",
      "login": "admin",
      "password": "mi_password_seguro",
      "model": "res.partner",
      "method": "read",
      "args": [[1], ["name", "email"]]
    }
  }'
```

---

## 🖥️ Interfaz y Configuración Administrativa en Odoo

A diferencia del flujo nativo de Odoo 19 (que es de autoservicio en el perfil del usuario), este módulo adopta un enfoque **centralizado de control administrativo** idóneo para Odoo 16-18:

1. **Generación de Claves:** Navega al menú principal y haz clic en **JSON-RPC 2.0** > **Generate API Key**.
2. **Configuración:** En el asistente, asocia el token a un usuario (las ACLs del usuario gobernarán los permisos), asigna un nombre de referencia (ej. "Enlace WooCommerce") y define una fecha de expiración si lo requieres. Luego pulsa **Generate API Key**.
3. **Gestión:** Las claves creadas se pueden consultar, revocar o archivar desde **JSON-RPC 2.0** > **API Keys**.
4. **Auditoría de Peticiones:** Visita **JSON-RPC 2.0** > **API Logs** para ver un panel detallado de monitorización con el rendimiento, dirección IP y posibles errores de todas las integraciones externas conectadas.

---

## 🔒 Estructura de Respuestas de Error
En caso de fallo (problemas de permisos, validación de datos o excepciones de usuario), el endpoint REST `/json/2` retorna códigos de estado HTTP semánticos (400, 401, 403, 404, 500) y un cuerpo JSON consistente con el estándar de Odoo 19:

```json
{
  "name": "odoo.exceptions.AccessError",
  "message": "No tiene los permisos necesarios para modificar este registro.",
  "arguments": ["No tiene los permisos necesarios..."],
  "debug": "Traceback (most recent call last):\n  File ..."
}
```
*(El campo `debug` con el traceback solo se muestra si el servidor está en modo debug de Odoo, garantizando que no se filtren detalles de seguridad internos en entornos de producción).*

---

## 📋 Requisitos e Instalación

1. Descarga el código y colócalo en tu directorio de `addons`. El nombre de la carpeta debe ser `odoo_rpc_to_json_2`.
2. Reinicia el servicio de Odoo (`sudo systemctl restart odoo` o equivalente).
3. Activa el **Modo Desarrollador** en Odoo.
4. Dirígete a **Aplicaciones**, haz clic en **Actualizar lista de aplicaciones**.
5. Busca el módulo `odoo_rpc_to_json_2` (o "JSON/2 API") y haz clic en **Instalar**.

### Compatibilidad y Soporte
* **Versiones Soportadas:** Odoo 16.0, 17.0, 18.0.
* **Licencia:** LGPL-3.
* **Soporte:** Las incidencias y mejoras son bienvenidas a través del canal oficial de soporte de Odoo Apps.
