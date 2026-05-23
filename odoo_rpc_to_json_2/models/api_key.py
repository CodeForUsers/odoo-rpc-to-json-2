# -*- coding: utf-8 -*-
"""
Modelo de API Key para autenticación JSON/2 + JSON-RPC 2.0.

Diseño de seguridad (coincide con res.users.apikeys de Odoo 19):
  - Claves generadas con secrets.token_urlsafe(48) → 64 caracteres url-safe
  - Almacenadas como hash SHA-256 (nunca en texto plano)
  - Comparación segura contra ataques de tiempo con hmac.compare_digest
  - Caducidad opcional
  - last_used se actualiza en cada autenticación exitosa
  - La clave cruda se devuelve en el contexto *una sola vez* justo tras su creación
"""

import hashlib
import hmac
import secrets

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class JsonRpc2ApiKey(models.Model):
    _name = 'jsonrpc2.api.key'
    _description = 'JSON/2 API Key'
    _order = 'create_date desc'

    name = fields.Char(
        string='Description',
        required=True,
        help='Human-readable label (e.g., "ERP → WMS Integration").',
    )
    user_id = fields.Many2one(
        'res.users',
        string='User',
        required=True,
        ondelete='cascade',
        default=lambda self: self.env.user,
        help='Odoo user whose permissions are used for this key.',
    )
    key_hash = fields.Char(
        string='Key Hash (SHA-256)',
        readonly=True,
        copy=False,
        help='SHA-256 hexadecimal hash. The raw key is only displayed when created.',
    )
    key_prefix = fields.Char(
        string='Key Prefix',
        readonly=True,
        copy=False,
        size=12,
        help='First 12 characters of the key for identification purposes.',
    )
    active = fields.Boolean(default=True)
    last_used = fields.Datetime(string='Last Used', readonly=True)
    expires_at = fields.Datetime(
        string='Expires At',
        help='Leave empty for a key without expiration.',
    )

    # ------------------------------------------------------------------
    # Restricciones
    # ------------------------------------------------------------------

    @api.constrains('name')
    def _check_name_length(self):
        for rec in self:
            if len(rec.name.strip()) < 3:
                raise ValidationError(
                    _("The API key description must have at least 3 characters."))

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    @api.model
    def create(self, vals):
        """Genera una clave criptográficamente segura; almacena solo su hash.

        La clave cruda es accesible mediante self.env.context['raw_api_key']
        inmediatamente después de su creación (visualización de un solo uso).
        """
        raw_key = 'jrpc2_' + secrets.token_urlsafe(48)
        vals['key_hash'] = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
        vals['key_prefix'] = raw_key[:12]
        record = super().create(vals)
        # Exponer clave cruda en el contexto para el wizard/API de visualización única
        return record.with_context(raw_api_key=raw_key)

    @api.model
    def generate_key(self, name, user_id=None):
        """Crea una nueva API key y devuelve la clave cruda (mostrada una sola vez).

        Esta es la forma principal de generar API keys programáticamente,
        reflejando el patrón de Odoo 19 de mostrar la clave cruda solo al crearla.

        Retorna:
            dict: {'id': <key_id>, 'key': '<raw_api_key>'}
        """
        vals = {'name': name}
        if user_id:
            vals['user_id'] = user_id
        record = self.create(vals)
        raw_key = record.env.context.get('raw_api_key', '')
        return {'id': record.id, 'key': raw_key}

    # ------------------------------------------------------------------
    # Funciones auxiliares públicas
    # ------------------------------------------------------------------

    @api.model
    def _authenticate_by_key(self, raw_key):
        """Valida *raw_key* y devuelve el registro res.users enlazado o False.

        Utiliza hmac.compare_digest para una comparación en tiempo constante (timing-safe).
        """
        if not raw_key:
            return False
        key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
        # Obtener todas las claves activas; iterar para comparación resistente a timing-attacks
        keys = self.sudo().search([('active', '=', True)], order='id')
        matched = None
        for key_rec in keys:
            stored = key_rec.key_hash or ''
            if hmac.compare_digest(stored, key_hash):
                matched = key_rec
                # NO hacer break temprano – iterar siempre sobre todas las claves (seguridad)
        if matched is None:
            return False
        # Comprobar caducidad
        if matched.expires_at and matched.expires_at < fields.Datetime.now():
            return False
        # Actualizar last_used
        matched.sudo().write({'last_used': fields.Datetime.now()})
        return matched.user_id

    @api.model
    def action_show_key(self):
        """Devuelve la clave cruda del contexto (solo válida justo tras creación)."""
        return self.env.context.get('raw_api_key')

class JsonRpc2ApiKeyWizard(models.TransientModel):
    _name = 'jsonrpc2.api.key.wizard'
    _description = 'Generate API Key Wizard'

    name = fields.Char(string='Description', required=True)
    user_id = fields.Many2one('res.users', string='User', required=True, default=lambda self: self.env.user)
    expires_at = fields.Datetime(string='Expires At', help='Leave empty so it never expires.')
    
    generated_key = fields.Char(string='Your API Key', readonly=True)

    def action_generate(self):
        self.ensure_one()
        # Generamos la clave mediante el método seguro del modelo
        res = self.env['jsonrpc2.api.key'].generate_key(
            name=self.name,
            user_id=self.user_id.id
        )
        # Asignamos la fecha de expiración si la hay
        if self.expires_at:
            self.env['jsonrpc2.api.key'].browse(res['id']).write({'expires_at': self.expires_at})
            
        self.generated_key = res['key']
        # Recargamos la vista del wizard mostrando la clave generada
        return {
            'type': 'ir.actions.act_window',
            'name': 'Save your API Key',
            'res_model': 'jsonrpc2.api.key.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }
