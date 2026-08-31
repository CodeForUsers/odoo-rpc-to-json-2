# -*- coding: utf-8 -*-
"""
Modelo de API Key para autenticación JSON/2 + JSON-RPC 2.0.

Diseño de seguridad (coincide con res.users.apikeys de Odoo 19):
  - Claves generadas con secrets.token_urlsafe(48) → 64 caracteres url-safe
  - Almacenadas como hash SHA-256 (nunca en texto plano)
  - Indexación por hash para búsquedas O(1) de alto rendimiento
  - Restricción granular opcional de modelos permitidos
  - Restricción granular opcional de métodos ORM permitidos
  - Lista blanca opcional de IPs y subredes CIDR
  - Límite de tasa de peticiones (Rate Limiting)
  - Caducidad opcional
  - last_used se actualiza en cada autenticación exitosa
  - La clave cruda se devuelve en el contexto *una sola vez* justo tras su creación
"""

from datetime import timedelta
import hashlib
import hmac
import ipaddress
import logging
import secrets

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, AccessDenied, AccessError, UserError

_logger = logging.getLogger(__name__)


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
        index=True,
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

    # -- Restricciones de Seguridad Avanzada -------------------------------
    allowed_model_ids = fields.Many2many(
        'ir.model',
        'jsonrpc2_api_key_model_rel',
        'key_id',
        'model_id',
        string='Allowed Models',
        help='If set, this key will only be permitted to access these specific models. Leave empty to allow all models accessible by the user.',
    )
    allowed_methods = fields.Char(
        string='Allowed Methods',
        help='Comma-separated list of allowed ORM methods (e.g. "search_read,read,create"). Leave empty for all public methods.',
    )
    allowed_ips = fields.Char(
        string='Allowed IPs / CIDR',
        help='Comma-separated list of allowed IP addresses or CIDR blocks (e.g., "192.168.1.50, 10.0.0.0/24"). Leave empty to allow any IP.',
    )
    rate_limit_requests = fields.Integer(
        string='Max Requests',
        default=0,
        help='Maximum requests allowed per interval. 0 means unlimited.',
    )
    rate_limit_interval = fields.Selection(
        [('minute', 'Per Minute'), ('hour', 'Per Hour'), ('day', 'Per Day')],
        string='Rate Limit Interval',
        default='minute',
        required=True,
    )

    # ------------------------------------------------------------------
    # Restricciones
    # ------------------------------------------------------------------

    @api.constrains('name')
    def _check_name_length(self):
        for rec in self:
            if len((rec.name or '').strip()) < 3:
                raise ValidationError(
                    _("The API key description must have at least 3 characters."))

    @api.constrains('allowed_ips')
    def _check_allowed_ips_format(self):
        for rec in self:
            if not rec.allowed_ips:
                continue
            for raw_entry in rec.allowed_ips.split(','):
                entry = raw_entry.strip()
                if not entry:
                    continue
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    try:
                        ipaddress.ip_address(entry)
                    except ValueError:
                        raise ValidationError(
                            _('Invalid IP or CIDR range in allowed IPs: "%s"') % entry
                        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    @api.model
    def create(self, vals):
        """Genera una clave criptográficamente segura; almacena solo su hash."""
        raw_key = 'jrpc2_' + secrets.token_urlsafe(48)
        vals['key_hash'] = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
        vals['key_prefix'] = raw_key[:12]
        record = super().create(vals)
        return record.with_context(raw_api_key=raw_key)

    @api.model
    def generate_key(self, name, user_id=None, expires_at=None,
                     allowed_model_ids=None, allowed_methods=None,
                     allowed_ips=None, rate_limit_requests=0,
                     rate_limit_interval='minute'):
        """Crea una nueva API key con restricciones y devuelve la clave cruda."""
        vals = {
            'name': name,
            'rate_limit_requests': rate_limit_requests,
            'rate_limit_interval': rate_limit_interval,
        }
        if user_id:
            vals['user_id'] = user_id
        if expires_at:
            vals['expires_at'] = expires_at
        if allowed_model_ids:
            vals['allowed_model_ids'] = [(6, 0, allowed_model_ids)]
        if allowed_methods:
            vals['allowed_methods'] = allowed_methods
        if allowed_ips:
            vals['allowed_ips'] = allowed_ips

        record = self.create(vals)
        raw_key = record.env.context.get('raw_api_key', '')
        return {'id': record.id, 'key': raw_key}

    # ------------------------------------------------------------------
    # Validaciones de Seguridad por Petición
    # ------------------------------------------------------------------

    def check_ip_allowed(self, client_ip):
        """Verifica si client_ip cumple con la lista blanca allowed_ips."""
        self.ensure_one()
        if not self.allowed_ips or not client_ip:
            return True
        try:
            ip_obj = ipaddress.ip_address(client_ip.strip())
        except ValueError:
            _logger.warning("Could not parse client IP: %s", client_ip)
            return False

        for raw_entry in self.allowed_ips.split(','):
            entry = raw_entry.strip()
            if not entry:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if ip_obj in network:
                    return True
            except ValueError:
                continue
        return False

    def check_model_allowed(self, model_name):
        """Verifica si el modelo está dentro de los modelos permitidos."""
        self.ensure_one()
        if not self.allowed_model_ids:
            return True
        allowed_models = {m.model for m in self.allowed_model_ids}
        return model_name in allowed_models

    def check_method_allowed(self, method_name):
        """Verifica si el método ORM está permitido."""
        self.ensure_one()
        if not self.allowed_methods:
            return True
        allowed = {m.strip() for m in self.allowed_methods.split(',') if m.strip()}
        return method_name in allowed

    def check_rate_limit(self):
        """Verifica si la clave ha excedido su límite de tasa."""
        self.ensure_one()
        if not self.rate_limit_requests or self.rate_limit_requests <= 0:
            return True, None

        now = fields.Datetime.now()
        interval_delta = {
            'minute': timedelta(minutes=1),
            'hour': timedelta(hours=1),
            'day': timedelta(days=1),
        }.get(self.rate_limit_interval, timedelta(minutes=1))

        since = now - interval_delta
        count = self.env['jsonrpc2.api.log'].sudo().search_count([
            ('user_id', '=', self.user_id.id),
            ('auth_method', '=', 'api_key'),
            ('create_date', '>=', since),
        ])

        if count >= self.rate_limit_requests:
            return False, _('Rate limit exceeded. Maximum %s requests allowed per %s.') % (
                self.rate_limit_requests, self.rate_limit_interval
            )
        return True, None


class JsonRpc2ApiKeyWizard(models.TransientModel):
    _name = 'jsonrpc2.api.key.wizard'
    _description = 'Generate API Key Wizard'

    name = fields.Char(string='Description', required=True)
    user_id = fields.Many2one('res.users', string='User', required=True, default=lambda self: self.env.user)
    expires_at = fields.Datetime(string='Expires At', help='Leave empty so it never expires.')

    allowed_model_ids = fields.Many2many(
        'ir.model',
        string='Allowed Models',
        help='Optional: Restrict key access only to selected models.',
    )
    allowed_methods = fields.Char(
        string='Allowed Methods',
        help='Optional: Comma-separated list (e.g. "search_read,read,create").',
    )
    allowed_ips = fields.Char(
        string='Allowed IPs',
        help='Optional: Comma-separated IPs or CIDR subnets.',
    )
    rate_limit_requests = fields.Integer(
        string='Max Requests (0 for unlimited)',
        default=0,
    )
    rate_limit_interval = fields.Selection(
        [('minute', 'Per Minute'), ('hour', 'Per Hour'), ('day', 'Per Day')],
        string='Interval',
        default='minute',
    )

    generated_key = fields.Char(string='Your API Key', readonly=True)

    def action_generate(self):
        self.ensure_one()
        res = self.env['jsonrpc2.api.key'].generate_key(
            name=self.name,
            user_id=self.user_id.id,
            expires_at=self.expires_at,
            allowed_model_ids=self.allowed_model_ids.ids if self.allowed_model_ids else None,
            allowed_methods=self.allowed_methods,
            allowed_ips=self.allowed_ips,
            rate_limit_requests=self.rate_limit_requests,
            rate_limit_interval=self.rate_limit_interval,
        )

        self.generated_key = res['key']
        return {
            'type': 'ir.actions.act_window',
            'name': 'Save your API Key',
            'res_model': 'jsonrpc2.api.key.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }
