# -*- coding: utf-8 -*-

from odoo import models, fields


class JsonRpc2ApiLog(models.Model):
    """Registro de auditoría para cada llamada JSON-RPC 2.0 y REST procesada por el módulo.

    Los registros son creados por la capa de servicio y son de solo lectura desde la
    interfaz de Odoo. Se puede añadir una acción planificada más adelante para purgar entradas antiguas.
    """

    _name = 'jsonrpc2.api.log'
    _description = 'JSON-RPC 2.0 API Log'
    _order = 'create_date desc'
    _rec_name = 'summary'

    # -- Metadatos de la petición ------------------------------------------
    database = fields.Char(string='Database', readonly=True, index=True)
    user_id = fields.Many2one(
        'res.users',
        string='User',
        readonly=True,
        index=True,
    )
    auth_method = fields.Selection(
        [('password', 'Password'), ('api_key', 'API Key')],
        string='Auth Method',
        readonly=True,
    )

    # -- Campos JSON-RPC ----------------------------------------------------
    jsonrpc_id = fields.Char(
        string='Request ID',
        readonly=True,
        help='The "id" field of the JSON-RPC 2.0 request.',
    )
    rpc_method = fields.Char(
        string='RPC Method',
        readonly=True,
        index=True,
        help='Main JSON-RPC method (e.g. "call").',
    )
    model_name = fields.Char(
        string='Model',
        readonly=True,
        index=True,
    )
    model_method = fields.Char(
        string='Model Method',
        readonly=True,
        index=True,
    )

    # -- Resultado / error --------------------------------------------------
    state = fields.Selection(
        [('success', 'Success'), ('error', 'Error')],
        string='Result',
        readonly=True,
        index=True,
    )
    error_message = fields.Text(string='Error Message', readonly=True)
    duration_ms = fields.Float(
        string='Duration (ms)',
        readonly=True,
        digits=(12, 2),
    )

    # -- Resumen calculado --------------------------------------------------
    summary = fields.Char(
        string='Summary',
        compute='_compute_summary',
        store=True,
    )

    # -- Info del cliente ---------------------------------------------------
    client_ip = fields.Char(string='Client IP', readonly=True)

    # ------------------------------------------------------------------
    # Campos Calculados
    # ------------------------------------------------------------------

    def _compute_summary(self):
        for rec in self:
            parts = [rec.rpc_method or '?']
            if rec.model_name:
                parts.append(rec.model_name)
            if rec.model_method:
                parts.append(rec.model_method)
            rec.summary = ' → '.join(parts)
