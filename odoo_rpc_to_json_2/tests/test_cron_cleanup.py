# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from odoo.tests.common import TransactionCase


class TestCronCleanup(TransactionCase):

    def setUp(self):
        super().setUp()
        self.ApiLog = self.env['jsonrpc2.api.log']
        self.ConfigParam = self.env['ir.config_parameter'].sudo()

    def test_01_cron_cleanup_purges_old_logs(self):
        """Verifica que el cron elimine únicamente logs anteriores al periodo de retención."""
        self.ConfigParam.set_param('jsonrpc2.log_retention_days', '10')

        # Log reciente
        recent_log = self.ApiLog.create({
            'rpc_method': 'call',
            'model_name': 'res.partner',
            'model_method': 'search_read',
            'state': 'success',
        })

        # Log antiguo (simular create_date anterior)
        old_log = self.ApiLog.create({
            'rpc_method': 'call',
            'model_name': 'res.partner',
            'model_method': 'create',
            'state': 'success',
        })
        old_date = (datetime.now() - timedelta(days=20)).strftime('%Y-%m-%d %H:%M:%S')
        self.env.cr.execute(
            "UPDATE jsonrpc2_api_log SET create_date = %s WHERE id = %s",
            (old_date, old_log.id)
        )

        # Ejecutar limpieza
        self.ApiLog._cron_cleanup_logs()

        # Verificar resultados
        self.assertTrue(recent_log.exists())
        self.assertFalse(old_log.exists())
