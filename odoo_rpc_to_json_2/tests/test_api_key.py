# -*- coding: utf-8 -*-

from datetime import timedelta
import hashlib
from odoo import fields
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestJsonRpc2ApiKey(TransactionCase):

    def setUp(self):
        super().setUp()
        self.ApiKey = self.env['jsonrpc2.api.key']
        self.test_user = self.env['res.users'].create({
            'name': 'API Test User',
            'login': 'api_test_user@example.com',
            'email': 'api_test_user@example.com',
        })

    def test_01_create_api_key_hashes_token(self):
        """Verifica que la clave se crea con hash SHA-256 y prefijo."""
        res = self.ApiKey.generate_key(
            name='Test Integration Key',
            user_id=self.test_user.id
        )
        self.assertTrue(res['key'].startswith('jrpc2_'))
        key_record = self.ApiKey.browse(res['id'])
        self.assertEqual(key_record.name, 'Test Integration Key')
        self.assertEqual(key_record.user_id, self.test_user)
        self.assertTrue(key_record.key_hash)
        expected_hash = hashlib.sha256(res['key'].encode('utf-8')).hexdigest()
        self.assertEqual(key_record.key_hash, expected_hash)
        self.assertEqual(key_record.key_prefix, res['key'][:12])

    def test_02_name_validation(self):
        """Verifica que no se permitan descripciones de menos de 3 caracteres."""
        with self.assertRaises(ValidationError):
            self.ApiKey.create({
                'name': 'ab',
                'user_id': self.test_user.id
            })

    def test_03_ip_whitelisting(self):
        """Verifica la validación de listas blancas de IPs individuales y CIDR."""
        key = self.ApiKey.create({
            'name': 'IP Restricted Key',
            'user_id': self.test_user.id,
            'allowed_ips': '192.168.1.50, 10.0.0.0/24'
        })
        self.assertTrue(key.check_ip_allowed('192.168.1.50'))
        self.assertTrue(key.check_ip_allowed('10.0.0.42'))
        self.assertFalse(key.check_ip_allowed('192.168.1.51'))
        self.assertFalse(key.check_ip_allowed('172.16.0.1'))

    def test_04_model_and_method_restrictions(self):
        """Verifica restricciones de modelos y métodos específicos."""
        partner_model = self.env['ir.model'].search([('model', '=', 'res.partner')], limit=1)
        key = self.ApiKey.create({
            'name': 'Partner Readonly Key',
            'user_id': self.test_user.id,
            'allowed_model_ids': [(6, 0, [partner_model.id])],
            'allowed_methods': 'search_read,read'
        })
        # Modelos
        self.assertTrue(key.check_model_allowed('res.partner'))
        self.assertFalse(key.check_model_allowed('res.users'))

        # Métodos
        self.assertTrue(key.check_method_allowed('search_read'))
        self.assertTrue(key.check_method_allowed('read'))
        self.assertFalse(key.check_method_allowed('create'))
        self.assertFalse(key.check_method_allowed('unlink'))

    def test_05_rate_limiting(self):
        """Verifica el cálculo de tasa de peticiones."""
        key = self.ApiKey.create({
            'name': 'Rate Limited Key',
            'user_id': self.test_user.id,
            'rate_limit_requests': 2,
            'rate_limit_interval': 'minute'
        })
        # Sin logs previos, debe permitir
        ok, _msg = key.check_rate_limit()
        self.assertTrue(ok)

        # Crear 2 logs
        self.env['jsonrpc2.api.log'].create({
            'user_id': self.test_user.id,
            'auth_method': 'api_key',
            'state': 'success',
            'create_date': fields.Datetime.now(),
        })
        self.env['jsonrpc2.api.log'].create({
            'user_id': self.test_user.id,
            'auth_method': 'api_key',
            'state': 'success',
            'create_date': fields.Datetime.now(),
        })

        # Al alcanzar 2 peticiones en el intervalo, debe rechazar
        ok, msg = key.check_rate_limit()
        self.assertFalse(ok)
        self.assertIn('Rate limit exceeded', msg)
