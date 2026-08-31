# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from ..services import jsonrpc2_service as svc


class TestJson2ServiceAndController(TransactionCase):

    def setUp(self):
        super().setUp()
        self.ApiKey = self.env['jsonrpc2.api.key']
        self.test_user = self.env['res.users'].create({
            'name': 'API REST User',
            'login': 'api_rest_user@example.com',
            'email': 'api_rest_user@example.com',
        })
        res = self.ApiKey.generate_key(
            name='Test REST Key',
            user_id=self.test_user.id
        )
        self.raw_key = res['key']
        self.key_rec = self.ApiKey.browse(res['id'])
        self.db_name = self.env.cr.dbname

    def test_01_authenticate_from_headers_success(self):
        """Verifica la autenticación correcta con cabeceras Bearer."""
        headers = {
            'Authorization': f'Bearer {self.raw_key}',
            'X-Odoo-Database': self.db_name,
        }
        db, uid, err = svc.authenticate_from_headers(headers)
        self.assertIsNone(err)
        self.assertEqual(db, self.db_name)
        self.assertEqual(uid, self.test_user.id)

    def test_02_authenticate_missing_or_bad_key(self):
        """Verifica el rechazo con clave inválida."""
        headers = {
            'Authorization': 'Bearer jrpc2_invalid_random_key_1234567890',
            'X-Odoo-Database': self.db_name,
        }
        db, uid, err = svc.authenticate_from_headers(headers)
        self.assertIsNotNone(err)
        http_code, exc_type, msg = err
        self.assertEqual(http_code, 401)

    def test_03_execute_orm_private_method_blocked(self):
        """Verifica que los métodos privados que inician con _ sean bloqueados."""
        result, exc_info = svc.execute_orm(
            self.db_name, self.test_user.id, 'res.partner', '_compute_display_name',
            {}, '127.0.0.1', debug=False
        )
        self.assertIsNone(result)
        self.assertIsNotNone(exc_info)
        http_code, exc_name, msg, _args, _tb = exc_info
        self.assertEqual(http_code, 403)
        self.assertIn('private method', msg)

    def test_04_jsonrpc2_dispatch_search_read(self):
        """Verifica el flujo de despacho JSON-RPC 2.0."""
        payload = {
            'jsonrpc': '2.0',
            'method': 'call',
            'id': 42,
            'params': {
                'db': self.db_name,
                'api_key': self.raw_key,
                'model': 'res.partner',
                'method': 'search_read',
                'args': [[]],
                'kwargs': {'fields': ['name'], 'limit': 1}
            }
        }
        resp = svc.dispatch(payload, client_ip='127.0.0.1', debug=False)
        self.assertEqual(resp.get('jsonrpc'), '2.0')
        self.assertEqual(resp.get('id'), 42)
        self.assertIn('result', resp)
        self.assertNotIn('error', resp)

    def test_05_dynamic_schema_introspection(self):
        """Verifica la generación de esquema dinámico de un modelo."""
        schema = svc.get_model_schema(self.db_name, self.test_user.id, 'res.partner')
        self.assertEqual(schema['model'], 'res.partner')
        self.assertIn('properties', schema)
        self.assertIn('name', schema['properties'])
        self.assertIn('supported_methods', schema)
        self.assertIn('search_read', schema['supported_methods'])

    def test_06_list_accessible_models(self):
        """Verifica el listado de modelos disponibles."""
        models = svc.list_accessible_models(self.db_name, self.test_user.id)
        model_names = [m['model'] for m in models]
        self.assertIn('res.partner', model_names)
        self.assertIn('res.users', model_names)

