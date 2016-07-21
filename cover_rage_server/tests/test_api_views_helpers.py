from unittest import TestCase, mock


from cover_rage_server.api_views import cover_rage_status_url


class CoverRageStatusUrlTestCase(TestCase):

    @mock.patch('cover_rage_server.api_views.settings.SRV_SCHEME', new='https')
    @mock.patch('cover_rage_server.api_views.settings.SRV_HOST', new='example.com')
    def test_cover_rage_status_url(self):
        result = cover_rage_status_url('token', 'sha')
        expected_result = 'https://example.com/api/status/token/sha/'
        self.assertEqual(result, expected_result)
