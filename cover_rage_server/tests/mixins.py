import asyncio
from unittest import mock


class AsyncMockMixin(object):

    @staticmethod
    def coro_mock():
        coro = mock.Mock(name="CoroutineResult")
        corofunc = mock.Mock(
            name="CoroutineFunction",
            side_effect=asyncio.coroutine(coro)
        )
        corofunc.coro = coro
        return corofunc


# noinspection PyUnresolvedReferences
class AioHttpViewTestMixin(object):
    """
    Mixin to test `aiohttp` views.

    Example:
    --------

    class SomeApiViewTestCase(AioHttpViewTestMixin, TestCase):

        def setUp(self):
            super(SomeApiViewTestCase, self).setUp()

            # Create event loop
            self.loop = asyncio.get_event_loop()

            # Get required view
            from project.api.views import SomeApiView
            self.view = SomeApiView

        def test_call_success(self):

            # Mock request
            self.request.match_info = self.mock_request_match_info()
            self.request.headers = self.mock_response_headers()
            self.request.json = self.mock_response_json()
            ...

            # Run view
            view = self.view(self.request)
            response = self.loop.run_until_complete(view.post())

            # Check response
            self.assertEqual(response.status, 200)
            self.assertEqual(response.body, ...)
    """

    loop = None
    request = None

    def setUp(self):
        super(AioHttpViewTestMixin, self).setUp()
        self.loop = asyncio.get_event_loop()
        app = mock.Mock()
        app.loop = self.loop
        self.request = mock.Mock()
        self.request.app = app
