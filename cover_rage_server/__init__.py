import asyncio
from concurrent.futures import ThreadPoolExecutor

from aiohttp import web as aiohttp_web

from . import settings
from .api_views import (
    BadgeApiView,
    BitbucketWebHookEventApiView,
    GithubWebHookEventApiView,
    ResultsApiView,
    StatusApiView,
)
from cover_rage_server.storage import create_redis_pool


def get_application():  # pragma: no cover

    async def on_shutdown(application):
        """
        Close Redis pool on shutdown
        """
        await application.redis_pool.clear()

    # Event loop config
    loop = asyncio.get_event_loop()
    loop.set_default_executor(ThreadPoolExecutor(settings.THREAD_POOL_SIZE))

    # Create application
    app = aiohttp_web.Application(loop=loop)

    # Attach Redis poll
    redis_pool = loop.run_until_complete(create_redis_pool(loop))
    app.redis_pool = redis_pool
    app.on_shutdown.append(on_shutdown)

    # Routes
    app.router.add_route('GET',  '/api/badge/{token}/', BadgeApiView)
    app.router.add_route('POST', '/api/hooks/bitbucket/{token}/', BitbucketWebHookEventApiView)
    app.router.add_route('POST', '/api/hooks/github/{token}/', GithubWebHookEventApiView)
    app.router.add_route('POST', '/api/results/{token}/', ResultsApiView)
    app.router.add_route('GET',  '/api/status/{token}/{sha}/', StatusApiView)

    return app


def cli_run(argv):  # pragma: no cover
    app = get_application()
    return app
