#!/usr/bin/env sh

RAGE_SRV_REDIS_HOST=$RAGESRV_REDIS_1_PORT_6379_TCP_ADDR
RAGE_SRV_REDIS_PORT=$RAGESRV_REDIS_1_PORT_6379_TCP_PORT

gunicorn \
    "cover_rage_server:get_application()" \
    --bind $RAGE_SRV_BIND_HOST:$RAGE_SRV_BIND_PORT \
    --worker-class "aiohttp.worker.GunicornWebWorker" \
    --log-level $RAGE_SRV_GUNICORN_LOG_LEVEL \
    --timeout $RAGE_SRV_GUNICORN_TIMEOUT
