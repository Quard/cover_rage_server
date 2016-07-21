FROM python:3.5.2-alpine

ENV COVER_RAGE_SERVER_VERSION=0.0.1
ENV RAGE_SRV_SCHEME=https
ENV RAGE_SRV_HOST=example.com
ENV RAGE_SRV_THREAD_POOL_SIZE=4
ENV RAGE_SRV_REDIS_HOST=127.0.0.1
ENV RAGE_SRV_REDIS_PORT=6379
ENV RAGE_SRV_REDIS_DB=1
ENV RAGE_SRV_MIN_GOOD_COVERAGE_PERCENTAGE=94
ENV RAGE_SRV_BIND_HOST=0.0.0.0
ENV RAGE_SRV_BIND_PORT=8080
ENV RAGE_SRV_GUNICORN_LOG_LEVEL=INFO
ENV RAGE_SRV_GUNICORN_TIMEOUT=0

RUN apk add --update alpine-sdk
RUN pip install cover-rage-server==$COVER_RAGE_SERVER_VERSION

COPY ./docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]