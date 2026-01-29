FROM php:8.4-apache AS base

ENV HTTP2TCP_CORS_ALLOW_ORIGIN="*"
ENV HTTP2TCP_DOCS_URL="https://github.com/hrnco/http2tcp-local-agent"

FROM base AS prebuild

ENV COMPOSER_ALLOW_SUPERUSER=1
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

FROM prebuild AS dev

FROM base AS prod
