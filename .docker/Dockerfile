FROM php:8.4-apache AS base

ENV HTTP2TCP_CORS_ALLOW_ORIGIN="*"
ENV HTTP2TCP_DOCS_URL="https://github.com/hrnco/http2tcp-local-agent"

COPY ./.docker/apache/000-default.conf /etc/apache2/sites-available/000-default.conf

FROM base AS prebuild

ENV COMPOSER_ALLOW_SUPERUSER=1
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

RUN apt-get update && apt-get install -y \
    git curl mc nano telnet iputils-ping htop \
    && yes | pecl install -o -f xdebug \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

FROM prebuild AS dev

FROM base AS prod

