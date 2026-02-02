FROM php:8.4-apache AS base

RUN apt-get update && apt-get install -y \
    openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite headers

VOLUME ["/data"]

COPY .docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 80

FROM base AS prebuild

#ENV COMPOSER_ALLOW_SUPERUSER=1
#COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
#
#RUN apt-get update && apt-get install -y \
#    git curl mc nano telnet iputils-ping htop \
#    && yes | pecl install -o -f xdebug \
#    && apt-get clean && rm -rf /var/lib/apt/lists/*

FROM prebuild AS dev

FROM base AS prod
