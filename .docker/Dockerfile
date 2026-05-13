FROM php:8.4-apache-trixie

RUN a2enmod rewrite headers

VOLUME ["/data"]

# Copy application source.
COPY . /var/www/html

COPY .docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 80
