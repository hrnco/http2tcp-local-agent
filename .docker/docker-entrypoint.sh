#!/bin/sh
set -e

if [ -d /data ]; then
  chown -R www-data:www-data /data
  chmod 700 /data
fi

exec apache2-foreground
