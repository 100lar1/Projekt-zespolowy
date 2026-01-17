FROM php:8.1-apache

# ✅ Instalacja rozszerzenia mysqli
RUN docker-php-ext-install mysqli

COPY . /var/www/html/
EXPOSE 80