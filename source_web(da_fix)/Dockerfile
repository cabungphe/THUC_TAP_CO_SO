FROM php:7.2-apache

RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org|archive.debian.org|g' /etc/apt/sources.list && \
    sed -i '/stretch-updates/d' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list && \
    apt-get update
RUN docker-php-ext-install mysqli pdo_mysql
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli

COPY . /var/www/html/
WORKDIR /var/www/html/
RUN a2enmod rewrite
RUN mkdir -p /var/www/html/user/avatar && chmod 0777 /var/www/html/user/avatar
RUN mkdir -p /var/www/html/templates_c && chmod 0777 /var/www/html/templates_c