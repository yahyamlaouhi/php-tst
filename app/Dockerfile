FROM php:8.2.11-fpm


ENV COMPOSER_ALLOW_SUPERUSER=1

RUN apt-get update && apt-get install -y \
    unzip \
    zip \
    git \
    libpng-dev \
    libzip-dev \
    && docker-php-ext-install pdo pdo_mysql

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

COPY . .
RUN ls 

RUN pwd

#install
RUN composer install --prefer-dist --no-dev --no-scripts --no-progress --no-interaction


#run composer dump-autoload --optimize
RUN composer dump-autoload --optimize

