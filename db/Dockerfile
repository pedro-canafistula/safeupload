FROM ubuntu:22.04

LABEL desc="Instância MySQL para desenvolvimento do projeto acadêmico SafeUpload"
LABEL versao_ambiente="Ubuntu 22.04.5 - MySQL 8.4 LTS"

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV TZ=America/Sao_Paulo
ENV DEBIAN_FRONTEND=noninteractive
ENV MYSQL_CONFIG=/etc/mysql/my.cnf

RUN apt update && apt upgrade -y

RUN apt install -y \
    curl \
    vim \
    wget \
    iputils-ping \
    gnupg \
    lsb-release \
    debconf \
    debconf-utils

RUN rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN wget https://dev.mysql.com/get/mysql-apt-config_0.8.40-1_all.deb

RUN echo "mysql-apt-config mysql-apt-config/select-server select mysql-8.4-lts" | debconf-set-selections && \
    echo "mysql-apt-config mysql-apt-config/select-product select ok" | debconf-set-selections

RUN dpkg -i mysql-apt-config_0.8.40-1_all.deb
RUN apt update && apt upgrade -y

RUN echo "mysql-community-server mysql-community-server/root-pass password stage" | debconf-set-selections && \
    echo "mysql-community-server mysql-community-server/re-root-pass password stage" | debconf-set-selections

RUN apt install -y mysql-server

RUN rm -rf /var/lib/apt/lists/* /tmp/mysql-apt-config_0.8.40-1_all.deb

RUN rm -rf /var/lib/mysql/*

WORKDIR /app

COPY my.cnf /app

RUN cat /app/my.cnf > "$MYSQL_CONFIG"

COPY initdb /app/initdb

RUN chmod -R +r /app/initdb

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 3306

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]