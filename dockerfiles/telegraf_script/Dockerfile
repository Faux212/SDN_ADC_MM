# Based on https://github.com/weldpua2008/docker-net-snmp
FROM telegraf

ADD requirements.txt /home

RUN export  DEBIAN_FRONTEND=noninteractive && \
    export DEBIAN_RELEASE=$(awk -F'[" ]' '/VERSION=/{print $3}'  /etc/os-release | tr -cd '[[:alnum:]]._-' ) && \
    echo "remove main from /etc/apt/sources.list" && \
    sed -i '/main/d' /etc/apt/sources.list && \
    echo "remove contrib from /etc/apt/sources.list" && \
    sed -i '/contrib/d' /etc/apt/sources.list && \
    echo "remove non-free from /etc/apt/sources.list" && \
    sed -i '/non-free/d' /etc/apt/sources.list && \
    echo "deb http://httpredir.debian.org/debian ${DEBIAN_RELEASE} main contrib non-free"  >> /etc/apt/sources.list && \
    echo "deb http://httpredir.debian.org/debian ${DEBIAN_RELEASE}-updates main contrib non-free"  >> /etc/apt/sources.list && \
    echo "deb http://security.debian.org ${DEBIAN_RELEASE}/updates main contrib non-free"  >> /etc/apt/sources.list && \
    set -x &&\
    apt-get update && \
    apt-get install -y \
    sshpass \
    build-essential \
    cron \
    ssh \
    python-pip \
    python2.7 \
    python2.7-dev \
    less \
    nano \
    snmp snmpd snmp-mibs-downloader &&\
    rm -r /var/lib/apt/lists/*

RUN pip install -r /home/requirements.txt

ADD config/crontab /etc/cron.d/strip_discovery_cron

RUN chmod 0644 /etc/cron.d/strip_discovery_cron

RUN touch /var/log/cron.log

CMD cron && tail -f /var/log/cron.log

COPY config /home

WORKDIR /home

EXPOSE 8125 8094 8092
