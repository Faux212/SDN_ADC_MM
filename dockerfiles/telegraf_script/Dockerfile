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

COPY config/telegraf.conf /etc/telegraf

COPY config /home

COPY config/tele_get_switch_data.py /home

COPY config/tele_get_device_data.py /home

COPY config/tele_get_net_stats.py /home

WORKDIR /home

EXPOSE 8125 8094 8092
