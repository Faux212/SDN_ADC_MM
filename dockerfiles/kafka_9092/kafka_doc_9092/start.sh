#!/bin/bash -x
echo "Starting kafka"

IP=$(grep "\s${HOSTNAME}$" /etc/hosts | head -n 1 | awk '{print $1}')
sed -i "s|{BROKER_ID}|${BROKER_ID}|g" /kafka/config/server.properties
sed -i "s|{CONTAINER_IP}|${IP}|g" /kafka/config/server.properties
sed -i "s|{MACHINE_IP}|${ADVERTISED_HOST}|g" /kafka/config/server.properties
sed -i "s|{KAFKA_PORT}|${ADVERTISED_PORT}|g" /kafka/config/server.properties
sed -i "s|{ZOOKEEPER_IP}|${ZOOKEEPER_IP}|g" /kafka/config/server.properties
sed -i "s|{ZOOKEEPER_PORT}|${ZOOKEEPER_PORT}|g" /kafka/config/server.properties
HOSTNAME="${HOSTNAME}"

exec /kafka/bin/kafka-server-start.sh /kafka/config/server.properties

exec echo "DONE"
