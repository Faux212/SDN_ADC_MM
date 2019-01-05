#!/bin/bash
sudo sysctl -w vm.max_map_count=262144

echo "Installing Docker..."
apt-get update && apt-get install docker.io -y

echo "Creating Virtual Network 'SDNet_Docker' (172.18.0.0/16)..."
docker network create --subnet=172.18.0.0/16 SDNet_Docker

echo "Pulling and Running 'Floodlight_Controller' (172.18.0.2)..."
docker pull glefevre/floodlight

docker run --net SDNet_Docker --ip 172.18.0.2 \
              --name Floodlight_Controller \
              glefevre/floodlight

echo "Pulling and Running 'Portainer_GUI' (172.18.0.4)..."
docker pull portainer/portainer

docker volume create portainer_data

docker run -d -p 9000:9000 \
              --net SDNet_Docker --ip 172.18.0.4 \
              --name Portainer_GUI \
              -v /var/run/docker.sock:/var/run/docker.sock \
              -v portainer_data:/data portainer/portainer \

echo "Pulling and Running 'Mininet_Container' (172.18.0.3)..."
docker pull iwaseyusuke/mininet

docker run -it --rm --privileged -e DISPLAY \
             --net SDNet_Docker --ip 172.18.0.3 \
             --name Mininet_Container \
             -v /tmp/.X11-unix:/tmp/.X11-unix \
             -v /lib/modules:/lib/modules \
             iwaseyusuke/mininet

sudo docker run --net SDNet_Docker --ip 172.18.0.9 --restart always --name zookeeper zookeeper &
sudo docker run --net SDNet_Docker --ip 172.18.0.6 --restart always --env ADVERTISED_PORT=9090 --env ZOOKEEPER_IP=172.18.0.9 --env ZOOKEEPER_PORT=2181 --env BROKER_ID=0 --name kafka_9090_local kafka_doc_9090  &
sudo docker run --net SDNet_Docker --ip 172.18.0.7 --restart always --env ADVERTISED_PORT=9091 --env ZOOKEEPER_IP=172.18.0.9 --env ZOOKEEPER_PORT=2181 --env BROKER_ID=1 --name kafka_9091_local kafka_doc_9091  &
sudo docker run --net SDNet_Docker --ip 172.18.0.8 --restart always --env ADVERTISED_PORT=9092 --env ZOOKEEPER_IP=172.18.0.9 --env ZOOKEEPER_PORT=2181 --env BROKER_ID=2 --name kafka_9092_local kafka_doc_9092  &

sleep 60s

echo " ####################################### Creating Kafka Topics #######################################"
cd kafka_files
sudo bin/kafka-topics.sh --create --zookeeper 172.18.0.9:2181 --replication-factor 3 --partitions 1 --topic SDN_Stats
bin/kafka-configs.sh --zookeeper 172.18.0.9:2181 --entity-type topics --alter --add-config retention.ms=86400000 --entity-name SDN_Stats
cd ..
## sudo bin/kafka-topics.sh --describe --zookeeper 172.18.0.9:2181 --topic SDN_Stats ##


sudo docker run --net SDNet_Docker --ip 172.18.0.10 --restart always --name telegraf_collector telegraf_collector &

sudo docker run --net SDNet_Docker --ip 172.18.0.11 --restart always --log-opt max-size=50m -v elastisearch_data:/usr/share/elasticsearch/data --name elasticsearch elasticsearch_doc &

sudo docker run --net SDNet_Docker --ip 172.18.0.12 --restart always --name logstash logstash_doc &

sudo docker run -p 3000:3000 --net SDNet_Docker --ip 172.18.0.13 --restart always --name grafana grafana/grafana &
