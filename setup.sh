#!/bin/bash
echo "Installing Docker..."
apt-get update && apt-get install docker.io

echo "Creating Virtual Network 'SDNet_Docker' (172.18.0.0/16)..."
docker network create --subnet=172.18.0.0/16 SDNet_Docker

echo "Pulling and Running 'Floodlight_Controller' (172.18.0.2)..."
docker pull glefevre/floodlight

docker run --net SDNet_Docker --ip 172.18.0.2 \
              --name Floodlight_Controller \
              glefevre/floodlight

echo "Pulling and Running 'Mininet_Container' (172.18.0.3)..."
docker pull iwaseyusuke/mininet

docker run -it --rm --privileged -e DISPLAY \
             --net SDNet_Docker --ip 172.18.0.3 \
             --name Mininet_Container \
             -v /tmp/.X11-unix:/tmp/.X11-unix \
             -v /lib/modules:/lib/modules \
             iwaseyusuke/mininet

echo "Pulling and Running 'Portainer_GUI' (172.18.0.4)..."
docker pull portainer/portainer

docker volume create portainer_data

docker run -d -p 9000:9000 \
              --net SDNet_Docker --ip 172.18.0.4 \
              --name Portainer_GUI \
              -v /var/run/docker.sock:/var/run/docker.sock \
              -v portainer_data:/data portainer/portainer \
