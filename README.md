# Automated device configuration and monitoring management with Software Defined Networking #

## **NOTE:** This README is outdated. Please refer to PDFs supplied in Docs directory for Setup Guide and Lab Manual ##

A project focused on learning about Software Defined Networking, configuring and writing automated tools for use in the management and transition to such networks.

***

## Setup ##
### Install Docker ###
```
apt-get update && apt-get install docker.io
```
***
## Create Virtual Container Network ##
We will create a dedicated network for the docker containers we are going to run. This network will be named "**SDNet_Docker**" and use the subnet **172.18.0.0/16**.
```
docker network create --subnet=172.18.0.0/16 SDNet_Docker
```

***
## Pull and Run Relevant Docker Containers ##
***
### FloodLight SDN Controller ###
First we will pull a containerised version of the opensource SDN Controller "FloodLight". We will be using Floodlight for our demonstration due to its opensource nature and easy-to-interact-with API.
#### Pull the image ####
```
docker pull glefevre/floodlight
```
#### Run the container ####
We are going to deploy the FloodLight container now, using the IP **172.18.0.2** and name "**Floodlight_Controller**".
```
docker run --net SDNet_Docker --ip 172.18.0.2 \
              --name Floodlight_Controller \
              glefevre/floodlight
```
The Floodlight GUI is now available at **http://172.18.0.2:8080/ui/pages/index.html**

***
### Mininet ###
Mininet is a really cool application that allows the emulation of traditional networks within a virtual environment. It is commonly used for testing SDN controllers during their development. This application will allow us to run our applications as though they were on a traditional, physical network deployment.  
#### Pull the image ####
```
docker pull iwaseyusuke/mininet
```
#### Run the container ####
We are going to deploy the Mininet container now, using the IP **172.18.0.3** and name "**Mininet_Container**".
```
docker run -it --rm --privileged -e DISPLAY \
             --net SDNet_Docker --ip 172.18.0.3 \
             --name Mininet_Container \
             -v /tmp/.X11-unix:/tmp/.X11-unix \
             -v /lib/modules:/lib/modules \
             iwaseyusuke/mininet
```
***
### Portainer ###
Portainer acts as a user-friendly GUI for using docker. It is not required in this project, however is useful for docker/container management and is a good tool to implement for productivity.
#### Pull the image ####
```
docker pull portainer/portainer
```
#### Create Portainer Volume ####
Docker Containers use 'Volumes' to allow for persistant storage as by default, all data is stored within the running instance. To avoid this, we are going to create a volume for our Portainer instance. (We will have to reference this in our *docker run* command)
```
docker volume create portainer_data
```

#### Run the container ####
We are going to deploy the Portainer container now, using the IP **172.18.0.4** and name "**Portainer_GUI**". (We are going to be forwarding Portainer's Web-Interface (Port 9000) over to our host's own Port 9000.)
```
docker run -d -p 9000:9000 \
              --net SDNet_Docker --ip 172.18.0.4 \
              --name Portainer_GUI \
              -v /var/run/docker.sock:/var/run/docker.sock \
              -v portainer_data:/data portainer/portainer

```
After this command has been run, give it a minute and you should be able to access Portainer through your web browser by going to *http://localhost:9000*.
***
## Monitoring Data Pipeline ##
FloodLight API --> Telegraf --> Kafka --> Logstash --> ElasticSearch --> Kibana/Grafana
### Telegraf ###
Telegraf is an application that allows the exporting of data through a variety of inputs and plugins.

For this project, we are taking advantage of the **exec** input plugin; using python scripts that query the FloodLight API for relevant live statistical information.

The JSON data produced by these scripts is then pushed using the **kafka** output plugin every 5 seconds.

#### Build the docker image: ####
```
cd dockerfiles/telegraf_script && docker build -t telegraf_collector
```
#### Run the Telegraf container: ####
```
docker run --net SDNet_Docker \
           --ip 172.18.0.10 \
           --restart always \
           --name telegraf_collector \
           telegraf_collector &
```
### Kafka ###
Kafka is an application that is used to transport and queue data between a producer and storage. For this project we are using a single Kafka **Zookeeper** and 3 **Kafka Brokers** for redundancy and persistant messages in the event of destination downtime.

#### Build the images: ####
```
cd dockerfiles/kafka_9090 && docker build -t kafka_doc_9090 .

cd ../kakfa_9091 && docker build -t kafka_doc_9091 .

cd ../kakfa_9092 && docker build -t kafka_doc_9092 .

docker pull zookeeper
```

#### Run the Kafka containers: ####
```
 docker run --net SDNet_Docker \
            --ip 172.18.0.9 \
            --restart always \
            --name zookeeper \
            zookeeper &

 docker run --net SDNet_Docker \
            --ip 172.18.0.6 \
            --restart always \
            --env ADVERTISED_PORT=9090 \
            --env ZOOKEEPER_IP=172.18.0.9 \
            --env ZOOKEEPER_PORT=2181 \
            --env BROKER_ID=0 \
            --name kafka_9090_local \
            kafka_doc_9090  &

 docker run --net SDNet_Docker \
            --ip 172.18.0.7 \
            --restart always \
            --env ADVERTISED_PORT=9091 \
            --env ZOOKEEPER_IP=172.18.0.9 \
            --env ZOOKEEPER_PORT=2181 \
            --env BROKER_ID=1 \
            --name kafka_9091_local \
            kafka_doc_9091  &

 docker run --net SDNet_Docker \
            --ip 172.18.0.8 \
            --restart always \
            --env ADVERTISED_PORT=9092 \
            --env ZOOKEEPER_IP=172.18.0.9 \
            --env ZOOKEEPER_PORT=2181 \
            --env BROKER_ID=2 \
            --name kafka_9092_local \
            kafka_doc_9092  &
```
***
### ELK Stack ###
We will be implemented a containerised ELK Stack for our data pipeline. This stack includes applications ElasticSearch, Logstash and Kibana.
***
#### ElasticSearch ####
We will be using ElasticSearch as the datastore for the statistics we are pulling from Floodlight's API.
##### Build the docker image: #####
```
sudo sysctl -w vm.max_map_count=262144

cd dockerfiles/elastic && docker build -t elasticsearch_doc .
```
##### Run the ElasticSearch container: #####
```
sudo docker run --net SDNet_Docker \
                --ip 172.18.0.11 \
                --restart always \
                --log-opt max-size=50m \
                -v elastisearch_data:/usr/share/elasticsearch/data \
                --name elasticsearch \
                elasticsearch_doc &
```
***
#### Logstash ####
Logstash is used in our datapipeline to manipulate, filter and richen our data.
##### Build the docker image: #####
```
cd dockerfiles/logstash && docker build -t logstash_doc .
```
##### Run the Logstash container: #####
```
sudo docker run --net SDNet_Docker \
                --ip 172.18.0.12 \
                --restart always \
                --name logstash \
                logstash_doc &
```
***
#### Kibana ####
Kibana is used as the frontend GUI for ElasticSearch. It provides a good representation of Elastic's stored data and its frequency of input.
##### Build the docker image: #####
```
cd dockerfiles/kibana && docker build -t kibana_doc .
```
##### Run the Kibana container: #####
```
sudo docker run --net SDNet_Docker \
                -p 5601:5601 \
                --ip 172.18.0.14 \
                --restart always \
                --name kibana \
                kibana_doc &
```

Kibana's GUI is now available at **http://localhost:5601**


***
### Grafana ###
Grafana is an extremely versatile data visualisation tool that will be used as the user-facing interface for our SDN data graphing.
##### Build the docker image: #####
```
cd dockerfiles/grafana && docker build -t grafana_doc .
```
##### Run the Grafana container: #####
```
sudo docker run --net SDNet_Docker \
                -p 3000:3000 \
                --ip 172.18.0.13 \
                --restart always \
                --name grafana \
                grafana_doc &
```

An instance of Grafana is now available at **http://localhost:3000**

***
## Connecting Floodlight and Mininet ##
***
### Interacting with your Containers ###
Depending upon your preference, you can choose to interact with the containers either by using the command:
```
docker attach $CONTAINER_NAME
```
This will give you a direct shell into whichever container you choose to specify.


OR


You can use the Portainer GUI we referenced above. Simply head on over to *localhost:9000* in your preferred web-browser.
After proceeding through the authentication pages, you will see a list of your running containers.
Click the container you'd like to interact with and press the *shell* icon. Enter the container using **bash** and the user **root**.

***
### Starting the Mininet ###
We are going to use our Mininet Container to simulate a linear network of 3 routers and 3 switches - all connecting to our Floodlight controller.

To do this, we need to interact with our Mininet container via a shell using either method specified above.
```
docker attach Mininet_Container
```
***
Once directly interfacing with the container we are going to tell it to run Mininet, specify our SDN controller and the network specifications we desire.

After the controller's prompt, we will input the command:
```
mn --controller=remote,ip=172.18.0.2 --topo=linear,3
```
If successful, we should see output similar to:
```
*** Creating network

*** Adding controller
Connecting to remote controller at 172.18.0.2:6653

*** Adding hosts:
h1 h2 h3

*** Adding switches:
s1 s2 s3

*** Adding links:
(h1, s1) (h2, s2) (h3, s3) (s2, s1) (s3, s2)

*** Configuring hosts
h1 h2 h3

*** Starting controller
c0

*** Starting 3 switches
s1 s2 s3 ...

*** Starting CLI:

mininet>
```
A network of 3 Routers, 3 Switches and your external FloodLight Controller has been created.

You also have access to the Mininet prompt to interact with the individual network devices.
***
At this point if you open another tab in your browser and navigate to http://172.18.0.2:32785/ui/pages/index.html - You will be able to interact with the Floodlight controller through its GUI.

Click the topology tab on this page to see our virtual network devices appear correctly. It should be similar to the one shown below:

<img src="https://github.com/Faux212/SDN_ADC_MM/blob/master/images/mininet_topo.png" width="350" height="350">

***
