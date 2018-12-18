# Automated device configuration and monitoring management with Software Defined Networking #

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
sudo docker network create --subnet=172.18.0.0/16 SDNet_Docker
```

***
## Pull and Run Relevant Docker Containers ##
### FloodLight SDN Controller ###
First we will pull a containerised version of the opensource SDN Controller "FloodLight". We will be using Floodlight for our demonstration due to its opensource nature and easy-to-interact-with API.
#### Pull the image ####
```
docker pull glefevre/floodlight
```
#### Run the container ####
We are going to deploy the FloodLight container now, using the IP 172.18.0.2 and name "**Floodlight_Controller**".
```
docker run --net SDNet_Docker --ip 172.18.0.2 \
              --name Floodlight_Controller \
              glefevre/floodlight
```
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
              -v portainer_data:/data portainer/portainer \

```
After this command has been run, give it a minute and you should be able to access Portainer through your web browser by going to *localhost:9000*.
### Grafana ###
### Prometheus ###

***
## Connecting Floodlight and Mininet##
