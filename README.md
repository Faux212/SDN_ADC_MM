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
              -v portainer_data:/data portainer/portainer \

```
After this command has been run, give it a minute and you should be able to access Portainer through your web browser by going to *localhost:9000*.
***
### Grafana ###
***
### Prometheus ###
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
