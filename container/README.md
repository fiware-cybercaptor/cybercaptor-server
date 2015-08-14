CyberCAPTOR Server
==============

[FIWARE Cyber seCurity Attack graPh moniTORing](https://fiware-cybercaptor.github.io/cybercaptor-server/) Docker container

This project is part of FIWARE. For more information, please consult [FIWARE website](http://www.fiware.org/).

CyberCAPTOR is an implementation of the Cyber Security Generic Enabler, the future developments of the [Security Monitoring GE](http://catalogue.fiware.org/enablers/security-monitoring).

Build Status: [![Build Status](https://travis-ci.org/fiware-cybercaptor/cybercaptor-server.svg)](https://travis-ci.org/fiware-cybercaptor/cybercaptor-server)

## How to use this Dockerfile

You can build a docker image based on this Dockerfile. 
This image will contain only the CyberCAPTOR Server, listenning on port `8080`. 
This requires that you have [docker](https://docs.docker.com/installation/) installed on your machine.

If you just want to have a CyberCAPTOR Server running as quickly as possible jump to section *The Fastest Way*.

If you want to know what is behind the scenes of our container you can go ahead and read the build and run sections.

## The Fastest Way

Docker will allow you to launch CyberCAPTOR server in a few seconds (without download time)
by pulling its image from the [Docker Hub](https://hub.docker.com/):

```
docker run --name cybercaptor-server -p 8080:8080 fiwarecybercaptor/cybercaptor-server
```

This will redirect `http://localhost:8080` to the container port `8080`.

## Build the image

This is an alternative approach to the one presented in the previous section. 
You do not need to go through these steps if you can use the up-to-date version on Dockerhub.
The end result will be the same, but this way you have a bit more of control of what's happening.

First, you need to download the sources [from Github](https://github.com/fiware-cybercaptor/cybercaptor-server)

```
git clone https://github.com/fiware-cybercaptor/cybercaptor-server.git
```

Then, build the container in the `container` folder

```
cd cybercaptor-server
cd container
docker build -t cybercaptor-server .
```

This can take some time, as several dependencies and builds need to be done. 
Note that the parameter `-t cybercaptor-server` gives the tag name of this container. This name could be anything, or even include an organization like `-t org/cybercaptor-server`. 
This name is later used to run the container based on the image.

If you want to know more about images and the building process you can find it in [Docker's documentation](https://docs.docker.com/userguide/dockerimages/).


Then, you can launch the container in a similar way as previously:

```
docker run --name cybercaptor-server -p 8080:8080 cybercaptor-server
```

You can find again the tag name `cybercaptor-server` to specify the container that you want to launch.
    
## Run the container

The following line will run the container exposing port `8080`, give it a name -in this case `cybercaptor-server`, 
and run it displaying its log console. This uses the image built in the previous section.

```
docker run --name cybercaptor-server -p 8080:8080 cybercaptor-server
```

It is also possible to launch it as a deamon (without displaying the logs) using the `-d` parameter

```
docker run --name cybercaptor-server -p 8080:8080 -d cybercaptor-server
```
