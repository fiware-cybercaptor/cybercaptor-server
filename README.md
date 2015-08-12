cybercaptor-server
==============

Cyber Security Monitoring Tool based on Attack Graphs - Server (Computing)

This project is part of FIWARE. For more information, please consult [FIWARE website](http://www.fiware.org/).

CyberCAPTOR is an implementation of the Cyber Security Generic Enabler, the future developments of the [Security Monitoring GE](http://catalogue.fiware.org/enablers/security-monitoring).

Build Status: [![Build Status](https://travis-ci.org/fiware-cybercaptor/cybercaptor-server.svg)](https://travis-ci.org/fiware-cybercaptor/cybercaptor-server)


## Development Version Installation

### Prerequisite
- Ubuntu 
- Java 1.7
- Apache Tomcat 7
- Apache Maven 3
- [XSB](http://xsb.sourceforge.net/)
- [MulVAL](http://www.arguslab.org/mulval.html)

### Build

1) Get sources from Github
```
git clone https://github.com/fiware-cybercaptor/cybercaptor-server.git
cd cybercaptor-server 
```

2) Use Maven to download dependencies and build the web application archive (.war).
```
mvn clean
mvn package
```

### Installation

1) Deploy the .war into tomcat.

Using command line

```
cp ./target/cybercaptor-server*.war /var/lib/tomcat7/webapps/cybercaptor-server.war
```

This can also be done using the tomcat GUI manager, or with Maven's tomcat7 plugin.

2) Link the configuration and scripts repertory and fix permissions

```
sudo ln -s `pwd`/configuration-files /usr/share/tomcat7/.remediation
sudo ln -s `pwd`/src/main/python/ /usr/share/tomcat7/python_scripts
chmod -R o+rw ./configuration-files/
sudo chown -R tomcat7:tomcat7 /usr/share/tomcat7/
```

3) Copy and edit the configuration file

```
cp ./configuration-files/config.properties.sample ./configuration-files/config.properties
vim ./configuration-files/config.properties

```

### Test 

Go on URL : http://localhost:8080/cybercaptor-server/rest/json/initialize

If the result is ```{"status":"Loaded"}```, the application has been properly built and installed.

## Docker Version Deployment

### Build container (optional)

```
docker build -t cybersecurityge .
```

### Run container

If you want to run the server in foreground, launch the following command:

```
docker run --rm --name cybersecurityge -p 8000:8080 cybersecurityge
```

If you want to run the server in background, launch the following command:

```
docker run -d --rm --name cybersecurityge -p 8000:8080 cybersecurityge
```

Then, the application can be accessed at http://localhost:8000/cybercaptor-server/.

## Debugging

### Main logs files 
- ``` /var/log/tomcat7/catalina.out ```
- ``` `pwd`/configuration-files/tmp/xsb_log.txt ```
- ``` `pwd`/configuration-files/tmp/input-generation.log ```
