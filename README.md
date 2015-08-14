CyberCAPTOR Server
==============

FIWARE Cyber seCurity Attack graPh moniTORing - Server

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

## API

### API usage

To use the CyberCAPTOR server API, the first call to test that the server is available is

```
curl http://localhost:8080/cybercaptor-server/rest/version/detailed
```

which should returns something like

```
{"version":"4.4"}
```

Before using the API to manipulate the attack graph, the attack paths, and the remediations, 
the first call that needs to be done is 

```
curl -c /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/initialize
```

which loads the topology, generates the attack graph with MulVAL and computes the attack paths.

Note the `-c /tmp/curl.cookie` option of curl, allowing to keep the session cookie, necessary to chain calls and keep
the attack graph and attack paths in session.

Then, the calls to get the attack paths, attack graph or remediations can be used:

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_path/number # Get the number of attack paths
```

Note the `-b /tmp/curl.cookie` option of curl, to load the previously saved session cookie.

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_path/0 # Get the attack path 0
```

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_graph # Get the attack graph
```

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_path/0/remediations # Get the remediations for attack path 0
```

The full list of API calls and specifications can be found in [doc/API.md](doc/API.md) using the [API blueprint](https://apiblueprint.org/) syntax.

### API verification

The API specified using Blueprint can be checked with the [dredd](https://github.com/apiaryio/dredd) tool.
In order to do that, first install bredd with NPM (you should have Node.js installed).

```
sudo npm install -g dredd
```

Go in the folder in which is the dredd configuration file [tools/api/dredd.yml](tools/api/dredd.yml):

```
cd tools/api
```

Execute dredd

```
dredd
```

In addition to the console reports provided by dredd, a detailed report file can be found in `tools/api/report.html`.