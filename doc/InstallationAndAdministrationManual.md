CyberCAPTOR-Server - Installation and Administration Manual
==========

This project is a part of FIWARE. For more information, please consult [FIWARE website] (http://www.fiware.org/).

CyberCAPTOR is an  implementation of the Cyber Security Generic Enabler, the future developments of the [Security Monitoring GE] (http://catalogue.fiware.org/enablers/security-monitoring).

The high-level README file of CyberCAPTOR-Server [can be found here](../README.md).

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
	- [Prerequisite](#prerequisite)
	- [Installation](#initialization)
	- [Test](#test)
- [Administration](#administration)


# Introduction
This is the Installation and Administration Manual for CyberCAPTOR-Server.

# Installation
This part detailed the procedure to install correctly CyberCAPTOR-Server.

## Development Version Installation

### Prerequisite

CyberCAPTOR-Server has been tested with the following software, but it should be possible to
build and run in on all *Linux* OS, with Java 7.

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

See in [#configuration] to see the description of all parameters used in the configuration file.

## Docker Version Deployment

### Build container (optional)

```
docker build -t cybercaptor-server .
```

### Run container

If you want to run the server in foreground, launch the following command:

```
docker run --rm --name cybercaptor-server -p 8000:8080 fiwarecybercaptor/cybercaptor-server
```

If you want to run the server in background, launch the following command:

```
docker run -d --rm --name cybercaptor-server -p 8000:8080 fiwarecybercaptor/cybercaptor-server
```

Then, the application can be accessed at http://localhost:8000/cybercaptor-server/.

More details about building and/or running the Docker container can be found in [container/README.md](../container/README.md)

### Test

Go on URL : http://localhost:8080/cybercaptor-server/rest/json/initialize

If the result is ```{"status":"Loaded"}```, the application has been properly built and installed.

# Administration

## Configuration file

The configuration file of CyberCAPTOR-Server allows to select many parameters and file paths used by CyberCAPTOR-Server.

This file is located in `configuration-files/config.properties`.

```
xsb-path=/opt/XSB/bin # The XSB installation binary path
output-path=/root/.remediation/tmp # The output folder for temporary computations
mulval-path=/opt/mulval/ # MulVAL installation path
mulval-rules-path=/root/.remediation/rules-with-topology.P # The MulVAL rules description file
cost-parameters-path=/root/.remediation/cost-parameters # The folder in which the remediation cost parameters are defined
database-path=/root/.remediation/vulnerability-remediation-database.db # The path toward the remediation database. A remediation database can be downloaded from https://github.com/fiware-cybercaptor/cyber-data-extraction/releases/download/4.4.1/vulnerability-remediation-database.db
python-path=/usr/bin/python # Python path
mulval-input-script-folder=/root/cyber-data-extraction/ # The folder in which the mulval input script is stored
host-interfaces-path=/root/.remediation/inputs/hosts-interfaces.csv # The path where the CSV host interfaces file is described (if using topology files on server)
vlans-path=/root/.remediation/inputs/vlans.csv # The path where the CSV vlans file is described (if using topology files on server)
routing-path=/root/.remediation/inputs/routing.csv # The path where the routing file is described (if using topology files on server)
flow-matrix-path=/root/.remediation/inputs/flow-matrix.csv # The path where the CSV flow matrix file is described (if using topology files on server)
vulnerability-scan-path=/root/.remediation/inputs/scan.nessus # The path where the Nessus XML file is described (if using topology files on server)
mulval-input=/root/.remediation/tmp/mulval-input-generated.P # The path where the MulVAL input file is stored.
topology-path=/root/.remediation/inputs/topology-generated.xml # The path where the topology file will be stored.
remediations-history-path=/root/.remediation/remediations-history.bin # The path where the remediation history is stored.
alerts-temporary-path=/root/.remediation/alerts-temp.bin # The path where the IDMEF alerts are temporary stored.
```

More information about the parameters can be found in [CyberCAPTOR-Data-Extraction README](https://github.com/fiware-cybercaptor/cybercaptor-data-extraction).

# Sanity check procedures

## End to End testing

Go on URL : http://localhost:8080/cybercaptor-server/rest/json/initialize

If the result is ```{"status":"Loaded"}```, the application has been properly built and installed.

## List of Running Processes

### Execution of .war with tomcat7

```
# Results of ps -aux
root        20 12.1  4.1 3753696 337544 ?      Sl   11:45   0:09 /usr/bin/java -Djava.util.logging.config.file=/var/lib/tomcat7/conf/logging.properties -Djava.util.
root        66  0.0  0.0   4448  1568 ?        S    11:46   0:00 /bin/sh /opt/mulval//utils/graph_gen.sh /root/.remediation/tmp/mulval-input-generated.P -l -r /root
root       127  0.0  0.1  30076 14196 ?        R    11:46   0:00 /opt/XSB/config/x86_64-unknown-linux-gnu/bin/xsb
```


### Execution via Docker

When idle
```
# Results of ps -aux in docker container
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.4  0.1  28236  9584 ?        Ss   11:45   0:00 /usr/bin/python3 -u /sbin/my_init
root         8  0.0  0.0    196    40 ?        S    11:45   0:00 /usr/bin/runsvdir -P /etc/service
root         9  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv tomcat7
root        10  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv syslog-ng
root        11  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv sshd
root        12  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv cron
root        13  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv syslog-forwarder
root        14  0.0  0.0  26752  2688 ?        S    11:45   0:00 /usr/sbin/cron -f
root        15  0.0  0.0   7480   704 ?        S    11:45   0:00 tail -f -n 0 /var/log/syslog
root        16  0.1  0.0  65760  6672 ?        S    11:45   0:00 syslog-ng -F -p /var/run/syslog-ng.pid --no-caps
root        17  0.0  0.0  21088  3196 ?        S    11:45   0:00 bash ./run
root        20 60.5  4.0 3749936 329468 ?      Sl   11:45   0:09 /usr/bin/java -Djava.util.logging.config.file=/var/lib/tomcat7/conf/logging.properties -Djava.util.
```

When MuLlVAL is running
```
# Results of ps -aux in docker container
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  28236  9584 ?        Ss   11:45   0:00 /usr/bin/python3 -u /sbin/my_init
root         8  0.0  0.0    196    40 ?        S    11:45   0:00 /usr/bin/runsvdir -P /etc/service
root         9  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv tomcat7
root        10  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv syslog-ng
root        11  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv sshd
root        12  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv cron
root        13  0.0  0.0    176     4 ?        Ss   11:45   0:00 runsv syslog-forwarder
root        14  0.0  0.0  26752  2688 ?        S    11:45   0:00 /usr/sbin/cron -f
root        15  0.0  0.0   7480   704 ?        S    11:45   0:00 tail -f -n 0 /var/log/syslog
root        16  0.0  0.0  65760  6672 ?        S    11:45   0:00 syslog-ng -F -p /var/run/syslog-ng.pid --no-caps
root        17  0.0  0.0  21088  3196 ?        S    11:45   0:00 bash ./run
root        20 12.1  4.1 3753696 337544 ?      Sl   11:45   0:09 /usr/bin/java -Djava.util.logging.config.file=/var/lib/tomcat7/conf/logging.properties -Djava.util.
root        66  0.0  0.0   4448  1568 ?        S    11:46   0:00 /bin/sh /opt/mulval//utils/graph_gen.sh /root/.remediation/tmp/mulval-input-generated.P -l -r /root
root       127  0.0  0.1  30076 14196 ?        R    11:46   0:00 /opt/XSB/config/x86_64-unknown-linux-gnu/bin/xsb
```

## Network interfaces Up & Open

The only port that needs to be open is the one chosen either by tomcat server, either for Docker container. It is port 8080 in examples above.

# Diagnosis Procedures

## Resource availability

The amount of RAM and hard disk needed for CyberCAPTOR-Server can be high, according to the network topology. 8Gb of RAM and 1Go of hard disk dedicated to the application should be enough for a small-medium systems. For medium to big information systems, 32Gb of RAM and 30Go of hard disk dedicated to the application may be needed.

## Main logs files

The main logs of the application can be accessed with

- ``` /var/log/tomcat7/catalina.out ```
- ``` `pwd`/configuration-files/tmp/xsb_log.txt ```
- ``` `pwd`/configuration-files/tmp/input-generation.log ```

In docker container, they can be accessed with the following commands:

- ```docker exec cybercaptor-server tail -n 50 -f /var/log/tomcat7/catalina.out```
- ```docker exec cybercaptor-server tail -f /root/.remediation/tmp/tmp/xsb_log.txt```
- ```docker exec cybercaptor-server tail -f /root/.remediation/tmp/tmp/input-generation.log```
