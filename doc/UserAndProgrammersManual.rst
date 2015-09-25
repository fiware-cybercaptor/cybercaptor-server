CyberCAPTOR-Server - User and Programmer Guide
==========

This project is a part of FIWARE. For more information, please consult [FIWARE website] (http://www.fiware.org/).

CyberCAPTOR is an  implementation of the Cyber Security Generic Enabler, the future developments of the [Security Monitoring GE] (http://catalogue.fiware.org/enablers/security-monitoring).

The high-level README file of CyberCAPTOR-Server [can be found here](../README.md).

## Table of Contents

- [Introduction](#introduction)
- [User Guide](#user-guide)
	- [CyberCAPTOR-Server API](#cybercaptor-server-api)
		- [API usage](#api-usage)
  		- [Version API calls](#version-api-calls)
  		- [Initialization calls](#initialization-calls)
			- [Attack graph, attack paths and remediation calls](#attack-graph-attack-paths-and-remediation-calls)
- [Programmer Guide](#programmer-guide)
	- [Javadoc](#javadoc)
	- [API verification](#api-verification)

# Introduction
This is the User and Programmer Guide of CyberCAPTOR-Server.

# User Guide
This guide describe how to use CyberCAPTOR-Server.

## CyberCAPTOR-Server API

CyberCAPTOR-Server only contains the REST API Server of CyberCAPTOR. Thus, it can be used only via its REST API.
If you want a GUI for CyberCAPTOR-Server, you can use CyberCAPTOR-Client which is described in [https://github.com/fiware-cybercaptor/cybercaptor-client].

### API usage

#### Version API calls

To use the CyberCAPTOR server API, the first call to test that the server is available is

```
curl http://localhost:8080/cybercaptor-server/rest/version/detailed
```

which should returns something like

```
{"version":"4.4"}
```

#### Initialization calls

Before using the API to manipulate the attack graph, the attack paths, and the remediations,
the first call that needs to be done is

```
curl -c /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/initialize
```

which loads the topology, generates the attack graph with MulVAL and computes the attack paths.

Note the `-c /tmp/curl.cookie` option of curl, allowing to keep the session cookie, necessary to chain calls and keep
the attack graph and attack paths in session.

It is also possible to load the topology from an XML file, or a XML string containing the XML network topology, using the
POST method of the `/rest/json/initialize` call :

Using a XML String:

```
curl -c /tmp/curl.cookie -H "Content-Type: application/xml" -X POST -d '<topology><machine><name>linux-user-1</name><security_requirement>7</security_requirement><interfaces><interface><name>eth0</name><ipaddress>192.168.1.111</ipaddress><vlan><name>user-lan</name><label>user-lan</label></vlan></interface></interfaces><routes><route><destination>0.0.0.0</destination><mask>0.0.0.0</mask><gateway>192.168.1.111</gateway><interface>eth0</interface></route></routes></machine><machine><name>linux-user-2</name><security_requirement>30</security_requirement><interfaces><interface><name>eth0</name><ipaddress>192.168.1.112</ipaddress><vlan><name>user-lan</name><label>user-lan</label></vlan></interface></interfaces><services><service><name>mdns</name><ipaddress>192.168.1.112</ipaddress><protocol>udp</protocol><port>5353</port><vulnerabilities><vulnerability><type>remoteExploit</type><cve>CVE-2007-2446</cve><goal>privEscalation</goal><cvss>10.0</cvss></vulnerability></vulnerabilities></service></services><routes><route><destination>0.0.0.0</destination><mask>0.0.0.0</mask><gateway>192.168.1.111</gateway><interface>eth0</interface></route></routes></machine></topology>' http://localhost:8080/cybercaptor-server/rest/json/initialize
```

Using a XML file:

```
curl -c /tmp/curl.cookie -X POST  -H "Content-Type: multipart/form-data"  -F "file=@./topology.xml" http://localhost:8080/cybercaptor-server/rest/json/initialize
```

#### Attack graph, attack paths and remediation calls

Then, the calls to get the attack paths, attack graph or remediations can be used:

Get the number of attack paths:

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_path/number
```

Note the `-b /tmp/curl.cookie` option of curl, to load the previously saved session cookie.

Get the attack path 0:

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_path/0
```

Get the attack graph

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_graph
```

Get the remediations for attack path 0:

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/attack_path/0/remediations
```

Get the XML network topology (useful for backups):

```
curl -b /tmp/curl.cookie http://localhost:8080/cybercaptor-server/rest/json/topology
```

The full list of API calls and specifications is stored in [apiary.apib](../apiary.apib) and can be visualized on [Apiary.io](http://docs.cybercaptor.apiary.io/#) using the [Apiary Blueprint format](https://apiblueprint.org/).


# Programmer Guide
This guide describe how to develop within CyberCAPTOR-Server.

## Javadoc

The Javadoc of CyberCAPTOR-Server as well as many interesting information for developers can be found on github pages:  [Developer pages](https://fiware-cybercaptor.github.io/cybercaptor-server/) - [Javadoc](https://fiware-cybercaptor.github.io/cybercaptor-server/apidocs/index.html).

Javadoc can be updated directly with Maven using

```
 mvn site-deploy
```

Don't forget to configure GitHub OAuth token in `~/.m2/settings.xml`.
Tokens can be generated on https://github.com/settings/tokens, with repo and user:email authorized scopes.

```
<settings>
      <servers>
          <server>
                <id>github</id>
                <password>OAuth token</password>
          </server>
      </servers>
</settings>
```

### API verification

The API specified using Blueprint can be checked with the [dredd](https://github.com/apiaryio/dredd) tool.
In order to do that, first install bredd with NPM (you should have Node.js installed).

```
sudo npm install -g dredd
```

Go in the folder in which is the dredd configuration file [tools/api/dredd.yml](../tools/api/dredd.yml):

```
cd tools/api
```

Execute dredd

```
dredd
```

In addition to the console reports provided by dredd, a detailed report file can be found in `tools/api/report.html`.
