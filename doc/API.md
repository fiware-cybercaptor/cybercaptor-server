FORMAT: 1A

# CyberCAPTOR server

**CyberCAPTOR server** is the Java REST API Server of [FIWARE Cyber seCurity Attack graPh moniTORing](https://github.com/fiware-cybercaptor/cybercaptor-server).

# Group REST API without init
API calls **without** the need of the `initialize` call (the load of the database and generation of the attack path).

## Group Version
Get REST API version information.

### Version [GET /rest/version]
Get the simple version of the API. Generally useful to makes some tests.

+ Response 200 (text/plain)

        4.4

### VersionDetailed [GET /rest/version/detailed]
Get the API version in JSON.

+ Response 200 (application/json)
    + Body

            {"version":"4.4"}
            
# Group REST API after init
API calls **after** the `initialize` call (the load of the database and generation of the attack path).


## Initialize [/rest/json/initialize]
Generates the attack graph and initializes the main objects needed by other API calls (database, attack graph, attack paths,...).

### Initialize from data on disk [GET]

+ Response 200 (application/json)

        {"status":"Loaded"}

## Group Host with init [/rest/json/host/list]
Calls related to hosts after initialization.

### Get the host list [GET]
Get the list of hosts with their security requirements.

+ Response 200 (application/json)

        {"hosts":[]}
        
### Set the host list [POST]
Set the hosts and their security_requirements.

+ Request (application/json)

        {"hosts":[{"security_requirements":[{"metric":"High","name":"sec-req-xml"}],"name":"linux-user-1"},{"security_requirements":[{"metric":"High","name":"sec-req-xml"}],"name":"linux-user-2"}]}

+ Response 200 (application/json)

        {}
        
## Group Attack graph with init [/rest/json/attack_graph]
Calls related to the attack graph after initialization.

### Get the attack graph [GET]
Get the attack graph

+ Response 200 (application/json)

        {"attack_graph":{"arcs":{},"vertices":{}}}
        
### Get the attack graph score [GET /rest/json/attack_graph/score]
Get the attack graph score.

+ Response 200 (application/json)

        {"score":""}
        
### Get the topological attack graph [GET /rest/json/attack_graph/topological]
Get the attack graph in its topological form.

+ Response 200 (application/json)

        {"arcs":{}, "vertices":{}}
        
## Group Attack path with init [/rest/json/attack_path]
Calls related to the attack paths after initialization.

### Get the attack paths list [GET /rest/json/attack_path/list]
Get the list of attack paths.

+ Response 200 (application/json)

        {"attack_paths":{}}
        
### Get the number of attack paths [GET /rest/json/attack_path/number]
Get the number of attack paths.

+ Response 200 (application/json)

        {"number":2}

### Get one attack path [GET /rest/json/attack_path/{id}]
Get the attack path {id}.

+ Parameters
    + id: 0 (number, required) - The number of attack path to get

+ Response 200 (application/json)
    + Attributes (object)
        + id: 0
    + Body

            {"attack_path":{}}

### Get one attack path in topological form [GET /rest/json/attack_path/{id}/topological]
Get the attack path {id} as a topological graph.

+ Parameters
    + id: 0 (number, required) - The number of attack path to get in topological form

+ Response 200 (application/json)
    + Attributes (object)
        + id: 0
    + Body

            {"arcs":{}, "vertices":{}}
            
### Get the remediations to an attack path [GET /rest/json/attack_path/{id}/remediations]
Get the remediations of the attack path {id}.

+ Parameters
    + id: 0 (number, required) - The number of the attack path for which remediations will be calculated

+ Response 200 (application/json)
    + Attributes (object)
        + id: 0
    + Body

            {"remediations":{}}
            
### Simulate the remediation to an attack path [GET /rest/json/attack_path/{id}/remediation/{id_remediation}]
Simulate the remediation {id_remediation} of the path {id}, and compute the new attack graph.

+ Parameters
    + id: 0 (number, required) - The number of the attack path for which remediations will be calculated
    + id_remediation: 0 (number, required) - The number of the remediation to apply.

+ Response 200 (application/json)
    + Attributes (object)
        + id: 0
        + id_remediation: 0
    + Body

            {"attack_graph":{"arcs":{},"vertices":{}}
