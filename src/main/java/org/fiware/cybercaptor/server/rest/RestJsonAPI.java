/****************************************************************************************
 * This file is part of FIWARE CyberCAPTOR,                                             *
 * instance of FIWARE Cyber Security Generic Enabler                                    *
 * Copyright (C) 2012-2015  Thales Services S.A.S.,                                     *
 * 20-22 rue Grande Dame Rose 78140 VELIZY-VILACOUBLAY FRANCE                           *
 *                                                                                      *
 * FIWARE CyberCAPTOR is free software; you can redistribute                            *
 * it and/or modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 3 of the License,       *
 * or (at your option) any later version.                                               *
 *                                                                                      *
 * FIWARE CyberCAPTOR is distributed in the hope                                        *
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied           *
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 * GNU General Public License for more details.                                         *
 *                                                                                      *
 * You should have received a copy of the GNU General Public License                    *
 * along with FIWARE CyberCAPTOR.                                                       *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/
package org.fiware.cybercaptor.server.rest;

import org.fiware.cybercaptor.server.api.AttackPathManagement;
import org.fiware.cybercaptor.server.api.InformationSystemManagement;
import org.fiware.cybercaptor.server.attackgraph.AttackGraph;
import org.fiware.cybercaptor.server.attackgraph.AttackPath;
import org.fiware.cybercaptor.server.attackgraph.MulvalAttackGraph;
import org.fiware.cybercaptor.server.attackgraph.Vertex;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.monitoring.Monitoring;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.remediation.DeployableRemediation;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.json.JSONObject;
import org.json.XML;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JSON Rest API, main API, since the XML API has been depreciated.
 *
 * @author Francois -Xavier Aguessy
 */
@Path("/json/")
public class RestJsonAPI {

    /**
     * Returns the {@link javax.ws.rs.core.Response} object from a {@link org.json.JSONObject}
     *
     * @param jsonObject the jsonObject to return
     * @return the relative {@link javax.ws.rs.core.Response} object
     */
    public static Response returnJsonObject(JSONObject jsonObject) {
        return Response.ok(jsonObject.toString())
                .header("Access-Control-Allow-Origin", "http://localhost")
                .header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
                .header("Access-Control-Max-Age", "1209600")
                .build();
    }

    /**
     * Returns an error message, in a {@link org.json.JSONObject} ({error:"the error message"}
     *
     * @param errorMessage the error message to return
     * @return the {@link javax.ws.rs.core.Response} to this {@link org.json.JSONObject}
     */
    public static Response returnErrorMessage(String errorMessage) {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("error", errorMessage);

        return returnJsonObject(jsonObject);
    }

    /**
     * Generates the attack graph and initializes the main objects for other API calls
     * (database, attack graph, attack paths,...)
     *
     * @param request the HTTP request
     * @return the HTTP response
     * @throws Exception
     */
    @GET
    @Path("initialize")
    @Produces(MediaType.APPLICATION_JSON)
    public Response initialise(@Context HttpServletRequest request) throws Exception {
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
        String databasePath = ProjectProperties.getProperty("database-path");

        //Load the vulnerability and remediation database
        Database database = new Database(databasePath);

        String topologyFilePath = ProjectProperties.getProperty("topology-path");

        Logger.getAnonymousLogger().log(Level.INFO, "Generating topology and mulval inputs " + topologyFilePath);
        InformationSystemManagement.prepareMulVALInputs();

        Logger.getAnonymousLogger().log(Level.INFO, "Loading topology " + topologyFilePath);
        InformationSystem informationSystem = InformationSystemManagement.loadTopologyXMLFile(topologyFilePath, database);


        AttackGraph attackGraph = InformationSystemManagement.generateAttackGraphWithMulValUsingAlreadyGeneratedMulVALInputFile();
        if (attackGraph == null)
            return returnErrorMessage("the attack graph is empty");
        Logger.getAnonymousLogger().log(Level.INFO, "Launch scoring function");
        attackGraph.loadMetricsFromTopology(informationSystem);
        List<AttackPath> attackPaths = AttackPathManagement.scoreAttackPaths(attackGraph, attackGraph.getNumberOfVertices());

        //Delete attack paths that have less than 3 hosts (attacker that pown its own host).
        List<AttackPath> attackPathToKeep = new ArrayList<AttackPath>();
        for (AttackPath attackPath : attackPaths) {
            if (attackPath.vertices.size() > 3) {
                attackPathToKeep.add(attackPath);
            }
        }
        attackPaths = attackPathToKeep;

        Logger.getAnonymousLogger().log(Level.INFO, attackPaths.size() + " attack paths scored");
        Monitoring monitoring = new Monitoring(costParametersFolderPath);
        monitoring.setAttackPathList(attackPaths);
        monitoring.setInformationSystem(informationSystem);
        monitoring.setAttackGraph((MulvalAttackGraph) attackGraph);

        request.getSession(true).setAttribute("database", database);
        request.getSession(true).setAttribute("monitoring", monitoring);

        return returnJsonObject(new JSONObject().put("status", "Loaded"));
    }

    /**
     * OPTIONS call necessary for the Access-Control-Allow-Origin of the POST
     *
     * @param servletResponse the response
     * @return the HTTP response
     */
    @OPTIONS
    @Path("/initialize")
    public Response initializeOptions(@Context HttpServletResponse servletResponse) {
        prepareResponse(servletResponse);
        return null;
    }

    /**
     * Generates the attack graph and initializes the main objects for other API calls
     * (database, attack graph, attack paths,...).
     * Load the objects from the POST XML file describing the whole network topology
     *
     * @param request the HTTP request
     * @return the HTTP response
     * @throws Exception
     */
    @POST
    @Path("/initialize")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response initializeFromXMLFile(@Context HttpServletRequest request, String xmlString) throws Exception {
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
        String databasePath = ProjectProperties.getProperty("database-path");

        if (xmlString == null || xmlString.isEmpty())
            return returnErrorMessage("The input file is empty.");

        Logger.getAnonymousLogger().log(Level.INFO, "Load the vulnerability and remediation database");
        Database database = new Database(databasePath);

        String topologyFilePath = ProjectProperties.getProperty("topology-path");

        Logger.getAnonymousLogger().log(Level.INFO, "Storing topology in " + topologyFilePath);
        PrintWriter out = new PrintWriter(topologyFilePath);
        out.print(xmlString);
        out.close();

        Logger.getAnonymousLogger().log(Level.INFO, "Loading topology " + topologyFilePath);

        InformationSystem informationSystem = InformationSystemManagement.loadTopologyXMLFile(topologyFilePath, database);

        AttackGraph attackGraph = InformationSystemManagement.prepareInputsAndExecuteMulVal(informationSystem);

        if (attackGraph == null)
            return returnErrorMessage("the attack graph is empty");
        Logger.getAnonymousLogger().log(Level.INFO, "Launch scoring function");
        attackGraph.loadMetricsFromTopology(informationSystem);

        List<AttackPath> attackPaths = AttackPathManagement.scoreAttackPaths(attackGraph, attackGraph.getNumberOfVertices());

        //Delete attack paths that have less than 3 hosts (attacker that pown its own host).
        List<AttackPath> attackPathToKeep = new ArrayList<AttackPath>();
        for (AttackPath attackPath : attackPaths) {
            if (attackPath.vertices.size() > 3) {
                attackPathToKeep.add(attackPath);
            }
        }
        attackPaths = attackPathToKeep;

        Logger.getAnonymousLogger().log(Level.INFO, attackPaths.size() + " attack paths scored");
        Monitoring monitoring = new Monitoring(costParametersFolderPath);
        monitoring.setAttackPathList(attackPaths);
        monitoring.setInformationSystem(informationSystem);
        monitoring.setAttackGraph((MulvalAttackGraph) attackGraph);

        request.getSession(true).setAttribute("database", database);
        request.getSession(true).setAttribute("monitoring", monitoring);

        return returnJsonObject(new JSONObject().put("status", "Loaded"));
    }

    /**
     * Get the XML topology
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("/topology")
    @Produces(MediaType.APPLICATION_XML)
    public Response getTopology(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return Response.ok("The monitoring object is empty. Did you forget to " +
                    "initialize it ?").build();
        }
        return Response.ok(new XMLOutputter(Format.getPrettyFormat()).outputString(monitoring.getInformationSystem().toDomXMLElement())).build();
    }

    /**
     * Get the hosts list
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("host/list")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getHostList(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }
        return returnJsonObject(monitoring.getInformationSystem().getHostsListJson());
    }

    @OPTIONS
    @Path("/host/list")
    public Response setHostListOptions(@Context HttpServletResponse servletResponse) {
        prepareResponse(servletResponse);
        return null;
    }

    /**
     * Post the hosts list with their new security requirements
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @POST
    @Path("host/list")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setHostList(@Context HttpServletRequest request, String jsonString) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }
        JSONObject json = new JSONObject(jsonString);
        try {
            InformationSystemManagement.loadHostsSecurityRequirementsFromJson(monitoring, json);
            return returnJsonObject(null);
        } catch (Exception e) {
            return returnErrorMessage(e.getMessage());
        }


    }

    /**
     * Get the attack paths list
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/list")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getList(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        Element attackPathsXML = AttackPathManagement.getAttackPathsXML(monitoring);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return returnJsonObject(XML.toJSONObject(output.outputString(attackPathsXML)));

    }

    /**
     * Get the number of attack paths
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/number")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getNumber(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        return returnJsonObject(new JSONObject().put("number", monitoring.getAttackPathList().size()));
    }

    /**
     * Get one attack path (id starting from 0)
     *
     * @param request the HTTP Request
     * @param id      the id of the attack path to get
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackPath(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return returnErrorMessage("The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        Element attackPathXML = AttackPathManagement.getAttackPathXML(monitoring, id);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());

        return returnJsonObject(XML.toJSONObject(output.outputString(attackPathXML)));
    }

    /**
     * Get one attack path (id starting from 0) in its topological form
     *
     * @param request the HTTP Request
     * @param id      the id of the attack path to get
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}/topological")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTopologicalAttackPath(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return returnErrorMessage("The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        return returnJsonObject(AttackPathManagement.getAttackPathTopologicalJson(monitoring, id));
    }

    /**
     * Compute and return the remediations for an attack path
     *
     * @param request the HTTP Request
     * @param id      the identifier of the attack path for which the remediations will be computed
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}/remediations")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackPathRemediations(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));
        Database db = ((Database) request.getSession(true).getAttribute("database"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        if (db == null) {
            return returnErrorMessage("The database object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return returnErrorMessage("The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        Element remediationXML = AttackPathManagement.getRemediationXML(monitoring, id, db);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());

        return returnJsonObject(XML.toJSONObject(output.outputString(remediationXML)));
    }

    /**
     * Simulate the remediation id_remediation of the path id, and compute the new attack graph
     *
     * @param request        the HTTP Request
     * @param id             the identifier of the attack path for which the remediations will be computed
     * @param id_remediation the identifier of the remediation to simulate
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}/remediation/{id-remediation}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response simulateRemediationInAttackGraph(@Context HttpServletRequest request, @PathParam("id") int id, @PathParam("id-remediation") int id_remediation) throws Exception {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));
        Database db = ((Database) request.getSession(true).getAttribute("database"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        if (db == null) {
            return returnErrorMessage("The database object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return returnErrorMessage("The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        List<DeployableRemediation> remediations = monitoring.getAttackPathList().get(id).getDeployableRemediations(monitoring.getInformationSystem(), db.getConn(), monitoring.getPathToCostParametersFolder());

        int numberRemediations = remediations.size();

        if (id_remediation >= numberRemediations) {
            return returnErrorMessage("The remediation " + id_remediation + " does not exist. There are only" +
                    numberRemediations + " remediations (0 to " +
                    (numberRemediations - 1) + ")");
        }
        DeployableRemediation deployableRemediation = remediations.get(id_remediation);

        AttackGraph simulatedAttackGraph;

        try {
            simulatedAttackGraph = monitoring.getAttackGraph().clone();

            for (int i = 0; i < deployableRemediation.getActions().size(); i++) {
                Vertex vertexToDelete = deployableRemediation.getActions().get(i).getRemediationAction().getRelatedVertex();
                simulatedAttackGraph.deleteVertex(simulatedAttackGraph.vertices.get(vertexToDelete.id));
            }

            AttackPathManagement.scoreAttackPaths(simulatedAttackGraph, monitoring.getAttackGraph().getNumberOfVertices());

            Element attackGraphXML = simulatedAttackGraph.toDomElement();
            XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
            return returnJsonObject(XML.toJSONObject(output.outputString(attackGraphXML)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return returnErrorMessage("Error during the simulation of the remediation.");

    }

    /**
     * Get the whole attack graph
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_graph")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackGraph(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        Element attackGraphXML = monitoring.getAttackGraph().toDomElement();
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return returnJsonObject(XML.toJSONObject(output.outputString(attackGraphXML)));
    }

    /**
     * Get the attack graph score
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_graph/score")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackGraphScore(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        return returnJsonObject(new JSONObject().put("score", monitoring.getAttackGraph().globalScore));
    }

    /**
     * Get the topological representation of the whole attack graph
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_graph/topological")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTopologicalAttackGraph(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null) {
            return returnErrorMessage("The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        return returnJsonObject(AttackPathManagement.getAttackGraphTopologicalJson(monitoring));
    }

    protected void prepareResponse(@Context HttpServletResponse servletResponse) {
        servletResponse.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
        servletResponse.addHeader("Access-Control-Allow-Credentials", "true");
        servletResponse.addHeader("Access-Control-Allow-Origin", "http://localhost");
        servletResponse.addHeader("Access-Control-Allow-Headers", "origin, content-type, accept, authorization, Content-Type, X-Requested-With");
        servletResponse.addHeader("Access-Control-Max-Age", "1209600");
    }
}
