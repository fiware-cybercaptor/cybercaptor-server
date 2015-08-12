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
 * along with FIWARE Cyber Security Generic Enabler.                                    *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/

package org.fiware.cybercaptor.server.rest;

import org.fiware.cybercaptor.server.api.AttackPathManagement;
import org.fiware.cybercaptor.server.api.InformationSystemManagement;
import org.fiware.cybercaptor.server.attackgraph.AttackGraph;
import org.fiware.cybercaptor.server.attackgraph.AttackPath;
import org.fiware.cybercaptor.server.attackgraph.MulvalAttackGraph;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.monitoring.Monitoring;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class of the XML REST AttackGraph API (/rest/attack_paths)
 *
 * @author Francois-Xavier Aguessy
 * @deprecated Use rather the JSON API: {@link RestJsonAPI}
 */
@Deprecated
@Path("/attack_paths")
public class RestAPIAttackPaths {

    @GET
    @Path("initialize")
    public Response initialise(@Context HttpServletRequest request) throws Exception {
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
        String databasePath = ProjectProperties.getProperty("database-path");

        Database database = null;
        try {
            database = new Database(databasePath);

        } catch (Exception e) {
            e.printStackTrace();
        }


        String topologyFilePath = ProjectProperties.getProperty("topology-path");

        Logger.getAnonymousLogger().log(Level.INFO, "Generating topology and mulval inputs " + topologyFilePath);
        InformationSystemManagement.prepareMulVALInputs();

        Logger.getAnonymousLogger().log(Level.INFO, "Loading topology " + topologyFilePath);
        InformationSystem informationSystem = InformationSystemManagement.loadTopologyXMLFile(topologyFilePath, database);


        AttackGraph attackGraph = InformationSystemManagement.generateAttackGraphWithMulValUsingAlreadyGeneratedMulVALInputFile();
        if (attackGraph == null)
            return Response.ok("the attack graph is empty").build();
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

        Logger.getAnonymousLogger().log(Level.INFO, "Attack paths scored");
        Monitoring monitoring = new Monitoring(costParametersFolderPath);
        monitoring.setAttackPathList(attackPaths);
        monitoring.setInformationSystem(informationSystem);
        monitoring.setAttackGraph((MulvalAttackGraph) attackGraph);

        request.getSession(true).setAttribute("database", database);
        request.getSession(true).setAttribute("monitoring", monitoring);
        return Response.ok("loaded").build();
    }

    @GET
    @Path("list")
    @Produces(MediaType.TEXT_XML)
    public Response getList(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null)
            return Response.status(Status.NO_CONTENT).build();

        Element attackPathsXML = org.fiware.cybercaptor.server.api.AttackPathManagement.getAttackPathsXML(monitoring);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return Response.ok(output.outputString(attackPathsXML)).build();
    }

    @GET
    @Path("{id}")
    @Produces(MediaType.TEXT_XML)
    public Response getAttackPath(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null)
            return Response.status(Status.NO_CONTENT).build();

        Element attackPathXML = org.fiware.cybercaptor.server.api.AttackPathManagement.getAttackPathXML(monitoring, id);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());

        return Response.ok(output.outputString(attackPathXML)).build();
    }

    @GET
    @Path("{id}/remediations")
    @Produces(MediaType.TEXT_XML)
    public Response getAttackPathRemediations(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));
        Database db = ((Database) request.getSession(true).getAttribute("database"));

        if (monitoring == null || db == null)
            return Response.status(Status.NO_CONTENT).build();

        Element remediationXML = org.fiware.cybercaptor.server.api.AttackPathManagement.getRemediationXML(monitoring, id, db);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());

        if (remediationXML == null)
            return Response.status(Status.PRECONDITION_FAILED).build();
        return Response.ok(output.outputString(remediationXML)).build();
    }

    @GET
    @Path("attack_graph")
    @Produces(MediaType.TEXT_XML)
    public Response getAttackGraph(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getAttribute("monitoring"));

        if (monitoring == null)
            return Response.status(Status.NO_CONTENT).build();

        Element attackGraphXML = monitoring.getAttackGraph().toDomElement();
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return Response.ok(output.outputString(attackGraphXML)).build();
    }
}
