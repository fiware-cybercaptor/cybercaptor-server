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

import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.remediation.cost.GlobalParameters;
import org.fiware.cybercaptor.server.remediation.cost.OperationalCostParameters;
import org.jdom2.Document;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.json.JSONObject;
import org.json.XML;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.StringReader;

/**
 * JSON Rest API, configuration REST calls.
 *
 * @author Francois -Xavier Aguessy
 */
@Path("/json/configuration/")
public class RestJsonConfiguration {
    /**
     * Get the global cost parameters
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("/remediation-cost-parameters/global")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGlobalCostParameters(@Context HttpServletRequest request) {
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
        GlobalParameters globalParameters = new GlobalParameters();
        try {
            globalParameters.loadFromXMLFile(costParametersFolderPath + "/" + GlobalParameters.FILE_NAME);
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "The global parameters " +
                    "can not be load: " + e.getMessage());
        }

        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return RestApplication.returnJsonObject(request, XML.toJSONObject(output.outputString(globalParameters.toDomElement())));
    }

    /**
     * OPTIONS necessary for global cost parameters
     *
     * @param request the HTTP Request
     * @return the HTTP Response (empty OK)
     */
    @OPTIONS
    @Path("/remediation-cost-parameters/global")
    public Response setGlobalCostParametersOptions(@Context HttpServletRequest request) {
        return RestApplication.returnJsonObject(request, new JSONObject());
    }

    /**
     * Set the global cost parameters
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @POST
    @Path("/remediation-cost-parameters/global")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setGlobalCostParameters(@Context HttpServletRequest request, String jsonString) {
        JSONObject json = new JSONObject(jsonString);
        String xmlString = XML.toString(json);
        SAXBuilder sxb = new SAXBuilder();
        Document document = null;
        try {
            document = sxb.build(new InputSource(new StringReader(xmlString)));
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "Can not load the JSON" +
                    " string: " + e.getMessage());
        }
        GlobalParameters globalParameters = new GlobalParameters();
        globalParameters.loadFromDomDocument(document);
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");

        try {
            globalParameters.saveToXMLFile(costParametersFolderPath + "/" + GlobalParameters.FILE_NAME);
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "Can not save to XML file" +
                    " string: " + e.getMessage());
        }
        return RestApplication.returnJsonObject(request, new JSONObject());
    }

    /**
     * Get the operational cost parameters for a snort rule.
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("/remediation-cost-parameters/snort-rule")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSnortRuleCostParameters(@Context HttpServletRequest request) {
        return buildResponseForOperationalCostParameters(request, OperationalCostParameters.FILE_NAME_SNORT_RULE);
    }

    /**
     * OPTIONS necessary for operational cost parameters
     *
     * @param request the HTTP Request
     * @return the HTTP Response (empty OK)
     */
    @OPTIONS
    @Path("/remediation-cost-parameters/snort-rule")
    public Response setSnortRuleCostParameters(@Context HttpServletRequest request) {
        return RestApplication.returnJsonObject(request, new JSONObject());
    }

    /**
     * Set the operational cost parameters for a snort rule.
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @POST
    @Path("/remediation-cost-parameters/snort-rule")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setSnortRuleCostParameters(@Context HttpServletRequest request, String jsonString) {
        return saveAndBuildResponseForOperationalCostParameters(request, OperationalCostParameters.FILE_NAME_SNORT_RULE, jsonString);
    }


    /**
     * Get the operational cost parameters for a firewall rule.
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("/remediation-cost-parameters/firewall-rule")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getFirewallRuleCostParameters(@Context HttpServletRequest request) {
        return buildResponseForOperationalCostParameters(request, OperationalCostParameters.FILE_NAME_FIREWALL_RULE);
    }

    /**
     * OPTIONS necessary for operational cost parameters
     *
     * @param request the HTTP Request
     * @return the HTTP Response (empty OK)
     */
    @OPTIONS
    @Path("/remediation-cost-parameters/firewall-rule")
    public Response setFirewallRuleCostParameters(@Context HttpServletRequest request) {
        return RestApplication.returnJsonObject(request, new JSONObject());
    }

    /**
     * Set the operational cost parameters for a firewall rule.
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @POST
    @Path("/remediation-cost-parameters/firewall-rule")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setFirewallRuleCostParameters(@Context HttpServletRequest request, String jsonString) {
        return saveAndBuildResponseForOperationalCostParameters(request, OperationalCostParameters.FILE_NAME_FIREWALL_RULE, jsonString);
    }

    /**
     * Get the operational cost parameters for a patch.
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("/remediation-cost-parameters/patch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPatchRuleCostParameters(@Context HttpServletRequest request) {
        return buildResponseForOperationalCostParameters(request, OperationalCostParameters.FILE_NAME_PATCH);
    }

    /**
     * OPTIONS necessary for operational cost parameters
     *
     * @param request the HTTP Request
     * @return the HTTP Response (empty OK)
     */
    @OPTIONS
    @Path("/remediation-cost-parameters/patch")
    public Response setPatchRuleCostParameters(@Context HttpServletRequest request) {
        return RestApplication.returnJsonObject(request, new JSONObject());
    }

    /**
     * Set the operational cost parameters for a patch.
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @POST
    @Path("/remediation-cost-parameters/patch")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setPatchRuleCostParameters(@Context HttpServletRequest request, String jsonString) {
        return saveAndBuildResponseForOperationalCostParameters(request, OperationalCostParameters.FILE_NAME_PATCH, jsonString);
    }

    /**
     * Generic function to build the HTTP Reponse for operational cost parameters (snort rule, firewall rule, patch...)
     *
     * @param request               the HTTP Request
     * @param costParameterFileName the filename of the file to get
     * @return the HTTP response
     */
    private Response buildResponseForOperationalCostParameters(HttpServletRequest request, String costParameterFileName) {
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
        OperationalCostParameters operationalCostParameters = new OperationalCostParameters();
        try {
            operationalCostParameters.loadFromXMLFile(costParametersFolderPath + "/" + costParameterFileName);
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "The operational cost parameters " +
                    "can not be load: " + e.getMessage());
        }

        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return RestApplication.returnJsonObject(request, XML.toJSONObject(output.outputString(operationalCostParameters.toDomElement())));
    }

    /**
     * Generic function to save the JSON string of cost paramaters
     * and build the HTTP Reponse for operational cost parameters (snort rule, firewall rule, patch...)
     *
     * @param request               the HTTP Request
     * @param costParameterFileName the filename of the file to get
     * @param jsonString            the JSON input string
     * @return the HTTP response
     */
    private Response saveAndBuildResponseForOperationalCostParameters(HttpServletRequest request, String costParameterFileName, String jsonString) {
        JSONObject json = new JSONObject(jsonString);
        String xmlString = XML.toString(json);
        SAXBuilder sxb = new SAXBuilder();
        Document document = null;
        try {
            document = sxb.build(new InputSource(new StringReader(xmlString)));
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "Can not load the JSON" +
                    " string: " + e.getMessage());
        }
        OperationalCostParameters operationalCostParameters = new OperationalCostParameters();
        operationalCostParameters.loadFromDomDocument(document);
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");

        try {
            operationalCostParameters.saveToXMLFile(costParametersFolderPath + "/" + costParameterFileName);
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "Can not save to XML file" +
                    " string: " + e.getMessage());
        }
        return RestApplication.returnJsonObject(request, new JSONObject());
    }
}
