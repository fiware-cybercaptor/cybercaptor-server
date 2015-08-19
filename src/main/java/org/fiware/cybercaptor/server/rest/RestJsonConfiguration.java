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
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.json.XML;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

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
}
