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

import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Response;

/**
 * The Rest Application, the main entry point of jersey REST API
 *
 * @author Francois -Xavier Aguessy
 */
@ApplicationPath("/rest")
public class RestApplication extends ResourceConfig {
    /**
     * Register the package of the rest application
     */
    public RestApplication() {
        packages("org.fiware.cybercaptor.server.rest");
        packages("org.glassfish.jersey.examples.multipart");
        register(MultiPartFeature.class);
    }

    /**
     * Returns the {@link javax.ws.rs.core.Response} object from a {@link org.json.JSONObject}
     *
     * @param jsonObject the jsonObject to return
     * @return the relative {@link javax.ws.rs.core.Response} object
     */
    public static Response returnJsonObject(HttpServletRequest request, JSONObject jsonObject) {
        // client's origin
        String clientOrigin = request.getHeader("origin");

        return Response.ok(jsonObject.toString())
                .header("Access-Control-Allow-Origin", clientOrigin)
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
    public static Response returnErrorMessage(HttpServletRequest request, String errorMessage) {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("error", errorMessage);

        return returnJsonObject(request, jsonObject);
    }
}
