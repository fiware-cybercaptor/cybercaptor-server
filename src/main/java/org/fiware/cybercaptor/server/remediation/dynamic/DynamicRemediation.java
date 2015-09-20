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

package org.fiware.cybercaptor.server.remediation.dynamic;

import org.fiware.cybercaptor.server.dra.Alert;
import org.json.JSONObject;

/**
 * Abstract class that represents dynamic remediations = remediations that apply to a currently detected attack
 *
 * @author Francois -Xavier Aguessy
 */
public abstract class DynamicRemediation {
    /**
     * The alert related to this remediation.
     */
    private final Alert alert;

    /**
     * Instantiates a new Dynamic remediation.
     *
     * @param alert the alert
     */
    public DynamicRemediation(Alert alert) {
        this.alert = alert;
    }

    /**
     * To json object.
     *
     * @return the jSON object
     */
    public abstract JSONObject toJsonObject();

    /**
     * Gets alert.
     *
     * @return the alert
     */
    public Alert getAlert() {
        return alert;
    }
}
