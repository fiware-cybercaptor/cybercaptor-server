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
package org.fiware.cybercaptor.server.attackgraph;

/**
 * Represent a security requirement associated to a machine
 *
 * @author Francois-Xavier Aguessy
 */
public class SecurityRequirement {
    /**
     * The name of the security requirement
     */
    private String name;

    /**
     * The metric of the security requirement
     */
    private double metric = 0.;

    /**
     * Create a security requirement from name and metric
     *
     * @param name   the name of security requirement
     * @param metric the metric associated
     */
    public SecurityRequirement(String name, double metric) {
        this.name = name;
        this.metric = metric;
    }

    /**
     * Transform the plain text metric to a double value (used for calculation)
     *
     * @param plainText the textual metric
     * @return a double value corresponding to this metric
     */
    public static double getMetricValueFromPlainText(String plainText) {
        switch (plainText.toLowerCase()) {
            case "none":
                return 0.;
            case "negligeable":
                return 10.;
            case "minor":
                return 30.;
            case "medium":
                return 50.;
            case "severe":
                return 70.;
            case "catastrophic":
                return 90.;
            default:
                return 0;
        }
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the metric
     */
    public double getMetric() {
        return metric;
    }

    /**
     * @param metric the metric to set
     */
    public void setMetric(double metric) {
        this.metric = metric;
    }

    /**
     * Returns the metric has a plain texte string (generally for display)
     *
     * @return the name associated to the metric value
     */
    public String getMetricPlainText() {
        if (metric < 0)
            return "None";
        else if (metric < 20)
            return "Negligeable";
        else if (metric < 40)
            return "Minor";
        else if (metric < 60)
            return "Medium";
        else if (metric < 80)
            return "Severe";
        else
            return "Catastrophic";
    }
}
