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
package org.fiware.cybercaptor.server.informationsystem.graph;

/**
 * Class to represent an arc of the {@link InformationSystemGraph InformationSystemGraph}
 *
 * @author Francois-Xavier Aguessy
 */
public class InformationSystemGraphArc {
    /**
     * The arc source
     */
    private InformationSystemGraphVertex source;

    /**
     * The arc destination
     */
    private InformationSystemGraphVertex destination;

    /**
     * Eventually, the vulnerability that is supported by this arc
     */
    private String relatedVulnerability = null;

    /**
     * @return the source of the arc
     */
    public InformationSystemGraphVertex getSource() {
        return source;
    }

    /**
     * Set a new source to the arc
     *
     * @param source the new source of the arc
     */
    public void setSource(InformationSystemGraphVertex source) {
        this.source = source;
    }

    /**
     * @return the destination of the arc
     */
    public InformationSystemGraphVertex getDestination() {
        return destination;
    }

    /**
     * Set a new destination to the arc
     *
     * @param destination the new destination of the arc
     */
    public void setDestination(InformationSystemGraphVertex destination) {
        this.destination = destination;
    }

    /**
     * @return the vulnerability of the arc (can be null if not applicable)
     */
    public String getRelatedVulnerability() {
        return relatedVulnerability;
    }

    /**
     * Assign a new vulnerability to the arc
     *
     * @param relatedVulnerability the vulnerability to add to the arc
     */
    public void setRelatedVulnerability(String relatedVulnerability) {
        this.relatedVulnerability = relatedVulnerability;
    }

    /**
     * Test if two arcs are equals
     *
     * @param arc the arc to test with current arc
     * @return true if the arcs are equals
     */
    public boolean equals(InformationSystemGraphArc arc) {
        return arc.getDestination().equals(this.getDestination()) && arc.getSource().equals(this.getSource());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof InformationSystemGraphArc)
            return this.equals((InformationSystemGraphArc) obj);
        return super.equals(obj);
    }
}
