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

package org.fiware.cybercaptor.server.attackgraph.serializable;

import java.io.Serializable;

/**
 * Class to store a serializable topological attack path arc
 *
 * @author Francois-Xavier Aguessy
 */
public class SerializableArc implements Serializable {
    /**
     * The source id of the arc
     */
    private final int source;

    /**
     * The destination id of the arc
     */
    private final int destination;

    /**
     * the label of the arc
     */
    private final String label;

    /**
     * @param source      the source id of the arc
     * @param destination the destination id of the arc
     * @param label       the label of the arc
     */

    public SerializableArc(int source, int destination, String label) {
        this.source = source;
        this.destination = destination;
        this.label = label;
    }

    /**
     * Get the source of the arc
     *
     * @return the arc source
     */
    public int getSource() {
        return source;
    }

    /**
     * Get the destination of the arc
     *
     * @return the arc destination
     */
    public int getDestination() {
        return destination;
    }

    /**
     * Get the label of the arc
     *
     * @return the arc label
     */
    public String getLabel() {
        return label;
    }
}
