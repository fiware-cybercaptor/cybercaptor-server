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
 * Class to manage the arcs of an attack graph
 *
 * @author Francois-Xavier Aguessy
 */
public class Arc implements Cloneable {
    /**
     * The source vertex of the arc
     */
    public Vertex source;

    /**
     * The destination vertex of the arc
     */
    public Vertex destination;

    /**
     * Create an arc from source to destination
     *
     * @param source      The source vertex
     * @param destination The destinatino vertex
     */
    public Arc(Vertex source, Vertex destination) {
        this.source = source;
        this.destination = destination;
    }

    @Override
    public Arc clone() throws CloneNotSupportedException {
        return (Arc) super.clone();
    }

    @Override
    public String toString() {
        return "Arc [destination=" + destination + ", source=" + source + "]";
    }

}
