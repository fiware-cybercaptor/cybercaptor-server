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

import org.fiware.cybercaptor.server.attackgraph.AttackPath;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraph;
import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraphArc;
import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraphVertex;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Class to store a serializable attack path that is used for remediation automation
 * Used to memorize remediations that have been applied by operators.
 * This allows to serialize the attack path, to store it, and to test if an other attack path
 * is similar to this one.
 *
 * @author Francois-Xavier Aguessy
 */
public class SerializableAttackPath implements Serializable {

    /**
     * A list of vertices
     */
    public Map<Integer, SerializableVertex> vertices = new HashMap<Integer, SerializableVertex>();

    /**
     * A list of arcs between the vertices
     */
    public ArrayList<SerializableArc> arcs = new ArrayList<SerializableArc>();

    /**
     * Create a serializable attack path from an attack path
     *
     * @param attackPath        the attack path to serialize
     * @param informationSystem the information system
     * @throws Exception
     */
    public SerializableAttackPath(AttackPath attackPath, InformationSystem informationSystem) throws Exception {
        InformationSystemGraph informationSystemGraph = attackPath.getRelatedTopologyGraph(informationSystem);

        Map<InformationSystemGraphVertex, Integer> vertexToNumber = new HashMap<InformationSystemGraphVertex, Integer>();
        int id = 0;
        for (InformationSystemGraphVertex vertex : informationSystemGraph.getVertices()) {
            SerializableVertex serializableVertex = new SerializableVertex(vertex);
            vertices.put(id, serializableVertex);
            vertexToNumber.put(vertex, id);
            id++;
        }

        for (InformationSystemGraphArc arc : informationSystemGraph.getArcs()) {
            int sourceID = vertexToNumber.get(arc.getSource());
            int destination = vertexToNumber.get(arc.getDestination());
            arcs.add(new SerializableArc(sourceID, destination, "vulnerability:" + arc.getRelatedVulnerability()));
        }

    }

    /**
     * Test if an attack path is similar to another attack path
     *
     * @param attackPath the attack path to test
     * @return true if the attack paths are similar.
     */
    public boolean isSimilarTo(SerializableAttackPath attackPath) {
        boolean result = true;
        for (SerializableVertex serializableVertex : attackPath.vertices.values()) {
            boolean resultVertex = false;
            for (SerializableVertex vertexToTest : this.vertices.values()) {
                resultVertex |= vertexToTest.equals(serializableVertex);
            }
            result &= resultVertex;
        }
        return result;
    }
}
