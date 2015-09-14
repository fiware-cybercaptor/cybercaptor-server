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

import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;

/**
 * Class used to represent the information system graph (topological view of attack graph)
 *
 * @author Francois-Xavier Aguessy
 */
public class InformationSystemGraph {
    /**
     * The vertices of the information system graph
     */
    private ArrayList<InformationSystemGraphVertex> vertices = new ArrayList<InformationSystemGraphVertex>();

    /**
     * The arcs of the information system graph
     */
    private ArrayList<InformationSystemGraphArc> arcs = new ArrayList<InformationSystemGraphArc>();

    /**
     * Get the vertex of the information system graph, related to a machine of the information system
     *
     * @param machine a host
     * @return the related vertex in the information system graph
     */
    public InformationSystemGraphVertex getMachineVertex(InformationSystemHost machine) {
        for (InformationSystemGraphVertex vertex : getVertices()) {
            if (vertex.getType().equals(InformationSystemGraphVertex.TopologyVertexType.Machine) && vertex.getMachine().equals(machine))
                return vertex;
        }

        InformationSystemGraphVertex newVertex = new InformationSystemGraphVertex();
        newVertex.setType(InformationSystemGraphVertex.TopologyVertexType.Machine);
        newVertex.setMachine(machine);
        this.getVertices().add(newVertex);
        return newVertex;
    }

    /**
     * @return the vertices of the information system graph
     */
    public ArrayList<InformationSystemGraphVertex> getVertices() {
        return vertices;
    }

    /**
     * @return the arcs of the information system graph
     */
    public ArrayList<InformationSystemGraphArc> getArcs() {
        return arcs;
    }

    /**
     * Transform this graph to a json object (vertices arcs)
     *
     * @return the JSON object related to this graph
     */
    public JSONObject toJsonObject() {
        //Build the json list of hosts
        JSONObject json = new JSONObject();
        JSONObject arcs_object = new JSONObject();
        JSONArray arcs_array = new JSONArray();
        ArrayList<InformationSystemGraphVertex> vertices = this.getVertices();

        // Arcs
        for (InformationSystemGraphArc topologicalGraphArc : this.getArcs()) {
            JSONObject arc_object = new JSONObject();
            int id_destination = vertices.indexOf(topologicalGraphArc.getDestination());
            int id_source = vertices.indexOf(topologicalGraphArc.getSource());
            arc_object.put("dst", id_destination);
            arc_object.put("src", id_source);
            arc_object.put("label", topologicalGraphArc.getRelatedVulnerability());
            arcs_array.put(arc_object);
        }
        arcs_object.put("arc", arcs_array);
        json.put("arcs", arcs_object);

        JSONObject vertices_object = new JSONObject();
        JSONArray vertices_array = new JSONArray();
        // Vertices
        for (InformationSystemGraphVertex topologicalVertex : vertices) {
            JSONObject vertex_object = new JSONObject();
            int id = vertices.indexOf(topologicalVertex);
            vertex_object.put("id", id);
            vertex_object.put("type", topologicalVertex.getType().toString().toUpperCase());
            if (topologicalVertex.getType().equals(InformationSystemGraphVertex.TopologyVertexType.Machine)) {
                vertex_object.put("name", topologicalVertex.getMachine().getName());
                JSONArray ipAddresses = new JSONArray();
                for (Interface networkInterface : topologicalVertex.getMachine().getInterfaces().values()) {
                    ipAddresses.put(networkInterface.getAddress());
                }
                vertex_object.put("ip_addresses", ipAddresses);
            } else if (topologicalVertex.getType().equals(InformationSystemGraphVertex.TopologyVertexType.Network)) {
                vertex_object.put("name", topologicalVertex.getNetwork().getName());
                vertex_object.put("ip_address", topologicalVertex.getNetwork().getAddress() + "/" + topologicalVertex.getNetwork().getMask());
            }
            vertex_object.put("compromised", topologicalVertex.isCompromised());
            vertex_object.put("source_of_attack", topologicalVertex.isMachineOfAttacker());
            vertex_object.put("target", topologicalVertex.isTarget());

            vertices_array.put(vertex_object);
        }
        vertices_object.put("vertex", vertices_array);
        json.put("vertices", vertices_object);

        return json;
    }

    /**
     * Set a node of the information system graph as a target
     *
     * @param target the host that is a target
     */
    public void addTarget(InformationSystemHost target) {
        for (InformationSystemGraphVertex vertex : this.getVertices()) {
            if (vertex.getType().equals(InformationSystemGraphVertex.TopologyVertexType.Machine)) {
                if (vertex.getMachine().equals(target)) {
                    vertex.setTarget(true);
                }
            }
        }
    }
}
