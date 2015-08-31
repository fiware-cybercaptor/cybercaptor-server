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

import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraphVertex;

import java.io.Serializable;

/**
 * Class to store a serializable topological attack path vertex
 *
 * @author Francois -Xavier Aguessy
 */
public class SerializableVertex implements Serializable {

    /**
     * The related machine (if type of vertex is Machine)
     */
    private final String machine;

    /**
     * The related network (if type of vertex is Network)
     */
    private final String network;

    /**
     * The type of vertex
     */
    private final InformationSystemGraphVertex.TopologyVertexType type;

    /**
     * True if the machine/network is controlled by the attacker, else false
     */
    private final boolean machineOfAttacker;

    /**
     * True if the machine has been compromised
     */
    private final boolean compromised;

    /**
     * True if this vertex is the target of the attack path
     */
    private final boolean target;

    /**
     * Build a serializable vertex from a information system graph vertex.
     *
     * @param informationSystemGraphVertex the related information system graph vertex.
     */
    public SerializableVertex(InformationSystemGraphVertex informationSystemGraphVertex) {
        switch (informationSystemGraphVertex.getType()) {
            case Machine:
                this.machine = informationSystemGraphVertex.getMachine().getName();
                this.network = "";
                break;
            case Network:
                this.machine = "";
                this.network = informationSystemGraphVertex.getNetwork().getAddress() + "/" +
                        informationSystemGraphVertex.getNetwork().getMask();
                break;
            default:
                this.machine = "";
                this.network = "";
        }
        type = informationSystemGraphVertex.getType();
        machineOfAttacker = informationSystemGraphVertex.isMachineOfAttacker();
        compromised = informationSystemGraphVertex.isCompromised();
        target = informationSystemGraphVertex.isTarget();
    }

    /**
     * Gets machine.
     *
     * @return the machine
     */
    public String getMachine() {
        return machine;
    }

    /**
     * Gets network.
     *
     * @return the network
     */
    public String getNetwork() {
        return network;
    }

    /**
     * Gets type.
     *
     * @return the type
     */
    public InformationSystemGraphVertex.TopologyVertexType getType() {
        return type;
    }

    /**
     * Is machine of attacker.
     *
     * @return the boolean
     */
    public boolean isMachineOfAttacker() {
        return machineOfAttacker;
    }

    /**
     * Is compromised.
     *
     * @return the boolean
     */
    public boolean isCompromised() {
        return compromised;
    }

    /**
     * Is target.
     *
     * @return the boolean
     */
    public boolean isTarget() {
        return target;
    }

    /**
     * Test if equals to another serializable vertex
     * @param vertex the vertex to test
     * @return true if the vertices are equals
     */
    public boolean equals(SerializableVertex vertex) {
        boolean result = (this.isCompromised() == vertex.isCompromised());
        result &= (this.isTarget() == vertex.isTarget());
        result &= (this.isMachineOfAttacker() == vertex.isMachineOfAttacker());
        result &= (this.getType() == vertex.getType());
        result &= (this.getNetwork().equals(vertex.getNetwork()));
        result &= (this.getMachine().equals(vertex.getMachine()));
        return result;
    }
}
