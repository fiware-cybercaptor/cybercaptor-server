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
import org.fiware.cybercaptor.server.topology.asset.Network;

/**
 * Class used to represent a vertex of the {@link InformationSystemGraph InformationSystemGraph}
 *
 * @author Francois -Xavier Aguessy
 */
public class InformationSystemGraphVertex {

    /**
     * The related machine (if type of vertex is Machine)
     */
    private InformationSystemHost machine;

    /**
     * The related network (if type of vertex is Network)
     */
    private Network network;

    /**
     * The type of vertex
     */
    private TopologyVertexType type;

    /**
     * True if the machine/network is controlled by the attacker, else false
     */
    private boolean machineOfAttacker = false;

    /**
     * True if the machine has been compromised
     */
    private boolean compromised = false;

    /**
     * True if this vertex is the target of the attack path
     */
    private boolean target = false;

    /**
     * Get the related machine (if type of vertex is Machine)
     * @return the machine
     */
    public InformationSystemHost getMachine() {
        return machine;
    }

    /**
     * Sets machine.
     *
     * @param machine the machine to set to this vertex
     */
    public void setMachine(InformationSystemHost machine) {
        this.machine = machine;
    }

    /**
     * Get the related network (if type of vertex is Network)
     * @return the network
     */
    public Network getNetwork() {
        return network;
    }

    /**
     * Sets network.
     *
     * @param network the network to set to this vertex
     */
    public void setNetwork(Network network) {
        this.network = network;
    }

    /**
     * The type of vertex
     * @return the type
     */
    public TopologyVertexType getType() {
        return type;
    }

    /**
     * Set the type of this vertex
     *
     * @param type the type of vertex
     */
    public void setType(TopologyVertexType type) {
        this.type = type;
    }

    /**
     * True if the machine/network is controlled by the attacker, else false
     * @return the boolean
     */
    public boolean isMachineOfAttacker() {
        return machineOfAttacker;
    }

    /**
     * Set if this vertex represent a potential machine of the attacker
     *
     * @param machineOfAttacker true if this vertex is a machine of attacker
     */
    public void setMachineOfAttacker(boolean machineOfAttacker) {
        this.machineOfAttacker = machineOfAttacker;
    }

    /**
     * True if the machine has been compromised
     * @return the boolean
     */
    public boolean isCompromised() {
        return compromised;
    }

    /**
     * Set if the current vertex is a compromised machine or network
     *
     * @param compromised the new compromised value
     */
    public void setCompromised(boolean compromised) {
        this.compromised = compromised;
    }

    @Override
    public String toString() {
        switch (getType()) {
            case Machine:
                return this.getMachine().getName();
            case Network:
                return this.getNetwork().getAddress().getAddress();
        }
        return "";
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
     * Sets target.
     *
     * @param target the target
     */
    public void setTarget(boolean target) {
        this.target = target;
    }

    /**
     * The type of vertex of a topology vertex
     */
    public static enum TopologyVertexType {
        /**
         * A Machine.
         */
        Machine, /**
         * A Network.
         */
        Network
    }


}
