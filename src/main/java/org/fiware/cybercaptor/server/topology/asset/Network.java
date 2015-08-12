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
package org.fiware.cybercaptor.server.topology.asset;

import org.fiware.cybercaptor.server.topology.Topology;

/**
 * Class to represent a network
 *
 * @author Francois -Xavier Aguessy
 */
public class Network implements Cloneable {
    /**
     * The name of the network
     */
    private String name = "";

    /**
     * The ip address of the network
     */
    private IPAddress address = null;

    /**
     * The mask of the network
     */
    private IPAddress mask = IPAddress.getIPv4NetMask(32);

    /**
     * Create a network with an address and a mask
     *
     * @param address the ip address
     * @param mask    the mask
     */
    public Network(IPAddress address, IPAddress mask) {
        this.address = address;
        this.mask = mask;
    }

    /**
     * Instantiates a new Network.
     *
     * @param address the address
     */
    public Network(IPAddress address) {
        this.address = address;
        this.mask = IPAddress.getIPv4NetMask(32);
    }


    /**
     * Create a network with a string
     *
     * @param networkString network string with the CIDR format : A.B.C.D/X
     * @throws Exception the exception
     */
    public Network(String networkString) throws Exception {
        if (!networkString.contains("/"))
            throw new Exception("Wrong network format");
        String address = networkString.split("/")[0];
        String mask = networkString.split("/")[1];
        this.address = new IPAddress(address);
        this.mask = IPAddress.getIPv4NetMask(Integer.parseInt(mask));
    }

    /**
     * Gets name.
     *
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets name.
     *
     * @param name the name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets address.
     *
     * @return the address
     */
    public IPAddress getAddress() {
        return address;
    }

    /**
     * Gets mask.
     *
     * @return the mask
     */
    public IPAddress getMask() {
        return mask;
    }

    /**
     * Contains network.
     *
     * @param network an other network
     * @return true if this network contains the other network
     */
    public boolean containsNetwork(Network network) {
        return IPAddress.networkInOtherNetwork(network.getAddress(), network.getMask(), this.getAddress(), this.getMask());
    }

    /**
     * Is included in.
     *
     * @param network an other network
     * @return true if this network is included in the other network
     */
    public boolean isIncludedIn(Network network) {
        return IPAddress.networkInOtherNetwork(this.getAddress(), this.getMask(), network.getAddress(), network.getMask());
    }

    /**
     * Is internet.
     *
     * @return true if this network represents Internet. (any ip address)
     */
    public boolean isInternet() {
        return this.getAddress().equals(IPAddress.getIPv4NetMask(0)) && this.getMask().equals(IPAddress.getIPv4NetMask(0));
    }

    /**
     * Is in topology.
     *
     * @param topology the topology
     * @return true if the network contains no host of the topology
     */
    public boolean isInTopology(Topology topology) {
        return topology.getHostsInNetwork(this).size() > 0;
    }

    @Override
    public Network clone() throws CloneNotSupportedException {
        Network copie = (Network) super.clone();
        copie.address = this.getAddress().clone();
        copie.mask = this.getMask().clone();

        return copie;
    }

    @Override
    public String toString() {
        return getName() + " : " + getAddress().getAddress() + "/" + getMask().getMaskFromIPv4Address();
    }
}
