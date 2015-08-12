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

package org.fiware.cybercaptor.server.topology.asset.component;

import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.Network;
import org.fiware.cybercaptor.server.topology.asset.VLAN;
import org.jdom2.Element;

import java.util.ArrayList;
import java.util.List;

/**
 * Class that represents an interface on a host
 *
 * @author Francois-Xavier Aguessy
 */
public class Interface implements Cloneable {
    /**
     * The name of the interface
     */
    private String name = "";

    /**
     * The IPAddress of the interface
     */
    private IPAddress address = new IPAddress("0.0.0.0");

    /**
     * The VLAN in which is the interface
     */
    private VLAN vlan = new VLAN();

    /**
     * The network in which is the interface
     */
    private Network network = null;

    /**
     * The host in which is the interface
     */
    private Host host = null;

    /**
     * True if the host is directly connected to the internet
     */
    private boolean connectedToTheInternet = false;

    /**
     * Create an interface from its name and ip address
     *
     * @param name    the interface name
     * @param address its IP address
     * @param host    the host which has this interface
     * @throws Exception
     */
    public Interface(String name, String address, Host host) throws Exception {
        this.setHost(host);
        this.setName(name);
        this.setAddress(new IPAddress(address));
        this.setVlan(this.vlan);
    }

    /**
     * Create an interface from its name and ip address
     *
     * @param name    the interface name
     * @param address its IP address
     * @param host    the host which has this interface
     * @param vlan    the vlan of the interface
     * @throws Exception
     */
    public Interface(String name, String address, Host host, VLAN vlan) throws Exception {
        this.setHost(host);
        this.setName(name);
        this.setAddress(new IPAddress(address));
        this.setVlan(vlan);
    }

    /**
     * Merge two interfaces related to the same IP address
     *
     * @param i1 first interface
     * @param i2 second interface
     * @return the created interface
     * @throws Exception
     */
    public static Interface mergeTwoInterfaces(Interface i1, Interface i2) throws Exception {
        if (!i2.getAddress().equals(i1.getAddress()))
            return null;
        else {
            String name = ""; //First, we compute the name of the interface
            if (!i1.getName().isEmpty() && !i1.getName().startsWith("int")) //Not empty and not a default name
                name = i1.getName();
            if (!i2.getName().isEmpty() && !i2.getName().startsWith("int"))
                name = i2.getName();
            if (name.isEmpty() && !i2.getName().isEmpty())
                name = i2.getName();
            if (name.isEmpty() && !i1.getName().isEmpty())
                name = i1.getName();
            Interface newInterface = new Interface(name, i1.getAddress().getAddress(), i1.getHost());

            if (i1.getHost() != null)
                newInterface.setHost(i1.getHost());
            if (i2.getHost() != null)
                newInterface.setHost(i2.getHost());

            if (i1.getNetwork() != null)
                newInterface.setNetwork(i1.getNetwork());
            if (i2.getNetwork() != null)
                newInterface.setNetwork(i2.getNetwork());

            if (i1.getNetwork() != null && i1.getNetwork().getName() != null && !i1.getNetwork().getName().equals(""))
                newInterface.setVlan(i1.getVlan());
            else
                newInterface.setVlan(i2.getVlan());
            return newInterface;
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
     * @return the address
     */
    public IPAddress getAddress() {
        return address;
    }

    /**
     * @param address the address to set
     */
    public void setAddress(IPAddress address) {
        this.address = address;
    }

    /**
     * @return the vlan
     */
    public VLAN getVlan() {
        return vlan;
    }

    /**
     * @param vlan the vlan to set
     */
    public void setVlan(VLAN vlan) {
        this.vlan = vlan;
        vlan.addInterface(this);
        vlan.addHost(this.host);
    }

    /**
     * @return the network
     */
    public Network getNetwork() {
        return network;
    }

    /**
     * @param network the network to set
     */
    public void setNetwork(Network network) {
        this.network = network;
    }

    /**
     * @return the host
     */
    public Host getHost() {
        return host;
    }

    /**
     * @param host the host to set
     */
    public void setHost(Host host) {
        this.host = host;
    }

    /**
     * @return the directlyAccessibleInterface
     */
    public List<Interface> getDirectlyAccessibleInterface() {
        List<Interface> result = new ArrayList<Interface>();
        for (int i = 0; i < this.vlan.getInterfaces().size(); i++) {
            Interface intface = this.vlan.getInterfaces().get(i);
            if (!intface.equals(this)) {
                result.add(intface);
            }
        }
        return result;
    }

    /**
     * @return the connectedToTheInternet
     */
    public boolean isConnectedToTheInternet() {
        return connectedToTheInternet;
    }

    /**
     * @param connectedToTheInternet the connectedToTheInternet to set
     */
    public void setConnectedToTheInternet(boolean connectedToTheInternet) {
        this.connectedToTheInternet = connectedToTheInternet;
    }

    /**
     * @return the dom element corresponding to this interface in XML
     */
    public Element toDomElement() {
        Element root = new Element("interface");

        Element intfaceNameElement = new Element("name");
        intfaceNameElement.setText(this.getName());
        root.addContent(intfaceNameElement);

        root.addContent(this.vlan.toDOMElement());

        Element intfaceIpaddressElement = new Element("ipaddress");
        intfaceIpaddressElement.setText(this.getAddress().getAddress());
        root.addContent(intfaceIpaddressElement);

        if (getNetwork() != null) {
            Element networkIpaddressElement = new Element("network");
            networkIpaddressElement.setText(getNetwork().getAddress().getAddress());
            root.addContent(networkIpaddressElement);

            Element maskElement = new Element("mask");
            maskElement.setText(getNetwork().getMask().getAddress());
            root.addContent(maskElement);
        }

        Element intfaceDirectlyConnectedElement = new Element("directly-connected");
        root.addContent(intfaceDirectlyConnectedElement);
        for (int i = 0; i < this.getDirectlyAccessibleInterface().size(); i++) {
            Element ipAddressElement = new Element("ipaddress");
            ipAddressElement.setText(this.getDirectlyAccessibleInterface().get(i).getAddress().getAddress());
            intfaceDirectlyConnectedElement.addContent(ipAddressElement);
        }

        if (this.isConnectedToTheInternet()) {
            Element internetElement = new Element("internet");
            intfaceDirectlyConnectedElement.addContent(internetElement);
        }
        return root;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getAddress() == null) ? 0 : getAddress().hashCode());
        result = prime * result + ((getName() == null) ? 0 : getName().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Interface other = (Interface) obj;
        if (getAddress() == null) {
            if (other.getAddress() != null)
                return false;
        } else if (!getAddress().equals(other.getAddress()))
            return false;
        if (getName() == null) {
            if (other.getName() != null)
                return false;
        } else if (!getName().equals(other.getName()))
            return false;
        return true;
    }

    @Override
    public Interface clone() throws CloneNotSupportedException {
        Interface copie = (Interface) super.clone();
        copie.setAddress(this.getAddress().clone());
        copie.setVlan(this.vlan.clone());
        return copie;
    }

    @Override
    public String toString() {
        return "Interface [address=" + getAddress() + ", name=" + getName() + "]";
    }
}
