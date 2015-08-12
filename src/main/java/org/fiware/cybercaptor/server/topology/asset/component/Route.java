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

import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.jdom2.Element;

/**
 * Class that represents a route on a equipment
 *
 * @author Francois -Xavier Aguessy
 */
public class Route implements Cloneable {
    /**
     * The destination
     */
    private IPAddress destination;

    /**
     * The gateway
     */
    private IPAddress gateway;

    /**
     * The network mask
     */
    private IPAddress mask;

    /**
     * The interface
     */
    private Interface intface;


    /**
     * Create a route
     *
     * @param destination destination ip address
     * @param gateway     gateway ip address
     * @param mask        the destination mask
     * @param intface     the interface
     */
    public Route(IPAddress destination, IPAddress gateway, IPAddress mask, Interface intface) {
        super();
        this.setDestination(destination);
        this.setGateway(gateway);
        this.setMask(mask);
        this.setIntface(intface);
    }

    /**
     * Gets destination.
     *
     * @return the destination
     */
    public IPAddress getDestination() {
        return destination;
    }

    /**
     * Sets destination.
     *
     * @param destination the destination to set
     */
    public void setDestination(IPAddress destination) {
        this.destination = destination;
    }

    /**
     * Gets gateway.
     *
     * @return the gateway
     */
    public IPAddress getGateway() {
        return gateway;
    }

    /**
     * Sets gateway.
     *
     * @param gateway the gateway to set
     */
    public void setGateway(IPAddress gateway) {
        this.gateway = gateway;
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
     * Sets mask.
     *
     * @param mask the mask to set
     */
    public void setMask(IPAddress mask) {
        this.mask = mask;
    }

    /**
     * Gets intface.
     *
     * @return the intface
     */
    public Interface getIntface() {
        return intface;
    }

    /**
     * Sets intface.
     *
     * @param intface the intface to set
     */
    public void setIntface(Interface intface) {
        this.intface = intface;
    }

    /**
     * To dom xML element.
     *
     * @return the dom element corresponding to this route
     */
    public Element toDomXMLElement() {
        Element root = new Element("route");

        Element destinationElement = new Element("destination");
        destinationElement.setText(this.getDestination().getAddress());
        root.addContent(destinationElement);

        Element maskElement = new Element("mask");
        maskElement.setText(this.getMask().getAddress());
        root.addContent(maskElement);

        Element gatewayElement = new Element("gateway");
        gatewayElement.setText(this.getGateway().getAddress());
        root.addContent(gatewayElement);

        Element interfaceElement = new Element("interface");
        interfaceElement.setText(this.getIntface().getName());
        root.addContent(interfaceElement);

        return root;
    }

    @Override
    public Route clone() throws CloneNotSupportedException {
        Route copie = (Route) super.clone();
        copie.setDestination(this.getDestination().clone());
        copie.setGateway(this.getGateway().clone());
        copie.setMask(this.getMask().clone());

        return copie;
    }

    @Override
    public String toString() {
        String result = "";
        result += "destination : " + getDestination().getAddress() + "/" + getMask().getMaskFromIPv4Address() + " -> gateway : " + getGateway().getAddress() + " on interface " + getIntface().getName();
        return result;
    }

}
