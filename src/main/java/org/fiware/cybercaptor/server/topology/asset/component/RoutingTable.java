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
import org.jdom2.Element;

import java.util.ArrayList;
import java.util.List;

/**
 * Class that represents the routing table on a host
 *
 * @author Francois-Xavier Aguessy
 */
public class RoutingTable implements Cloneable {

    /**
     * The host related to this routing table;
     */
    private Host relatedHost;

    /**
     * The route list
     */
    private ArrayList<Route> routeList = new ArrayList<Route>();

    public RoutingTable(Host host) {
        this.relatedHost = host;
    }

    /**
     * @return the routeList
     */
    public ArrayList<Route> getRouteList() {
        return routeList;
    }

    /**
     * @param routeList the routeList to set
     */
    public void setRouteList(ArrayList<Route> routeList) {
        this.routeList = routeList;
    }

    /**
     * Add a new route in the routing table
     *
     * @param destination the destination IP Address
     * @param mask        the destination mask
     * @param gateway     the gateway
     * @param intface     the output interface
     * @return the added route
     */
    public Route addRoute(IPAddress destination, IPAddress mask, IPAddress gateway, Interface intface) {
        Route route = new Route(destination, gateway, mask, intface);
        if (destination.getAddress().equals("0.0.0.0") && gateway.getAddress().equals("0.0.0.0")) { //Default route
            if (hasDefaultRoute()) {
                this.getRouteList().remove(this.getRouteList().size() - 1);
                this.getRouteList().add(route);
            } else {
                this.getRouteList().add(route);
            }
        } else {
            if (hasDefaultRoute()) {
                this.getRouteList().add(this.getRouteList().size() - 1, route);
            } else {
                this.getRouteList().add(route);
            }
        }
        return route;
    }

    /**
     * @return true if this routing table has a default route, else false
     */
    public boolean hasDefaultRoute() {
        return this.getRouteList().size() > 0 && this.getRouteList().get(this.getRouteList().size() - 1).getDestination().getAddress().equals("0.0.0.0") && this.getRouteList().get(this.getRouteList().size() - 1).getMask().getAddress().equals("0.0.0.0");
    }

    /**
     * Add a default rule to the routing table (route at the end that match all ip addresses)
     *
     * @param gateway the gateway of this default rule
     * @param intface the interface of the default rule
     * @return the added rule
     * @throws Exception
     */
    public Route addDefaultGateway(IPAddress gateway, Interface intface) throws Exception {
        if (!this.relatedHost.getInterfaces().containsValue(intface)) {
            throw new Exception("this interface does not belongs to this host");
        }
        return addRoute(new IPAddress("0.0.0.0"), new IPAddress("0.0.0.0"), gateway, intface);
    }

    /**
     * @param ip the destination ip address
     * @return the next ip address according to the destination ip address and the routing table
     * @throws Exception
     */
    public IPAddress getNextHop(IPAddress ip) throws Exception {
        int int_ip = ip.toInt();
        for (int i = 0; i < getRouteList().size(); i++) {
            Route route = getRouteList().get(i);
            int int_destination = route.getDestination().toInt();
            int int_mask = route.getMask().toInt();
            if ((int_ip & int_mask) == (int_destination & int_mask)) {
                return route.getGateway();
            }
        }
        throw new Exception("Missing default gateway for host " + relatedHost.getName());
    }

    /**
     * Load the routing table from a DOM element extracted from an XML file
     *
     * @param domElement the routing table DOM root
     * @throws Exception
     */
    public void loadFromDomElement(Element domElement, Host host) throws Exception {
        List<Element> routesElements = domElement.getChildren("route");
        for (Element routeElement : routesElements) {
            Element destinationElement = routeElement.getChild("destination");
            Element maskElement = routeElement.getChild("mask");
            Element gatewayElement = routeElement.getChild("gateway");
            Element interfaceElement = routeElement.getChild("interface");

            if (destinationElement != null && maskElement != null && gatewayElement != null && interfaceElement != null) {
                Route route = new Route(new IPAddress(destinationElement.getText()), new IPAddress(gatewayElement.getText()), new IPAddress(maskElement.getText()), host.getInterfaces().get(interfaceElement.getText()));
                this.getRouteList().add(route);
            }
        }
    }

    @Override
    public RoutingTable clone() throws CloneNotSupportedException {
        RoutingTable copie = (RoutingTable) super.clone();

        copie.setRouteList(new ArrayList<Route>(this.getRouteList()));
        for (int i = 0; i < copie.getRouteList().size(); i++) {
            copie.getRouteList().set(i, copie.getRouteList().get(i).clone());
        }

        return copie;
    }

    @Override
    public String toString() {
        String result = "Routing table :\n";
        for (int i = 0; i < getRouteList().size(); i++) {
            result += "\t -" + getRouteList().get(i);
        }
        return result;
    }

}
