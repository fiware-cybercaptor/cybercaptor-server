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

package org.fiware.cybercaptor.server.flowmatrix;

import org.fiware.cybercaptor.server.topology.Topology;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.VLAN;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.jdom2.Element;

/**
 * Class to represent an element of a flow matrix line (IP, VLAN or Internet)
 *
 * @author Francois-Xavier Aguessy
 */
public class FlowMatrixElement {

    /**
     * The type of current flow matrix element
     */
    private final FlowMatrixElementType type;
    /**
     * The resource stored in the element: can be a VLAN object (for VLAN type),
     * a network interface (for IP type), or null, (for INTERNET type)
     */
    private final Object resource;

    /**
     * Create a flow matrix element from XML DOM element
     *
     * @param element  the XML DOM element
     * @param topology the network topology
     */
    public FlowMatrixElement(Element element, Topology topology) {
        if (element == null)
            throw new IllegalArgumentException("The flow matrix line element DOM element is null");
        String type = element.getAttributeValue("type");
        switch (type) {
            case "VLAN":
                String vlanName = element.getAttributeValue("resource");
                VLAN vlan = topology.getVlan(vlanName);
                this.type = FlowMatrixElementType.VLAN;
                this.resource = vlan;
                break;
            case "IP":
                String ipAddress = element.getAttributeValue("resource");
                this.type = FlowMatrixElementType.IP;
                try {
                    this.resource = topology.getInterfaceByIpAddress(new IPAddress(ipAddress));
                } catch (Exception e) {
                    throw new IllegalStateException("The resource is not an IP adress.");
                }
                break;
            case "INTERNET":
                this.type = FlowMatrixElementType.INTERNET;
                this.resource = null;
                break;
            default:
                this.type = null;
                this.resource = null;
                throw new IllegalArgumentException("The flow matrix line element type is not VLAN, IP or INTERNET : it is " + type);
        }
    }

    /**
     * Test if this flow matrix element (either Internet, IP or VLAN) contains a network interface
     *
     * @param ni the network interface to test
     * @return true if ni is contained in the current flow matrix element
     */
    public boolean contains(Interface ni) {
        switch (this.getType()) {
            case INTERNET:
                return false;
            case IP:
                return ni.getAddress().equals(this.getResource());
            case VLAN:
                try {
                    VLAN vlan = (VLAN) this.getResource();
                    return IPAddress.networkInOtherNetwork(new IPAddress(ni.getAddress().getAddress()), IPAddress.getIPv4NetMask(32), new IPAddress(
                            vlan.getNetworkAddress().getAddress()), IPAddress.getIPv4NetMask(vlan.getNetworkMask()));
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            default:
                return false;
        }
    }

    /**
     * @return true if this flow matrix element represents Internet
     */
    public boolean isInternet() {
        switch (this.getType()) {
            case INTERNET:
                return true;
            default:
                return false;
        }
    }

    /**
     * @return the type of the flow matrix element
     */
    public FlowMatrixElementType getType() {
        return type;
    }

    /**
     * @return the resource of the flow matrix element
     */
    public Object getResource() {
        return resource;
    }

    /**
     * Possible types of flow matrix element
     */
    public static enum FlowMatrixElementType {
        IP, VLAN, INTERNET
    }
}
