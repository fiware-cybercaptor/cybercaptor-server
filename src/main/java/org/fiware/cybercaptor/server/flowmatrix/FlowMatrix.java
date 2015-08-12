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
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.jdom2.Element;

import java.util.ArrayList;
import java.util.List;

/**
 * Class used to represent the flow matrix. A flow matrix is a set of flow matrix lines.
 *
 * @author Francois-Xavier Aguessy
 */
public class FlowMatrix {
    /**
     * The flow matrix lines
     */
    private List<FlowMatrixLine> flowMatrixLines = new ArrayList<>();

    /**
     * Create an empty flow matrix
     */
    public FlowMatrix() {

    }

    /**
     * Create a flow matrix from a XML DOM element
     *
     * @param element  the XML DOM element
     * @param topology the network topology
     */
    public FlowMatrix(Element element, Topology topology) {
        if (element != null) {
            for (Element flowMatrixLinesElement : element.getChildren("flow-matrix-line")) {
                getFlowMatrixLines().add(new FlowMatrixLine(flowMatrixLinesElement, topology));
            }
        }
    }

    /**
     * Test if the access is authorized in this flow matrix from the IP of ni1 to the IP of ni2 (using destinationPort and protocol)
     * If the flow matrix is empty (no lines), return always true
     *
     * @param ni1             the source network interface (IP)
     * @param ni2             the destination network interface (IP)
     * @param destinationPort the destination port
     * @param protocol        the protocol
     * @return true if the access is authorized, else false.
     */
    public boolean accessAuthorized(Interface ni1, Interface ni2, int destinationPort, FirewallRule.Protocol protocol) {
        if (this.getFlowMatrixLines().size() == 0)
            return true; //If there is no flow matrix loaded, return always true...

        //Accesses inside a VLAN are always enabled
        //TODO : note that this is false if local filtering is enabled...
        if (ni1.getVlan().equals(ni2.getVlan()))
            return true;
        for (FlowMatrixLine flowMatrixLine : this.getFlowMatrixLines()) {
            if (flowMatrixLine.getSource().contains(ni1) && flowMatrixLine.getDestination().contains(ni2)
                    && flowMatrixLine.getDestination_port().inRange(destinationPort)
                    && (flowMatrixLine.getProtocol() == FirewallRule.Protocol.ANY || protocol.equals(flowMatrixLine.getProtocol()) || protocol == FirewallRule.Protocol.ANY)) {
                return true;
            }

        }
        return false;
    }

    /**
     * Test if the access is authorized in this flow matrix from Internet to the IP of ni (using destinationPort and protocol)
     * If the flow matrix is empty (no lines), return always true
     *
     * @param ni              the destination network interface (IP)
     * @param destinationPort the destination port
     * @param protocol        the protocol
     * @return true if the access is authorized, else false.
     */
    public boolean accessAuthorizedFromInternet(Interface ni, int destinationPort, FirewallRule.Protocol protocol) {
        if (this.getFlowMatrixLines().size() == 0)
            return true; //If there is no flow matrix loaded, return always true...
        for (FlowMatrixLine flowMatrixLine : this.getFlowMatrixLines()) {
            if (flowMatrixLine.getSource().isInternet() && flowMatrixLine.getDestination().contains(ni)
                    && flowMatrixLine.getDestination_port().inRange(destinationPort)
                    && (flowMatrixLine.getProtocol() == FirewallRule.Protocol.ANY || protocol.equals(flowMatrixLine.getProtocol()))) {
                return true;
            }

        }
        return false;
    }

    /**
     * @return all lines of the flow matrix
     */
    public List<FlowMatrixLine> getFlowMatrixLines() {
        return flowMatrixLines;
    }

}
