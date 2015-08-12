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
 * along with FIWARE Cyber Security Generic Enabler.                                    *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/

package org.fiware.cybercaptor.server.flowmatrix;

import org.fiware.cybercaptor.server.topology.Topology;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.PortRange;
import org.jdom2.Element;

/**
 * Class to represent a line of the flow matrix (authorized access from source to destination)
 *
 * @author Francois-Xavier Aguessy
 */
public class FlowMatrixLine {
    /**
     * The source element
     */
    private final FlowMatrixElement source;

    /**
     * The destination element
     */
    private final FlowMatrixElement destination;

    /**
     * The source port range
     */
    private final PortRange source_port;

    /**
     * The destination port range
     */
    private final PortRange destination_port;

    /**
     * The protocol used
     */
    private final FirewallRule.Protocol protocol;

    /**
     * Create a flow matrix line from a XML DOM element
     *
     * @param element  the XML DOM Element
     * @param topology the network topology object
     */
    public FlowMatrixLine(Element element, Topology topology) {
        if (element == null)
            throw new IllegalArgumentException("The flow matrix line element is null");
        source = new FlowMatrixElement(element.getChild("source"), topology);
        destination = new FlowMatrixElement(element.getChild("destination"), topology);
        source_port = PortRange.fromString(element.getChildText("source_port"));
        destination_port = PortRange.fromString(element.getChildText("destination_port"));
        protocol = FirewallRule.Protocol.getProtocolFromString(element.getChildText("protocol"));
    }

    /**
     * @return get the source element
     */
    public FlowMatrixElement getSource() {
        return source;
    }

    /**
     * @return get the destination element
     */
    public FlowMatrixElement getDestination() {
        return destination;
    }

    /**
     * @return get the source port
     */
    public PortRange getSource_port() {
        return source_port;
    }

    /**
     * @return get the destination port
     */
    public PortRange getDestination_port() {
        return destination_port;
    }

    /**
     * @return get the protocol
     */
    public FirewallRule.Protocol getProtocol() {
        return protocol;
    }
}
