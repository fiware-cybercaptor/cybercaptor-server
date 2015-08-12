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
package org.fiware.cybercaptor.server.topology.asset.component;

import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.jdom2.Element;

/**
 * Class that represents a firewall rule
 *
 * @author Francois-Xavier Aguessy
 */
public class FirewallRule implements Cloneable {
    /**
     * the action to take if this rule is matched
     */
    private Action action;
    /**
     * the protocol
     */
    private Protocol protocol;
    /**
     * The source ip address
     */
    private IPAddress source;
    /**
     * The source mask
     */
    private IPAddress sourceMask;
    /**
     * The source port range
     */
    private PortRange sourcePortRange;
    /**
     * The destination IP address
     */
    private IPAddress destination;
    /**
     * The destination mask
     */
    private IPAddress destinationMask;
    /**
     * The destination port range
     */
    private PortRange destinationPortRange;
    /**
     * The table (INPUT, OUTPUT,FORWARD...)
     */
    private Table table;

    /**
     * Create a new firewall rule with all parameters
     *
     * @param action               the action to take if this rule is matched
     * @param protocol             the protocol
     * @param source               the source ip
     * @param sourceMask           the source mask
     * @param sourcePortRange      the port range
     * @param destination          the destination ip
     * @param destinationMask      the destination mask
     * @param destinationPortRange the port range
     */
    public FirewallRule(Action action, Protocol protocol, IPAddress source,
                        IPAddress sourceMask, PortRange sourcePortRange, IPAddress destination,
                        IPAddress destinationMask, PortRange destinationPortRange, Table table) {
        super();
        this.setAction(action);
        this.setProtocol(protocol);
        this.setSource(source);
        this.setSourceMask(sourceMask);
        this.setSourcePortRange(sourcePortRange);
        this.setDestination(destination);
        this.setDestinationMask(destinationMask);
        this.setDestinationPortRange(destinationPortRange);
        this.setTable(table);
    }

    /**
     * Parse the parameters of an IPTablesLine an create a FirewallRule
     *
     * @param target      "ACCEPT" or "DROP"
     * @param prot        the protocol (tcp, udp, all)
     * @param source      the source ip address with or without /mask
     * @param destination the destination ip address with or without /mask
     * @param options     the options
     * @return the FirewallRule related to the parameters
     * @throws Exception
     */
    public static FirewallRule parseIPTablesParams(String target, String prot, String source, String destination, String options, Table table) throws Exception {
        Action action = null;
        Protocol protocol = null;
        IPAddress ipsource;
        IPAddress masksource;
        PortRange sourcePortRange = new PortRange(true);
        IPAddress ipdestination;
        IPAddress maskdestination;
        PortRange destinationPortRange = new PortRange(true);

        //Action
        if (target.equals("ACCEPT")) {
            action = Action.ACCEPT;
        } else if (target.equals("DROP")) {
            action = Action.DROP;
        }

        //Protocol
        switch (prot) {
            case "tcp":
                protocol = Protocol.TCP;
                break;
            case "udp":
                protocol = Protocol.UDP;
                break;
            case "all":
                protocol = Protocol.ANY;
                break;
        }

        //source IP
        if (source.contains("/")) {
            ipsource = new IPAddress(source.substring(0, source.indexOf("/")));
            masksource = IPAddress.getIPv4NetMask(Integer.parseInt(source.substring(source.indexOf("/") + 1, source.length())));
        } else {
            ipsource = new IPAddress(source);
            masksource = new IPAddress("255.255.255.255");
        }

        //destination IP
        if (destination.contains("/")) {
            ipdestination = new IPAddress(destination.substring(0, destination.indexOf("/")));
            maskdestination = IPAddress.getIPv4NetMask(Integer.parseInt(destination.substring(destination.indexOf("/") + 1, destination.length())));
        } else {
            ipdestination = new IPAddress(destination);
            maskdestination = new IPAddress("255.255.255.255");
        }

        sourcePortRange.setAny(true); //If no information, the rule is for all ports
        destinationPortRange.setAny(true);
        //Options
        String[] options_list = options.split("\\s+");
        for (String anOptions_list : options_list) {
            String option = anOptions_list.trim();
            if (option.startsWith("spt:")) {
                sourcePortRange.setAny(false);
                String value = option.substring(4, option.length());
                sourcePortRange.setMin(Integer.parseInt(value));
                sourcePortRange.setMax(Integer.parseInt(value));
            } else if (option.startsWith("spts:")) {
                sourcePortRange.setAny(false);
                String value = option.substring(5, option.length());
                sourcePortRange.setMin(Integer.parseInt(value.substring(0, value.indexOf(":"))));
                sourcePortRange.setMax(Integer.parseInt(value.substring(value.indexOf(":") + 1, value.length())));
            } else if (option.startsWith("dpt:")) {
                destinationPortRange.setAny(false);
                String value = option.substring(4, option.length());
                destinationPortRange.setMin(Integer.parseInt(value));
                destinationPortRange.setMax(Integer.parseInt(value));
            } else if (option.startsWith("dpts:")) {
                destinationPortRange.setAny(false);
                String value = option.substring(5, option.length());
                destinationPortRange.setMin(Integer.parseInt(value.substring(0, value.indexOf(":"))));
                destinationPortRange.setMax(Integer.parseInt(value.substring(value.indexOf(":") + 1, value.length())));
            }
        }
        if (action == null || protocol == null || masksource == null || maskdestination == null)
            throw new Exception("Error in parsing rule");
        //System.out.println(sourcePortRange);
        return new FirewallRule(action, protocol, ipsource, masksource, sourcePortRange, ipdestination, maskdestination, destinationPortRange, table);
    }

    /**
     * @return the action
     */
    public Action getAction() {
        return action;
    }

    /**
     * @param action the action to set
     */
    public void setAction(Action action) {
        this.action = action;
    }

    /**
     * @return the protocol
     */
    public Protocol getProtocol() {
        return protocol;
    }

    /**
     * @param protocol the protocol to set
     */
    public void setProtocol(Protocol protocol) {
        this.protocol = protocol;
    }

    /**
     * @return the source
     */
    public IPAddress getSource() {
        return source;
    }

    /**
     * @param source the source to set
     */
    public void setSource(IPAddress source) {
        this.source = source;
    }

    /**
     * @return the sourceMask
     */
    public IPAddress getSourceMask() {
        return sourceMask;
    }

    /**
     * @param sourceMask the sourceMask to set
     */
    public void setSourceMask(IPAddress sourceMask) {
        this.sourceMask = sourceMask;
    }

    /**
     * @return the sourcePortRange
     */
    public PortRange getSourcePortRange() {
        return sourcePortRange;
    }

    /**
     * @param sourcePortRange the sourcePortRange to set
     */
    public void setSourcePortRange(PortRange sourcePortRange) {
        this.sourcePortRange = sourcePortRange;
    }

    /**
     * @return the destination
     */
    public IPAddress getDestination() {
        return destination;
    }

    /**
     * @param destination the destination to set
     */
    public void setDestination(IPAddress destination) {
        this.destination = destination;
    }

    /**
     * @return the destinationMask
     */
    public IPAddress getDestinationMask() {
        return destinationMask;
    }

    /**
     * @param destinationMask the destinationMask to set
     */
    public void setDestinationMask(IPAddress destinationMask) {
        this.destinationMask = destinationMask;
    }

    /**
     * @return the destinationPortRange
     */
    public PortRange getDestinationPortRange() {
        return destinationPortRange;
    }

    /**
     * @param destinationPortRange the destinationPortRange to set
     */
    public void setDestinationPortRange(PortRange destinationPortRange) {
        this.destinationPortRange = destinationPortRange;
    }

    /**
     * @return the table
     */
    public Table getTable() {
        return table;
    }

    /**
     * @param table the table to set
     */
    public void setTable(Table table) {
        this.table = table;
    }

    /**
     * @return the iptables command to add this rule
     */
    public String toIptablesAddRule() {
        String result = "";
        if (table == Table.INPUT)
            result += "iptables -I INPUT ";
        else if (table == Table.FORWARD)
            result += "iptables -I FORWARD ";
        else
            result += "iptables -I OUTPUT ";

        result += "-s " + getSource().getAddress() + "/" + getSourceMask().getMaskFromIPv4Address() + " ";
        result += "-d " + getDestination().getAddress() + "/" + getDestinationMask().getMaskFromIPv4Address() + " ";
        result += "-p " + getProtocol().toString() + " ";
        if (!getSourcePortRange().isAny())
            result += " --sport " + getSourcePortRange().getMin() + ":" + getSourcePortRange().getMax() + " ";
        if (!getDestinationPortRange().isAny())
            result += " --dport " + getDestinationPortRange().getMin() + ":" + getDestinationPortRange().getMax() + " ";
        result += " -j " + getAction().toString() + " ";
        return result;
    }

    /**
     * @return the dom element corresponding to this firewall rule in XML
     */
    public Element toDomXMLElement() {
        Element root = new Element("firewall-rule");

        Element protocolElement = new Element("protocol");
        root.addContent(protocolElement);
        protocolElement.setText(this.getProtocol().toString().toUpperCase());

        Element sourceIPElement = new Element("source-ip");
        root.addContent(sourceIPElement);
        sourceIPElement.setText(this.getSource().getAddress());

        Element sourceMaskElement = new Element("source-mask");
        root.addContent(sourceMaskElement);
        sourceMaskElement.setText(this.getSourceMask().getAddress());

        Element sourcePortElement = new Element("source-port");
        root.addContent(sourcePortElement);
        sourcePortElement.setText(this.getSourcePortRange().toString());

        Element destinationIPElement = new Element("destination-ip");
        root.addContent(destinationIPElement);
        destinationIPElement.setText(this.getDestination().getAddress());

        Element destinationMaskElement = new Element("destination-mask");
        root.addContent(destinationMaskElement);
        destinationMaskElement.setText(this.getDestinationMask().getAddress());

        Element destinationPortElement = new Element("destination-port");
        root.addContent(destinationPortElement);
        destinationPortElement.setText(this.getDestinationPortRange().toString());

        Element actionElement = new Element("action");
        root.addContent(actionElement);
        actionElement.setText(this.getAction().toString().toUpperCase());

        return root;
    }

    @Override
    public FirewallRule clone() throws CloneNotSupportedException {
        FirewallRule copie = (FirewallRule) super.clone();
        copie.setSource(this.getSource().clone());
        copie.setSourceMask(this.getSourceMask().clone());
        copie.setSourcePortRange(this.getSourcePortRange().clone());

        copie.setDestination(this.getDestination().clone());
        copie.setDestinationMask(this.getDestinationMask().clone());
        copie.setDestinationPortRange(this.getDestinationPortRange().clone());

        return copie;
    }

    @Override
    public String toString() {
        return "[action=" + getAction() + ", source=" + getSource().getAddress()
                + "/" + getSourceMask().getMaskFromIPv4Address() + ":"
                + getSourcePortRange() +
                ", destination="
                + getDestination().getAddress() + "/" + getDestinationMask().getMaskFromIPv4Address()
                + ":" + getDestinationPortRange()
                + ", protocol=" + getProtocol() + "]";
    }

    /**
     * @param rule2 a firewall rule
     * @return true if the current rule is included (action ignored) into rule2
     */
    public boolean includedIntoRule(FirewallRule rule2) {
        //Test if source network is included
        if (IPAddress.networkInOtherNetwork(this.getSource(), this.getSourceMask(), rule2.getSource(), rule2.getSourceMask())) {
            if (rule2.getSourcePortRange().inRange(this.getSourcePortRange())) {

                //Test if destination network is included
                if (IPAddress.networkInOtherNetwork(this.getDestination(), this.getDestinationMask(), rule2.getDestination(), rule2.getDestinationMask())) {
                    if (rule2.getDestinationPortRange().inRange(this.getDestinationPortRange())) {
                        return true;
                    }
                }

            }
        }
        return false;
    }

    /**
     * Possible Firewall actions
     */
    public enum Action {
        DROP, ACCEPT, LOG;

        public static Action getActionFromString(String action) {
            if (action.toLowerCase().equals("drop")) {
                return Action.DROP;
            } else if (action.toLowerCase().equals("log")) {
                return Action.LOG;
            } else {
                return Action.ACCEPT;
            }
        }
    }

    /**
     * IP protocols (TCP, UDP, ICMP) or all protocols (ANY)
     */
    public enum Protocol {
        TCP, UDP, ANY, ICMP;

        public static Protocol getProtocolFromString(String protocol) {
            if (protocol.toLowerCase().equals("tcp")) {
                return Protocol.TCP;
            } else if (protocol.toLowerCase().equals("udp")) {
                return Protocol.TCP;
            } else if (protocol.toLowerCase().equals("httpprotocol")) {
                return Protocol.TCP;
            } else if (protocol.toLowerCase().equals("icmp")) {
                return Protocol.ICMP;
            } else {
                return Protocol.ANY;
            }
        }

        public boolean contained(Protocol prot) {
            return this == Protocol.ANY || prot == this;
        }
    }

    /**
     * Types of table on a firewall
     */
    public enum Table {
        INPUT, OUTPUT, FORWARD
    }

}
