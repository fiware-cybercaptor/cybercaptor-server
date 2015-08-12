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
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule.Action;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule.Protocol;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule.Table;
import org.jdom2.Element;

import java.util.ArrayList;
import java.util.List;

/**
 * Class that represents the table of firewall rules on a host
 *
 * @author Francois-Xavier Aguessy
 */
public class FirewallRulesTable implements Cloneable {
    /**
     * The list of firewall rules
     */
    private ArrayList<FirewallRule> ruleList = new ArrayList<FirewallRule>();


    /**
     * The default action to take if no rule is matched
     */
    private Action defaultAction = Action.ACCEPT;
    /**
     * true if this element correspond to the input firewall rule table
     */
    private boolean isInput;

    public FirewallRulesTable(boolean isInput) {
        this.isInput = isInput;
    }

    /**
     * @return the ruleList
     */
    public ArrayList<FirewallRule> getRuleList() {
        return ruleList;
    }

    /**
     * @param ruleList the ruleList to set
     */
    public void setRuleList(ArrayList<FirewallRule> ruleList) {
        this.ruleList = ruleList;
    }

    /**
     * @return the defaultAction
     */
    public Action getDefaultAction() {
        return defaultAction;
    }

    /**
     * @param defaultAction the defaultAction to set
     */
    public void setDefaultAction(Action defaultAction) {
        this.defaultAction = defaultAction;
    }

    /**
     * Add a firewall rule in the firewall rule table
     *
     * @param action               the action if the rule is matched
     * @param protocol             the protocol
     * @param source               the source ip
     * @param sourceMask           the source mask
     * @param sourcePortRange      the source port range
     * @param destination          the destination ip
     * @param destinationMask      the destination mask
     * @param destinationPortRange the destination port range
     * @return a added rule
     */
    public FirewallRule addFirewallRule(Action action, Protocol protocol, IPAddress source, IPAddress sourceMask, PortRange sourcePortRange, IPAddress destination, IPAddress destinationMask, PortRange destinationPortRange) {
        for (int i = 0; i < this.getRuleList().size(); i++) {
            FirewallRule old_rule = this.getRuleList().get(i);
            if (old_rule.getProtocol() == protocol && old_rule.getSource().equals(source) && old_rule.getSourceMask().equals(sourceMask) && old_rule.getSourcePortRange().equals(sourcePortRange) && old_rule.getDestination().equals(destination) && old_rule.getDestinationMask().equals(destinationMask) && old_rule.getDestinationPortRange().equals(destinationPortRange))
                this.getRuleList().remove(i);
        }
        Table table;
        if (this.isInput)
            table = Table.INPUT;
        else
            table = Table.OUTPUT;

        FirewallRule rule = new FirewallRule(action, protocol, source, sourceMask, sourcePortRange, destination, destinationMask, destinationPortRange, table);
        this.getRuleList().add(rule);
        return rule;
    }

    /**
     * Test if a packet can pass according to the firewall rules
     *
     * @param protocol        the protocol used
     * @param source          the source ip address
     * @param sourceMask      the mask source
     * @param sourcePort      the port source (port number)
     * @param destination     the destination ip address
     * @param destinationMask the destination mask
     * @param destinationPort the port destination (port number)
     * @return true if the packet can pass the host, else false
     */
    public boolean packetCanPass(Protocol protocol, IPAddress source, IPAddress sourceMask, int sourcePort, IPAddress destination, IPAddress destinationMask, int destinationPort) {
        return packetCanPass(protocol, source, sourceMask, new PortRange(sourcePort, sourcePort), destination, destinationMask, new PortRange(destinationPort, destinationPort));
    }

    /**
     * Test if a packet can pass according to the firewall rules
     *
     * @param protocol             the protocol used
     * @param source               the source ip address
     * @param sourceMask           the mask source
     * @param sourcePortRange      the source port range
     * @param destination          the destination ip address
     * @param destinationMask      the destination mask
     * @param destinationPortRange the destination port range
     * @return true if the packet can pass the host, else false
     */
    public boolean packetCanPass(Protocol protocol, IPAddress source, IPAddress sourceMask, PortRange sourcePortRange, IPAddress destination, IPAddress destinationMask, PortRange destinationPortRange) {
        if (source.equals(destination) && sourceMask.getMaskFromIPv4Address() == 32 && destinationMask.getMaskFromIPv4Address() == 32)
            return true;
        for (int i = 0; i < getRuleList().size(); i++) {
            FirewallRule rule = getRuleList().get(i);
            if (rule.getProtocol().contained(protocol)
                    && IPAddress.networkInOtherNetwork(source, sourceMask, rule.getSource(), rule.getSourceMask())
                    && IPAddress.networkInOtherNetwork(destination, destinationMask, rule.getDestination(), rule.getDestinationMask())
                    && rule.getSourcePortRange().inRange(sourcePortRange)
                    && rule.getDestinationPortRange().inRange(destinationPortRange)) {
                if (rule.getAction() == Action.ACCEPT)
                    return true;
                else if (rule.getAction() == Action.DROP)
                    return false;
            }
        }
        return (this.getDefaultAction() == Action.ACCEPT);
    }

    /**
     * Load the firewall rule table from a DOM element extracted from an XML file
     *
     * @param domElement the firewall rule table DOM root
     * @throws Exception
     */
    public void loadFromDomElement(Element domElement) throws Exception {
        Element defaultPolicyElement = domElement.getChild("default-policy");
        if (defaultPolicyElement != null)
            this.setDefaultAction(Action.getActionFromString(defaultPolicyElement.getText()));

        //Add the firewall rules
        List<Element> fwRulesElements = domElement.getChildren("firewall-rule");
        for (Element fwRuleElement : fwRulesElements) {
            Element protocolElement = fwRuleElement.getChild("protocol");
            Element sourceIpElement = fwRuleElement.getChild("source-ip");
            Element sourceMaskElement = fwRuleElement.getChild("source-mask");
            Element sourcePortElement = fwRuleElement.getChild("source-port");
            Element destinationIpElement = fwRuleElement.getChild("destination-ip");
            Element destinationMaskElement = fwRuleElement.getChild("destination-mask");
            Element destinationPortElement = fwRuleElement.getChild("destination-port");
            Element actionElement = fwRuleElement.getChild("action");
            Table table;
            if (this.isInput)
                table = Table.INPUT;
            else
                table = Table.OUTPUT;

            if (protocolElement != null && sourceIpElement != null && sourceMaskElement != null &&
                    sourcePortElement != null && destinationIpElement != null && destinationMaskElement != null &&
                    destinationPortElement != null && actionElement != null) {
                FirewallRule fwRule = new FirewallRule(Action.getActionFromString(actionElement.getText()), Protocol.getProtocolFromString(protocolElement.getText()), new IPAddress(sourceIpElement.getText()), new IPAddress(sourceMaskElement.getText()), PortRange.fromString(sourcePortElement.getText()), new IPAddress(destinationIpElement.getText()), new IPAddress(destinationMaskElement.getText()), PortRange.fromString(destinationPortElement.getText()), table);
                this.getRuleList().add(fwRule);
            }
        }
    }

    /**
     * @return the dom element corresponding to this firewall rules tables in XML
     */
    public Element toDomXMLElement() {
        Element root;
        if (isInput)
            root = new Element("input-firewall");
        else
            root = new Element("output-firewall");

        Element defaultElement = new Element("default-policy");
        root.addContent(defaultElement);
        defaultElement.setText(this.getDefaultAction().toString().toUpperCase());

        //Firwall rules
        for (int i = 0; i < this.getRuleList().size(); i++) {
            FirewallRule rule = this.getRuleList().get(i);
            root.addContent(rule.toDomXMLElement());
        }

        return root;
    }

    @Override
    public FirewallRulesTable clone() throws CloneNotSupportedException {
        FirewallRulesTable copie = (FirewallRulesTable) super.clone();

        copie.setRuleList(new ArrayList<FirewallRule>(this.getRuleList()));
        for (int i = 0; i < copie.getRuleList().size(); i++) {
            copie.getRuleList().set(i, copie.getRuleList().get(i).clone());
        }

        return copie;
    }

    @Override
    public String toString() {
        String result = "";
        result += "FirewallRulesTable : defaultAction=" + getDefaultAction() + "\n";
        for (int i = 0; i < getRuleList().size(); i++) {
            result += "Rule " + i + " " + getRuleList().get(i) + "\n";
        }
        return result;
    }

    /**
     * @param rule a firewall rule
     * @return the list of firewall rules of this table that conflict with the rules given in parameter
     */
    public List<FirewallRule> getConflictsFirewallRulesWith(FirewallRule rule) {
        List<FirewallRule> result = new ArrayList<FirewallRule>();

        for (FirewallRule ruleToTest : this.ruleList) {
            if (rule.includedIntoRule(ruleToTest)) {
                //The action of these rules is different
                if (rule.getAction() != ruleToTest.getAction())
                    result.add(ruleToTest);
            }

            if (ruleToTest.includedIntoRule(rule)) {
                //The action of these rules is different
                if (rule.getAction() != ruleToTest.getAction())
                    result.add(ruleToTest);
            }

        }
        return result;
    }

    /**
     * Test if a firewall rule has a conflict with this firewall rule table
     * @param rule the firewall rule to test
     * @return true if there is a contect, else false
     */
    public boolean ruleConflictWithTable(FirewallRule rule) {
        List<FirewallRule> conflicts = this.getConflictsFirewallRulesWith(rule);
        return conflicts.size() > 0;
    }
}
