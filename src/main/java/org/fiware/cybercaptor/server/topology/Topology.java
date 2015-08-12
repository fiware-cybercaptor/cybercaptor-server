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

package org.fiware.cybercaptor.server.topology;


import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.Network;
import org.fiware.cybercaptor.server.topology.asset.VLAN;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;


/**
 * Class that represents the network topology
 *
 * @author Francois-Xavier Aguessy
 */
public class Topology implements Cloneable {
    /**
     * The list of hosts in the topology
     */
    private ArrayList<Host> hosts = new ArrayList<Host>();

    /**
     * The list of contained vlans
     */
    private HashMap<String, VLAN> vlans = new HashMap<String, VLAN>();

    /**
     * Gets hosts.
     *
     * @return the hosts
     */
    public ArrayList<Host> getHosts() {
        return hosts;
    }

    /**
     * Add host.
     *
     * @param host the host to add
     */
    public void addHost(Host host) {
        this.hosts.add(host);
    }

    /**
     * Gets vlans.
     *
     * @return the vlans
     */
    public HashMap<String, VLAN> getVlans() {
        return vlans;
    }

    /**
     * Gets vlan.
     *
     * @param label the label of the vlan to search
     * @return the vlan
     */
    public VLAN getVlan(String label) {
        return this.vlans.get(label);
    }

    /**
     * Add vlan.
     *
     * @param vlan the vlan to add
     */
    public void addVlan(VLAN vlan) {
        this.vlans.put(vlan.getLabel(), vlan);
    }

    /**
     * Gets new or existing vlan.
     *
     * @param vlanLabel the vlan label
     * @return the vlan witch label is vlanLabel if it exists, else create a new vlan
     */
    public VLAN getNewOrExistingVlan(String vlanLabel) {
        if (getVlans().containsKey(vlanLabel))
            return getVlans().get(vlanLabel);
        else {
            VLAN vlan = new VLAN(vlanLabel);
            vlan.setName(vlanLabel);
            this.vlans.put(vlanLabel, vlan);
            return vlan;
        }
    }

    /**
     * Compute the route between two hosts. The max TTL has been set to 64.
     *
     * @param m1 the source host
     * @param m2 the destination host
     * @return the list of hosts that constitute the route
     * @throws Exception the exception
     */
    public List<Host> routeBetweenHosts(Host m1, Host m2) throws Exception {
        List<Host> usedHosts = new ArrayList<Host>();
        Iterator<Entry<String, Interface>> ite = m2.getInterfaces().entrySet().iterator();
        if (!ite.hasNext())
            throw new Exception("The destination host has no interface");
        Entry<String, Interface> inteNext = ite.next();
        m1.routeAPacketTo(inteNext.getValue().getAddress(), 64, usedHosts);
        return usedHosts;
    }

    /**
     * Send a packet from a host to another and see if it is blocked or not.
     *
     * @param ipFrom          IP of the sender
     * @param sourcePort      port of the sender
     * @param ipTo            IP of the receiver
     * @param destinationPort port of the receiver
     * @param protocol        protocol used
     * @return true if this packet arrives.
     * @throws Exception the exception
     */
    public boolean sendAPacketFromAHostToAnotherSucceed(IPAddress ipFrom, int sourcePort, IPAddress ipTo, int destinationPort, FirewallRule.Protocol protocol) throws Exception {
        Host m1 = existingHostByIPAddress(ipFrom);
        Host m2 = existingHostByIPAddress(ipTo);
        List<Host> hostList = routeBetweenHosts(m1, m2);
        return sendAPacketOnARoute(hostList, ipFrom, new IPAddress("255.255.255.255"), sourcePort, ipTo, new IPAddress("255.255.255.255"), destinationPort, protocol);
    }


    /**
     * Send a packet on a route and see if it is blocked or not.
     *
     * @param route           the route of the packet
     * @param ipFrom          the ip from
     * @param maskFrom        the mask from
     * @param sourcePort      the source port
     * @param ipTo            IP of the receiver
     * @param maskTo          the mask to
     * @param destinationPort port of the receiver
     * @param protocol        protocol used
     * @return true if this packet arrives.
     * @throws Exception the exception
     */
    public boolean sendAPacketOnARoute(List<Host> route, IPAddress ipFrom, IPAddress maskFrom, int sourcePort, IPAddress ipTo, IPAddress maskTo, int destinationPort, FirewallRule.Protocol protocol) throws Exception {

        if (route.size() > 1) { //At least one host
            //First host : only output if this host if the source host (not the case if the packet is sent from the internet, in that case input and output)
            if (this.existingHostByIPAddress(ipFrom) != null && this.existingHostByIPAddress(ipFrom).equals(route.get(0))) {
                if (!route.get(0).getOutputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)) {
                    System.out.println("Don't pass host output of \"" + route.get(0).getName() + "\" (" + protocol + " From : " + ipFrom.getAddress() + "/" + maskFrom.getMaskFromIPv4Address() + ":" + sourcePort + " To " + ipTo.getAddress() + "/" + maskTo.getMaskFromIPv4Address() + ":" + destinationPort + ")");
                    return false;
                }
            } else {
                if (!route.get(0).getInputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)
                        || !route.get(0).getOutputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)) {
                    System.out.println("Don't pass host \"" + route.get(0).getName() + "\" (" + protocol + " From : " + ipFrom.getAddress() + "/" + maskFrom.getMaskFromIPv4Address() + ":" + sourcePort + " To " + ipTo.getAddress() + "/" + maskTo.getMaskFromIPv4Address() + ":" + destinationPort + ")");
                    return false;
                }
            }


            //Other hosts : test input and output
            for (int i = 1; i < route.size() - 1; i++) {
                if (!route.get(i).getInputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)
                        || !route.get(i).getOutputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)) {
                    System.out.println("Don't pass host \"" + route.get(i).getName() + "\" (" + protocol + " From : " + ipFrom.getAddress() + "/" + maskFrom.getMaskFromIPv4Address() + ":" + sourcePort + " To " + ipTo.getAddress() + "/" + maskTo.getMaskFromIPv4Address() + ":" + destinationPort + ")");
                    return false;
                }
            }

            //Last host : only input if this host if the destination host (not the case if the packet is sent to the internet, in that case input and output)
            if (this.existingHostByIPAddress(ipTo) != null && this.existingHostByIPAddress(ipTo).equals(route.get(route.size() - 1))) {
                if (!route.get(route.size() - 1).getInputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)) {
                    System.out.println("Don't pass input of host \"" + route.get(route.size() - 1).getName() + "\" (" + protocol + " From : " + ipFrom.getAddress() + "/" + maskFrom.getMaskFromIPv4Address() + ":" + sourcePort + " To " + ipTo.getAddress() + "/" + maskTo.getMaskFromIPv4Address() + ":" + destinationPort + ")");
                    return false;
                }
            } else {
                if (!route.get(route.size() - 1).getInputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)
                        || !route.get(route.size() - 1).getOutputFirewallRulesTable().packetCanPass(protocol, ipFrom, maskFrom, sourcePort, ipTo, maskTo, destinationPort)) {
                    System.out.println("Don't pass host \"" + route.get(route.size() - 1).getName() + "\" (" + protocol + " From : " + ipFrom.getAddress() + "/" + maskFrom.getMaskFromIPv4Address() + ":" + sourcePort + " To " + ipTo.getAddress() + "/" + maskTo.getMaskFromIPv4Address() + ":" + destinationPort + ")");
                    return false;
                }
            }

            return true;
        } else //Only one host on the route, no filtering
            //No host in the route --> The packet can not be sent !
            return route.size() == 1;

    }

    /**
     * Send a packet on a route from internet.
     *
     * @param route      the route followed by the packet
     * @param ipAddress  the destination ip address
     * @param portNumber the destination port
     * @param protocol   the proto used
     * @return true if the packet can pass the route if it comes from internet
     * @throws Exception the exception
     */
    public boolean sendAPacketOnARouteFromInternet(List<Host> route, IPAddress ipAddress, int portNumber, FirewallRule.Protocol protocol) throws Exception {
        return this.sendAPacketOnARoute(route, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), 1025, ipAddress, IPAddress.getIPv4NetMask(32), portNumber, protocol);
    }

    /**
     * Gets host by iP address.
     *
     * @param ipAddress an IP Address
     * @return The host in the topology that has this IP Address. If this host doesn't exists, just add a new one.
     * @throws Exception the exception
     */
    public Host getHostByIPAddress(IPAddress ipAddress) throws Exception {
        Host existingHost = existingHostByIPAddress(ipAddress);
        if (existingHost != null)
            return existingHost;
        Host newHost = new Host(ipAddress.getAddress(), this);
        newHost.addInterface("int1", ipAddress.getAddress());
        this.addHost(newHost);
        return newHost;
    }

    /**
     * Gets interface by ip address.
     *
     * @param ipAddress the ip address
     * @return the interface by ip address
     * @throws Exception the exception
     */
    public Interface getInterfaceByIpAddress(IPAddress ipAddress) throws Exception {
        for (Host host : getHosts()) {
            for (Interface networkInterface : host.getInterfaces().values()) {
                if (networkInterface.getAddress().equals(ipAddress)) {
                    return networkInterface;
                }
            }
        }
        return null;
    }

    /**
     * Existing host by iP address.
     *
     * @param ipAddress the ip address
     * @return the host if it exists else null
     */
    public Host existingHostByIPAddress(IPAddress ipAddress) {
        for (int i = 0; i < this.getHosts().size(); i++) {
            if (this.getHosts().get(i).hasIP(ipAddress))
                return this.getHosts().get(i);
        }
        return null;
    }

    /**
     * Existing host by name.
     *
     * @param name the name of the host
     * @return the host if it exists else null
     */
    public Host existingHostByName(String name) {
        for (int i = 0; i < this.getHosts().size(); i++) {
            if (this.getHosts().get(i).getName().equals(name))
                return this.getHosts().get(i);
        }
        //if(name.equals("internet"))
        //	return new Host("internet",this);

        return null;
    }

    /**
     * Merge two hosts of the topology
     *
     * @param m1 the first host
     * @param m2 the second host
     * @return the host
     * @throws Exception the exception
     */
    public Host mergeTwoHosts(Host m1, Host m2) throws Exception {
        String name = "";
        if (!m1.getName().isEmpty() && !IPAddress.pattern.matcher(m1.getName()).matches()) //Not empty and not an IP address
            name = m1.getName();
        if (!m2.getName().isEmpty() && !IPAddress.pattern.matcher(m2.getName()).matches()) //Not empty and not an IP address
            name = m2.getName();
        if (name.isEmpty() && !m2.getName().isEmpty())
            name = m2.getName();
        if (name.isEmpty() && !m1.getName().isEmpty())
            name = m1.getName();

        Host newHost = new Host(name, this);

        if (!m1.getInputFirewallRulesTable().getRuleList().isEmpty())
            newHost.setInputFirewallRulesTable(m1.getInputFirewallRulesTable());
        if (!m2.getInputFirewallRulesTable().getRuleList().isEmpty())
            newHost.setInputFirewallRulesTable(m2.getInputFirewallRulesTable());

        if (!m1.getOutputFirewallRulesTable().getRuleList().isEmpty())
            newHost.setOutputFirewallRulesTable(m1.getOutputFirewallRulesTable());
        if (!m2.getOutputFirewallRulesTable().getRuleList().isEmpty())
            newHost.setOutputFirewallRulesTable(m2.getOutputFirewallRulesTable());

        if (!m1.getRoutingTable().getRouteList().isEmpty())
            newHost.setRoutingTable(m1.getRoutingTable());
        if (!m2.getRoutingTable().getRouteList().isEmpty())
            newHost.setRoutingTable(m2.getRoutingTable());

        for (String key : m2.getInterfaces().keySet()) { //Add the interfaces of m2
            Interface m2Interface = m2.getInterfaces().get(key);
            m2Interface.setHost(newHost);
            Interface m1Interface = m1.getExistingInterfaceFromIP(m2Interface.getAddress());
            if (m1Interface == null) { //This interface is not in m1
                newHost.getInterfaces().put(m2Interface.getName(), m2Interface);
            } else { //This interface is in m1
                m1Interface.setHost(newHost);
                Interface newInterface = Interface.mergeTwoInterfaces(m2Interface, m1Interface);
                newHost.getInterfaces().put(newInterface.getName(), newInterface);
            }
            if (m1Interface != null) {
                m1Interface.setHost(newHost);
            }
        }

        for (String key : m1.getInterfaces().keySet()) { //Add the interfaces of m1
            Interface old_intface = m1.getInterfaces().get(key);
            old_intface.setHost(newHost);
            if (!newHost.hasIP(old_intface.getAddress())) {//we add the interface only if it has not been added yet
                newHost.getInterfaces().put(old_intface.getName(), old_intface);
            }
        }

        this.getHosts().remove(m1);
        this.getHosts().remove(m2);
        this.getHosts().add(newHost);
        return newHost;
    }

    @Override
    public Topology clone() throws CloneNotSupportedException {
        Topology copie = (Topology) super.clone();

        copie.hosts = new ArrayList<Host>(this.getHosts());
        for (int i = 0; i < copie.getHosts().size(); i++) {
            copie.getHosts().set(i, copie.getHosts().get(i).clone());
        }

        copie.vlans = new HashMap<String, VLAN>(this.getVlans());
        for (String key : copie.getVlans().keySet()) {
            copie.getVlans().put(key, copie.getVlans().get(key).clone());
        }

        //For all the hosts
        for (int i = 0; i < copie.getHosts().size(); i++) {
            //update the references in all the interfaces of all the hosts
            Host hostCopie = copie.getHosts().get(i);
            for (String key : hostCopie.getInterfaces().keySet()) {
                Interface currentInterface = hostCopie.getInterfaces().get(key);
                //replace the directly connected interfaces by the real interfaces of the new object


                for (int j = 0; j < currentInterface.getDirectlyAccessibleInterface().size(); j++) {
                    try {
                        Interface newHostAccessibleInterface = currentInterface.getDirectlyAccessibleInterface().get(j);
                        Host newHostAccessible = copie.getHostByIPAddress(newHostAccessibleInterface.getHost().getFirstIPAddress());
                        currentInterface.getDirectlyAccessibleInterface().set(j, newHostAccessible.getInterfaces().get(newHostAccessibleInterface.getName()));

                    } catch (Exception e) {
                        System.out.println("Problem when copying the topology : host whitout ip address");
                    }
                }
            }
            hostCopie.setTopology(copie);

        }

        //For all the vlans
        for (String key : copie.getVlans().keySet()) {
            //update the references in all the interfaces and hosts of all the vlans
            VLAN currentVlan = copie.getVlans().get(key);
            for (int k = 0; k < currentVlan.getInterfaces().size(); k++) {
                Interface intface = currentVlan.getInterfaces().get(k);
                currentVlan.getInterfaces().set(k, copie.existingHostByIPAddress(intface.getAddress()).getExistingInterfaceFromIP(intface.getAddress()));
            }

            for (int k = 0; k < currentVlan.getHosts().size(); k++) {
                Host currentHost = currentVlan.getHosts().get(k);
                currentVlan.getHosts().set(k, copie.existingHostByIPAddress(currentHost.getFirstIPAddress()));
            }
        }

        return copie;
    }

    @Override
    public String toString() {
        String result = "Topology :\n";
        for (int i = 0; i < getHosts().size(); i++) {
            result += "    - " + getHosts().get(i) + "\n";
        }
        return result;
    }

    /**
     * Gets hosts in network.
     *
     * @param network a network
     * @return all the hosts of this topology that are in the network
     */
    public List<Host> getHostsInNetwork(Network network) {
        List<Host> result = new ArrayList<Host>();
        for (int i = 0; i < this.getHosts().size(); i++) {
            Host host = this.getHosts().get(i);
            if (host.inNetwork(network)) {
                result.add(host);
            }
        }
        return result;
    }

}
