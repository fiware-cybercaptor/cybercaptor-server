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

package org.fiware.cybercaptor.server.topology.asset;


import org.fiware.cybercaptor.server.topology.Topology;
import org.fiware.cybercaptor.server.topology.asset.component.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Class that represent an host
 *
 * @author Francois-Xavier Aguessy
 */
public class Host implements Cloneable {

    /**
     * The name of the host
     */
    private String name = "";

    /**
     * The list of Interface of the host
     */
    private HashMap<String, Interface> interfaces = new HashMap<String, Interface>();

    /**
     * The routing table of the host
     */
    private RoutingTable routingTable;

    /**
     * The input firewall rules table of the host
     */
    private FirewallRulesTable inputFirewallRulesTable = new FirewallRulesTable(true);

    /**
     * The output firewall rules table of the host
     */
    private FirewallRulesTable outputFirewallRulesTable = new FirewallRulesTable(false);

    /**
     * The topology in which is the host
     */
    private Topology topology = null;

    /**
     * Create an empty host
     */
    public Host(Topology topology) {
        routingTable = new RoutingTable(this);
        this.topology = topology;
    }

    /**
     * Create a host with its name
     *
     * @param name the name
     */
    public Host(String name, Topology topology) {
        this(topology);
        this.setName(name);
    }

    /**
     * @return true if route1 is a suffix of route2
     */
    private static boolean routeSuffixOfAnOtherRoute(List<Host> route1, List<Host> route2) {
        if (route1.size() > route2.size()) //route2 is too short for having route1 as prefix
            return false;
        for (int i = 1; i <= route1.size(); i++) {
            if (!route1.get(route1.size() - i).equals(route2.get(route2.size() - i))) //One element is different
                return false;
        }
        return true;
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
     * @return the interfaces
     */
    public HashMap<String, Interface> getInterfaces() {
        return interfaces;
    }

    /**
     * @return the routingTable
     */
    public RoutingTable getRoutingTable() {
        return routingTable;
    }

    /**
     * @param routingTable the routingTable to set
     */
    public void setRoutingTable(RoutingTable routingTable) {
        this.routingTable = routingTable;
    }

    /**
     * @return the inputFirewallRulesTable
     */
    public FirewallRulesTable getInputFirewallRulesTable() {
        return inputFirewallRulesTable;
    }

    /**
     * @param inputFirewallRulesTable the inputFirewallRulesTable to set
     */
    public void setInputFirewallRulesTable(FirewallRulesTable inputFirewallRulesTable) {
        this.inputFirewallRulesTable = inputFirewallRulesTable;
    }

    /**
     * @return the outputFirewallRulesTable
     */
    public FirewallRulesTable getOutputFirewallRulesTable() {
        return outputFirewallRulesTable;
    }

    /**
     * @param outputFirewallRulesTable the outputFirewallRulesTable to set
     */
    public void setOutputFirewallRulesTable(FirewallRulesTable outputFirewallRulesTable) {
        this.outputFirewallRulesTable = outputFirewallRulesTable;
    }

    /**
     * @return the topology
     */
    public Topology getTopology() {
        return topology;
    }

    /**
     * @param topology the topology to set
     */
    public void setTopology(Topology topology) {
        this.topology = topology;
    }

    /**
     * Add (or get) an interface on the host
     *
     * @param name      the interface name
     * @param ipAddress the ip address of the interface
     * @return the new (or existing) interface
     * @throws Exception
     */
    public Interface addInterface(String name, String ipAddress) throws Exception {
        if (!this.getInterfaces().containsKey(name)) { //If this host has not already this interface
            Interface intface = new Interface(name, ipAddress, this);
            this.getInterfaces().put(name, intface);
            return intface;
        } else
            return this.getInterfaces().get(name);
    }

    /**
     * Add (or get) an interface on the host
     *
     * @param name      the interface name
     * @param ipAddress the ip address of the interface
     * @param vlan      the vlan of the interface
     * @return the new (or existing) interface
     * @throws Exception
     */
    public Interface addInterface(String name, String ipAddress, VLAN vlan) throws Exception {
        if (!this.getInterfaces().containsKey(name)) { //If this host has not already this interface
            Interface intface = new Interface(name, ipAddress, this, vlan);
            this.getInterfaces().put(name, intface);
            return intface;
        } else
            return this.getInterfaces().get(name);
    }

    /**
     * Send a packet to the ip address and record the used hosts
     *
     * @param usedHosts the crossed hosts
     * @param ip        an ip address
     * @param ttl       the time to live of the packet
     * @throws Exception
     */
    public void routeAPacketTo(IPAddress ip, int ttl, List<Host> usedHosts) throws Exception {
        usedHosts.add(this);
        if (ttl == 0) {//Problem in routing
            throw new Exception("Routing problem, TTL is null : packet to " + ip + " deleted on host " + this.getName());
        }

        if (!hasIP(ip)) { //Packet not arrived
            Host nextHost = null;
            List<Host> directlyAccessibleHosts = getDirectlyAccessibleHosts();
            for (Host directlyAccessibleHost : directlyAccessibleHosts) {
                if (directlyAccessibleHost.hasIP(ip)) //If the packet is for a neighbour, we send it to him
                    nextHost = directlyAccessibleHost;
            }
            if (nextHost != null) {
                nextHost.routeAPacketTo(ip, ttl - 1, usedHosts);
            } else {//We have to look in the routing table
                List<Host> directlyAccessible = getDirectlyAccessibleHosts();
                IPAddress nextIP = this.getRoutingTable().getNextHop(ip);
                boolean nextHostFound = false;
                for (Host aDirectlyAccessible : directlyAccessible) {
                    if (aDirectlyAccessible.hasIP(nextIP)) { //Search the nextHop host object
                        aDirectlyAccessible.routeAPacketTo(ip, ttl - 1, usedHosts);
                        nextHostFound = true;
                    }
                }
                if (!nextHostFound) { //Routing problem
                    throw new Exception("Routing problem, there is no route corresponding to the packet or the destination host is on the internet");
                }

            }
        }

    }

    /**
     * @param ipTo            the ip address of the receiver
     * @param destinationPort the port of the receiver
     * @param protocol        the protocol used
     * @return true if the packet is arrived, else false
     * @throws Exception
     */
    public boolean sendAPacketToSucceed(IPAddress ipTo, int destinationPort, FirewallRule.Protocol protocol) throws Exception {
        for (String key : this.interfaces.keySet()) {
            Interface intface = this.interfaces.get(key);
            if (sendPacketSucceed(intface.getAddress(), 1025, ipTo, destinationPort, protocol))
                return true;
        }
        return false;
    }

    /**
     * @param ipFrom          the ip address of the sender
     * @param sourcePort      the port of the sender
     * @param ipTo            the ip address of the receiver
     * @param destinationPort the port of the receiver
     * @param protocol        the protocol used
     * @return true if the packet is arrived, else false
     * @throws Exception
     */
    public boolean sendPacketSucceed(IPAddress ipFrom, int sourcePort, IPAddress ipTo, int destinationPort, FirewallRule.Protocol protocol) throws Exception {
        return hostThatPreventToSendAPacket(ipFrom, sourcePort, ipTo, destinationPort, protocol, 64) == null;
    }

    /**
     * Try to send a packet on this host. Return the host that blocked the packet, if applicable
     *
     * @param ipFrom          the ip address of the sender
     * @param sourcePort      the port of the sender
     * @param ipTo            the ip address of the receiver
     * @param destinationPort the port of the receiver
     * @param protocol        the protocol used
     * @param ttl             the time to lived of the packet
     * @return null if the packet is well arrived. Else the machine that blocked the packet
     * @throws Exception if there is a routing problem
     */
    public Host hostThatPreventToSendAPacket(IPAddress ipFrom, int sourcePort, IPAddress ipTo, int destinationPort, FirewallRule.Protocol protocol, int ttl) throws Exception {
        if (ttl == 0) //Problem in routing
            return this;
        if (hasIP(ipTo)) { //Packet arrived to the right host
            if (!getInputFirewallRulesTable().packetCanPass(protocol, ipFrom, IPAddress.getIPv4NetMask(32), sourcePort, ipTo, IPAddress.getIPv4NetMask(32), destinationPort)
                    && !hasIP(ipFrom)) //This packet can not pass this host if there is a rule that block it and this host is not the sender of the packet
                return this;
            else {
                return null;
            }
        } else { //Packet needs to be routed
            if (hasIP(ipFrom)) {//filtering only output
                if (!getOutputFirewallRulesTable().packetCanPass(protocol, ipFrom, IPAddress.getIPv4NetMask(32), sourcePort, ipTo, IPAddress.getIPv4NetMask(32), destinationPort))
                    return this;
            } else { //Filtering input + output
                if (!getInputFirewallRulesTable().packetCanPass(protocol, ipFrom, IPAddress.getIPv4NetMask(32), sourcePort, ipTo, IPAddress.getIPv4NetMask(32), destinationPort))
                    return this; //Packet doesn't pass input filtering
                if (!getOutputFirewallRulesTable().packetCanPass(protocol, ipFrom, IPAddress.getIPv4NetMask(32), sourcePort, ipTo, IPAddress.getIPv4NetMask(32), destinationPort))
                    return this; //Packet doen't pass output filtering
            }

            //If we arrive here, the packet has passed the filtering processes
            Host vlanMachine = hostInVlan(ipTo);
            if (vlanMachine != null) {
                return vlanMachine.hostThatPreventToSendAPacket(ipFrom, sourcePort, ipTo, destinationPort, protocol, ttl - 1);
            }

            IPAddress nextIP = this.getRoutingTable().getNextHop(ipTo);
            Host nextHost = topology.existingHostByIPAddress(nextIP);
            if (nextHost == null) { //Did not find the next host
                if (this.connectedToTheInternet()) //This host is connected to the internet
                    return null; //The packet has been sent on the internet
                else
                    return this; //This host is the last one and it doen't know where to send the packet : packet deleted
            } else { //We know the next hop and send to it the packet
                return nextHost.hostThatPreventToSendAPacket(ipFrom, sourcePort, ipTo, destinationPort, protocol, ttl - 1);
            }
        }
    }

    /**
     * @param ipAddress an IP Address
     * @return The host in the topology that has this IP Address. If this host doesn't exists, just add a new one.
     * @throws Exception
     */
    public Interface getInterfaceByIPAddress(IPAddress ipAddress) throws Exception {
        for (String key : this.getInterfaces().keySet()) {
            if (this.getInterfaces().get(key).getAddress().equals(ipAddress))
                return this.getInterfaces().get(key);
        }
        Interface newInterface = new Interface("int", ipAddress.getAddress(), this);
        this.getInterfaces().put("int", newInterface);
        return newInterface;
    }

    /**
     * @return the list of hosts that are directly accessible to the interfaces of this host
     */
    public List<Host> getDirectlyAccessibleHosts() {
        List<Host> directlyAccessibleHosts = new ArrayList<Host>();
        for (String key : this.getInterfaces().keySet()) {
            Interface intface = getInterfaces().get(key);
            for (int j = 0; j < intface.getVlan().getHosts().size(); j++) {
                directlyAccessibleHosts.add(intface.getVlan().getHosts().get(j));
            }
        }
        return directlyAccessibleHosts;
    }

    /**
     * @return the list of vlans in which is this host
     */
    public List<VLAN> getVlans() {
        List<VLAN> result = new ArrayList<VLAN>();
        for (String key : this.getInterfaces().keySet()) {
            Interface intface = getInterfaces().get(key);
            result.add(intface.getVlan());
        }
        return result;
    }

    /**
     * @param address the ip address to search
     * @return the host that possess this IP address, if this host is in one of the vlan of the host
     */
    public Host hostInVlan(IPAddress address) {
        List<VLAN> vlans = getVlans();
        for (VLAN vlan : vlans) {
            List<Host> hostsOfVlan = vlan.getHosts();
            for (Host aHostsOfVlan : hostsOfVlan) {
                if (aHostsOfVlan.hasIP(address))
                    return aHostsOfVlan;
            }
        }
        return null;
    }

    /**
     * @param ip an IP Address
     * @return true if this host as this address IP on one of its interface
     */
    public boolean hasIP(IPAddress ip) {
        return !(this.getExistingInterfaceFromIP(ip) == null);
    }

    /**
     * @param ip the IP to look for
     * @return the existing interface of the host that correspond to the ip if it exists else null
     */
    public Interface getExistingInterfaceFromIP(IPAddress ip) {
        Interface result = null;
        for (String key : this.getInterfaces().keySet()) {
            if (this.getInterfaces().get(key).getAddress().equals(ip)) {
                result = this.getInterfaces().get(key);
                break;
            }
        }
        return result;
    }

    public IPAddress getFirstIPAddress() {
        if (this.getInterfaces().size() > 0) {
            return this.getInterfaces().get(this.getInterfaces().keySet().iterator().next()).getAddress();
        } else
            return null;
    }

    /**
     * @return true if the host is directly connected to the internet (has a wan interface)
     */
    public boolean connectedToTheInternet() {
        for (String i : this.getInterfaces().keySet()) {
            if (this.getInterfaces().get(i).isConnectedToTheInternet()) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return the route from this host to the internet
     * @throws Exception
     */
    public List<Host> getRouteToInternet() throws Exception {
        List<Host> result = new ArrayList<Host>();
        result.add(this);
        if (this.connectedToTheInternet())
            return result;
        else {
            IPAddress nextIP;
            try {
                nextIP = this.getRoutingTable().getNextHop(IPAddress.getIPv4NetMask(0));
            } catch (Exception e) {
                if (e.getMessage().equals("Missing default gateway")) {
                    return new ArrayList<Host>();
                } else
                    throw new Exception(e.getMessage());
            }
            Host nextHost = topology.existingHostByIPAddress(nextIP);
            if (nextHost == null) {
                return new ArrayList<Host>();
            }
            List<Host> hostsToInternet = nextHost.getRouteToInternet();
            if (hostsToInternet.size() == 0)
                return hostsToInternet;
            else {
                result.addAll(hostsToInternet);
                return result;
            }
        }
    }

    /**
     * @return the routes from Internet to this host
     * @throws Exception
     */
    public List<List<Host>> getRoutesFromInternet() throws Exception {
        List<List<Host>> result = new ArrayList<List<Host>>();


        for (int i = 0; i < topology.getHosts().size(); i++) {
            Host currentHost = topology.getHosts().get(i);
            if (currentHost.connectedToTheInternet()) {
                List<Host> route = new ArrayList<Host>();
                currentHost.routeAPacketTo(this.getFirstIPAddress(), 64, route);
                result.add(route);
            }
        }


        //Start refinement : deletion of redundant routes (routes in which a route is a suffix of the other routes)

        //Check if a route is a "suffix" of another route, in such a case, delete routes with this suffix.
        boolean resultHasChanged = true;
        while (resultHasChanged) {
            resultHasChanged = false;
            for (int i = 0; i < result.size(); i++) {
                for (int j = i + 1; j < result.size(); j++) {
                    if (routeSuffixOfAnOtherRoute(result.get(i), result.get(j))) { //route i is a suffix of route j
                        result.remove(j);
                        j--;
                        resultHasChanged = true;
                    } else if (routeSuffixOfAnOtherRoute(result.get(j), result.get(i))) {// route j is a suffix of route i
                        result.remove(i);
                        i--;
                        resultHasChanged = true;
                        break;
                    }
                }
            }
        }
        //Refinement done

        return result;
    }

    /**
     * @param network a network
     * @return true if this host is in the network else false
     */
    public boolean inNetwork(Network network) {
        for (String key : this.getInterfaces().keySet()) {
            Interface intface = this.getInterfaces().get(key);
            if (intface.getNetwork() != null && (new Network(intface.getAddress())).isIncludedIn(network))
                return true;
        }
        return false;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((getInterfaces() == null) ? 0 : getInterfaces().hashCode());
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
        Host other = (Host) obj;

        if (getName() == null) {
            if (other.getName() != null)
                return false;
        } else if (!getName().equals(other.getName()))
            return false;

        if (getInterfaces() == null) {
            if (other.getInterfaces() != null)
                return false;
        }
        if (this.getInterfaces() != null) {
            for (String key : this.getInterfaces().keySet()) {
                if (!other.getInterfaces().containsKey(key) || !other.getInterfaces().get(key).equals(this.getInterfaces().get(key))) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public Host clone() throws CloneNotSupportedException {
        Host copie = (Host) super.clone();

		/*
		 * Interfaces
		 */
        copie.interfaces = new HashMap<String, Interface>(this.getInterfaces());
        for (String key : copie.getInterfaces().keySet()) {
            copie.getInterfaces().put(key, copie.getInterfaces().get(key).clone());
        }

        //update the host object in all interfaces
        for (String key : copie.getInterfaces().keySet()) {
            Interface currentInterface = copie.getInterfaces().get(key);

            //replace the host object
            currentInterface.setHost(copie);
        }

		/*
		 * Routing table
		 */
        copie.routingTable = this.getRoutingTable().clone();

        //update the reference to the interfaces in the route object with the new interfaces
        for (int i = 0; i < copie.getRoutingTable().getRouteList().size(); i++) {
            Route currentRoute = copie.getRoutingTable().getRouteList().get(i);
            currentRoute.setIntface(copie.getInterfaces().get(currentRoute.getIntface().getName()));
        }

		/*
		 * Firewall Rules Table
		 */
        copie.setInputFirewallRulesTable(this.getInputFirewallRulesTable().clone());
        copie.setOutputFirewallRulesTable(this.getOutputFirewallRulesTable().clone());

        return copie;
    }

    @Override
    public String toString() {
        return getName();
    }
}
