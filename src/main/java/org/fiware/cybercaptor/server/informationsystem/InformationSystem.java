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
package org.fiware.cybercaptor.server.informationsystem;


import org.fiware.cybercaptor.server.attackgraph.SecurityRequirement;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.flowmatrix.FlowMatrix;
import org.fiware.cybercaptor.server.flowmatrix.FlowMatrixElement;
import org.fiware.cybercaptor.server.flowmatrix.FlowMatrixLine;
import org.fiware.cybercaptor.server.topology.Topology;
import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.VLAN;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.fiware.cybercaptor.server.vulnerability.Vulnerability;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.util.ArrayList;
import java.util.List;


//TODO: check if some functions are not already defined in the topology.
// TODO: Perhaps this package should be merge with the topology.* package

/**
 * Class that represent the information system
 *
 * @author Francois-Xavier Aguessy
 */
public class InformationSystem implements Cloneable {


    /**
     * The network topology of the information system
     */
    private Topology topology = new Topology();

    /**
     * Is the attacker located on the internet in addition to {@link #machinesOfAttacker} ?
     */
    private boolean attackerLocatedOnInternet = false;

    /**
     * The flow matrix of the Information System
     */
    private FlowMatrix flowMatrix;

    /**
     * The list of machines that are mastered by the attacker
     */
    private List<InformationSystemHost> machinesOfAttacker = new ArrayList<InformationSystemHost>();


    /**
     * Create an empty information system
     */
    public InformationSystem() {

    }

    @Override
    public InformationSystem clone() throws CloneNotSupportedException {
        InformationSystem copie = (InformationSystem) super.clone();
        copie.topology = copie.topology.clone();
        return copie;
    }

    /**
     * Create a file with Datalog rules for the input of Mulval
     *
     * @param mulvalFilePath the filePath to store MulVAL input Datalog file
     * @throws Exception
     */
    public void exportToMulvalDatalogFile(String mulvalFilePath) throws Exception {
        PrintWriter fichier = new PrintWriter(new BufferedWriter(new FileWriter(mulvalFilePath)));

        //Add internet
        fichier.println("/**********************************/");
        fichier.println("/*    Add Internet                */");
        fichier.println("/**********************************/");

        fichier.println("attackerLocated(internet_host).");
        fichier.println("hasIP(internet_host,'1.1.1.1').");
        fichier.println("defaultLocalFilteringBehavior('internet_host',allow).");
        fichier.println("isInVlan('1.1.1.1','internet').");
        fichier.println();

        for (Host host : topology.getHosts()) {
            fichier.println("/**********************************/");
            fichier.println("/*    Add Host " + host.getName() + " */");
            fichier.println("/**********************************/");
            InformationSystemHost informationSystemHost = (InformationSystemHost) host;
            fichier.println("attackerLocated('" + host.getName() + "').");
            fichier.println("attackGoal(execCode('" + host.getName() + "', _)).");
            for (Interface networkInterface : host.getInterfaces().values()) {
                fichier.println("hasIP('" + host.getName() + "','" + networkInterface.getAddress().toString() + "').");
                if (networkInterface.getVlan() != null && !networkInterface.getVlan().getName().isEmpty()) {
                    fichier.println("isInVlan('" + networkInterface.getAddress().toString() + "','" + networkInterface.getVlan().getName() + "').");
                }
            }
            fichier.println("hostAllowAccessToAllIP('" + host.getName() + "').");
            for (Service service : informationSystemHost.getServices().values()) {
                fichier.println("installed('" + host.getName() + "','" + service.getName() + "').");
                if (service.getPortNumber() != 0) {
                    fichier.println("networkServiceInfo('" + service.getIpAddress() + "', '" + service.getName() + "', '" + service.getProtocol().toString() + "', " + service.getPortNumber() + ", 'user').");
                }

                for (String cve : service.getVulnerabilities().keySet()) {
                    Vulnerability vulnerability = service.getVulnerabilities().get(cve);
                    fichier.println("vulProperty('" + vulnerability.cve + "', " + vulnerability.exploitType + ", " + vulnerability.exploitGoal + ").");
                    fichier.println("vulExists('" + host.getName() + "', '" + vulnerability.cve + "', '" + service.getName() + "', " + vulnerability.exploitType + ", " + vulnerability.exploitGoal + ").");
                    if (vulnerability.cvss != null && vulnerability.cvss.getScore() >= 6.6) {
                        fichier.println("cvss('" + vulnerability.cve + "',h).");
                    } else if (vulnerability.cvss != null && vulnerability.cvss.getScore() >= 3.3) {
                        fichier.println("cvss('" + vulnerability.cve + "',m).");
                    } else if (vulnerability.cvss != null && vulnerability.cvss.getScore() > 0) {
                        fichier.println("cvss('" + vulnerability.cve + "',l).");
                    } else {
                        fichier.println("cvss('" + vulnerability.cve + "',m).");
                    }
                }
            }
            fichier.println();

        }

        //Add flow matrix elements
        if (this.flowMatrix != null && this.flowMatrix.getFlowMatrixLines().size() > 0) {
            for (FlowMatrixLine flowMatrixLine : this.flowMatrix.getFlowMatrixLines()) {
                String mulvalDestinationPort;
                if (flowMatrixLine.getDestination_port().isAny()) {
                    mulvalDestinationPort = "_";
                } else if (flowMatrixLine.getDestination_port().getMax() == flowMatrixLine.getDestination_port().getMin()) {
                    mulvalDestinationPort = "" + flowMatrixLine.getDestination_port().getMax();
                } else {
                    throw new IllegalStateException("Minimum and Maximum port range are not yet managed.");
                }

                String mulvalProtocol;
                if (flowMatrixLine.getProtocol().equals(FirewallRule.Protocol.ANY)) {
                    mulvalProtocol = "_";
                } else {
                    mulvalProtocol = "'" + flowMatrixLine.getProtocol().toString() + "'";
                }

                if (!mulvalDestinationPort.isEmpty() && !mulvalProtocol.isEmpty()) {
                    FlowMatrixElement sourceElement = flowMatrixLine.getSource();
                    FlowMatrixElement destinationElement = flowMatrixLine.getDestination();

                    if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.IP) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.IP)) {
                        if (sourceElement.getResource() instanceof Interface && destinationElement.getResource() instanceof Interface) {
                            Interface sourceInterface = (Interface) sourceElement.getResource();
                            Interface destinationInterface = (Interface) destinationElement.getResource();
                            fichier.println("haclprimit('" + sourceInterface.getAddress() + "','" + destinationInterface.getAddress() + "', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.INTERNET) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.IP)) {
                        if (destinationElement.getResource() instanceof Interface) {
                            Interface destinationInterface = (Interface) destinationElement.getResource();
                            fichier.println("vlanToIP('internet','" + destinationInterface.getAddress() + "', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.VLAN) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.IP)) {
                        if (sourceElement.getResource() instanceof VLAN && destinationElement.getResource() instanceof Interface) {
                            VLAN sourceVlan = (VLAN) sourceElement.getResource();
                            Interface destinationInterface = (Interface) destinationElement.getResource();
                            fichier.println("vlanToIP('" + sourceVlan.getName() + "','" + destinationInterface.getAddress() + "', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.IP) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.VLAN)) {
                        if (sourceElement.getResource() instanceof Interface && destinationElement.getResource() instanceof VLAN) {
                            Interface sourceInterface = (Interface) sourceElement.getResource();
                            VLAN destinationVlan = (VLAN) destinationElement.getResource();
                            fichier.println("ipToVlan('" + sourceInterface.getAddress() + "','" + destinationVlan.getName() + "', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.INTERNET) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.VLAN)) {
                        if (destinationElement.getResource() instanceof VLAN) {
                            VLAN destinationVLAN = (VLAN) destinationElement.getResource();
                            fichier.println("vlanToVlan('internet','" + destinationVLAN.getName() + "', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.VLAN) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.VLAN)) {
                        if (sourceElement.getResource() instanceof VLAN && destinationElement.getResource() instanceof VLAN) {
                            VLAN sourceVLAN = (VLAN) sourceElement.getResource();
                            VLAN destinationVLAN = (VLAN) destinationElement.getResource();
                            fichier.println("vlanToVlan('" + sourceVLAN.getName() + "','" + destinationVLAN.getName() + "', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.IP) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.INTERNET)) {
                        if (sourceElement.getResource() instanceof Interface) {
                            Interface sourceInterface = (Interface) sourceElement.getResource();
                            fichier.println("ipToVlan('" + sourceInterface.getAddress() + "','internet', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else if (sourceElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.VLAN) &&
                            destinationElement.getType().equals(FlowMatrixElement.FlowMatrixElementType.INTERNET)) {
                        if (sourceElement.getResource() instanceof VLAN) {
                            VLAN sourceVLAN = (VLAN) sourceElement.getResource();
                            fichier.println("vlanToVlan('" + sourceVLAN.getName() + "','internet', " + mulvalDestinationPort + "," + mulvalProtocol + ").");
                        } else {
                            throw new IllegalStateException("Illegal resource type");
                        }
                    } else {
                        throw new IllegalStateException("Unknown values of flow matrix");
                    }


                } else {
                    throw new IllegalStateException("Empty port or protocol");
                }
            }
        } else { //Empty flow matrix, add access betwen each couples of VLANs
            for (VLAN vlanFrom : this.topology.getVlans().values()) {
                for (VLAN vlanTo : this.topology.getVlans().values()) {
                    if (!vlanFrom.equals(vlanTo)) {
                        fichier.println("vlanToVlan('" + vlanFrom.getName() + "','" + vlanTo.getName() + "',_,_).");
                    }

                }
            }
        }

        fichier.println("/**********************************/");
        fichier.println("/******     General Rules    ******/");
        fichier.println("/**********************************/");
        fichier.println("defaultLocalFilteringBehavior(_,allow)."); //Attacker is on the internet

        fichier.close();
    }

    /**
     * Get a machine by its name or IP address. If the machine doesn't exist, add it to the topology
     *
     * @param str the name or IP address of the machine
     * @return the created or existing machine.
     * @throws Exception
     */
    public InformationSystemHost getHostByNameOrIPAddress(String str) throws Exception {
        if (IPAddress.isAnIPAddress(str)) {
            return getMachineByIPAddress(new IPAddress(str));
        } else {
            InformationSystemHost existingMachine = existingMachineByName(str);
            if (existingMachine != null)
                return existingMachine;
            InformationSystemHost newMachine = new InformationSystemHost(str, this.topology);
            this.topology.getHosts().add(newMachine);
            return newMachine;
        }
    }

    /**
     * get the routes from the internet to a host
     *
     * @param to the destination host
     * @return The list of routes
     * @throws Exception
     */
    public List<List<InformationSystemHost>> routesFromInternetTo(Host to) throws Exception {
        List<List<InformationSystemHost>> result = new ArrayList<List<InformationSystemHost>>();
        List<List<Host>> routes = to.getRoutesFromInternet();

        for (List<Host> route : routes) {
            List<InformationSystemHost> tmpResult = new ArrayList<InformationSystemHost>();
            for (Host aRoute : route) {
                tmpResult.add((InformationSystemHost) aRoute);
            }
            result.add(tmpResult);
        }

        return result;
    }

    /**
     * Get an existing machine of the information system with its name
     *
     * @param name the name of the machine
     * @return the machine if it exists else null
     */
    public InformationSystemHost existingMachineByName(String name) {
        for (int i = 0; i < this.topology.getHosts().size(); i++) {
            if (this.topology.getHosts().get(i).getName().equals(name))
                return (InformationSystemHost) this.topology.getHosts().get(i);
        }
        if (name.equals("internet"))
            return new InformationSystemHost("internet", topology);

        return null;
    }

    /**
     * Get an existing machine of the information system with its name or ip address
     *
     * @param str the name or ip address of the machine
     * @return the machine if it exists else null
     * @throws Exception
     */
    public InformationSystemHost existingMachineByNameOrIPAddress(String str) throws Exception {
        if (IPAddress.isAnIPAddress(str))
            return (InformationSystemHost) topology.existingHostByIPAddress(new IPAddress(str));
        else
            return existingMachineByName(str);
    }


    /**
     * Get an existing machine of the information system with a specific user
     *
     * @param username the name of the user
     * @return an existing machine that have the user that can use it.
     */
    public InformationSystemHost existingMachineByUserName(String username) {
        for (int i = 0; i < this.topology.getHosts().size(); i++) {
            InformationSystemHost machine = (InformationSystemHost) this.topology.getHosts().get(i);
            for (String j : machine.getUsers().keySet()) {
                if (machine.getUsers().get(j).getName().equals(username))
                    return machine;
            }
        }
        return null;
    }

    /**
     * Get a machine by its IP address, or create a new one if it does not exist
     *
     * @param ipAddress an IP Address
     * @return The machine in the topology that has this IP Address. If this machine doesn't exists, just add a new one.
     * @throws Exception
     */
    public InformationSystemHost getMachineByIPAddress(IPAddress ipAddress) throws Exception {
        InformationSystemHost existingMachine = (InformationSystemHost) topology.existingHostByIPAddress(ipAddress);
        if (existingMachine != null)
            return existingMachine;
        InformationSystemHost newMachine = new InformationSystemHost(ipAddress.getAddress(), topology);
        newMachine.addInterface("int1", ipAddress.getAddress());
        this.topology.getHosts().add(newMachine);
        return newMachine;
    }

    /**
     * Get the route from a host to the internet
     *
     * @param from the start of the route.
     * @return the route from a host to the internet
     * @throws Exception
     */
    public List<InformationSystemHost> routeToInternetFrom(Host from) throws Exception {
        List<InformationSystemHost> result = new ArrayList<InformationSystemHost>();
        List<Host> hosts = from.getRouteToInternet();
        for (Host host : hosts) {
            result.add((InformationSystemHost) host);
        }
        return result;
    }

    /**
     * Get the route between two hosts
     *
     * @param from the start of the route
     * @param to   the destination host
     * @return the route between two hosts
     * @throws Exception
     */
    public List<InformationSystemHost> routeBetweenHosts(InformationSystemHost from, InformationSystemHost to) throws Exception {
        List<InformationSystemHost> result = new ArrayList<InformationSystemHost>();
        List<Host> route = topology.routeBetweenHosts(from, to);
        for (Host aRoute : route) {
            result.add((InformationSystemHost) aRoute);
        }
        return result;
    }


    /**
     * Save the attack graph in an xml file
     *
     * @param filePath the file path where the attack graph will be save
     * @throws Exception
     */
    public void saveToXmlFile(String filePath) throws Exception {
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        output.output(toDomXMLElement(), new FileOutputStream(filePath));
    }

    /**
     * Get the XML DOM element of this information system
     *
     * @return the dom element corresponding to this topology with the format of the tva report file
     */
    public Element toDomXMLElement() {
        Element root = new Element("topology");

        //machines
        for (int i = 0; i < this.topology.getHosts().size(); i++) {
            InformationSystemHost machine = (InformationSystemHost) this.topology.getHosts().get(i);
            root.addContent(machine.toDomXMLElement());
        }

        return root;
    }

    /**
     * Load a network topology from a dom element
     *
     * @param domElement the dom element of an xml file
     * @throws Exception
     */
    public void loadFromDomElement(Element domElement, Database db) throws Exception {
        if (domElement == null)
            return;
        List<Element> hostsElement = domElement.getChildren("machine");
        for (Element hostElement : hostsElement) {
            InformationSystemHost host = new InformationSystemHost(this.topology);
            host.loadFromDomElement(hostElement, this.topology, db);
            this.topology.getHosts().add(host);
        }
        this.flowMatrix = new FlowMatrix(domElement.getChild("flow-matrix"), this.topology);
    }


    /**
     * Load the topology from an xml file
     *
     * @param XMLFilePath the path to the xml file
     * @throws Exception
     */
    public void loadFromXMLFile(String XMLFilePath, Database db) throws Exception {
        FileInputStream file = new FileInputStream(XMLFilePath);
        SAXBuilder sxb = new SAXBuilder();
        Document document = sxb.build(file);
        Element root = document.getRootElement();

        this.loadFromDomElement(root, db);
    }

    /**
     * Generates the Json object relative to the hosts list
     * @return the Json Object containing the hosts list
     */
    public JSONObject getHostsListJson() {
        //Build the json list of hosts
        JSONObject json = new JSONObject();
        JSONArray hosts_array = new JSONArray();
        for (Host host : this.getTopology().getHosts()) {
            InformationSystemHost informationSystemHost = (InformationSystemHost) host;
            JSONObject host_object = new JSONObject();
            host_object.put("name", informationSystemHost.getName());
            JSONArray security_requirements_array = new JSONArray();
            for (SecurityRequirement securityRequirement : informationSystemHost.getSecurityRequirements()) {
                JSONObject security_requirement = new JSONObject();
                security_requirement.put("name", securityRequirement.getName());
                security_requirement.put("metric", securityRequirement.getMetricPlainText());
                security_requirements_array.put(security_requirement);
            }
            host_object.put("security_requirements", security_requirements_array);
            hosts_array.put(host_object);
        }
        json.put("hosts", hosts_array);
        return json;
    }

    /**
     * Get the network topology
     *
     * @return the topology
     */
    public Topology getTopology() {
        return topology;
    }

    /**
     * Is the attacker located on the internet in addition to {@link #machinesOfAttacker} ?
     */
    public boolean isAttackerLocatedOnInternet() {
        return attackerLocatedOnInternet;
    }

    /**
     * Set the attacker on the internet status
     *
     * @param attackerLocatedOnInternet the new value of attackerLocatedOnInternet
     */
    public void setAttackerLocatedOnInternet(boolean attackerLocatedOnInternet) {
        this.attackerLocatedOnInternet = attackerLocatedOnInternet;
    }

    /**
     * Get the list of machines where the attacker is located (in addition to the internet)
     */
    public List<InformationSystemHost> getMachinesOfAttacker() {
        return machinesOfAttacker;
    }

    /**
     * Set the list of machines of the internet
     *
     * @param machinesOfAttacker new machines of the attacker
     */
    public void setMachinesOfAttacker(List<InformationSystemHost> machinesOfAttacker) {
        this.machinesOfAttacker = machinesOfAttacker;
    }
}
