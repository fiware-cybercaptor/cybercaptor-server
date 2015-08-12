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
import org.fiware.cybercaptor.server.remediation.Patch;
import org.fiware.cybercaptor.server.topology.Topology;
import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.Network;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRulesTable;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.fiware.cybercaptor.server.topology.asset.component.Route;
import org.fiware.cybercaptor.server.vulnerability.Vulnerability;
import org.jdom2.Element;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class that represents a host of the {@link org.fiware.cybercaptor.server.informationsystem.InformationSystem}
 *
 * @author Francois-Xavier Aguessy
 */
public class InformationSystemHost extends Host {

    /**
     * The network services running on this host
     */
    private Map<String, Service> services = new HashMap<String, Service>();

    /**
     * The list of the users of this host
     */
    private Map<String, User> users = new HashMap<String, User>();

    /**
     * The accounts on this host
     */
    private Map<String, Account> accounts = new HashMap<String, Account>();

    /**
     * The security requirements that needs this machine
     */
    private List<SecurityRequirement> securityRequirements = new ArrayList<SecurityRequirement>();

    /**
     * Create an empty host
     *
     * @param topology the network topology
     */
    public InformationSystemHost(Topology topology) {
        super(topology);
    }

    /**
     * Create a host with its name
     *
     * @param str      the name of the host
     * @param topology the topology
     */
    public InformationSystemHost(String str, Topology topology) {
        super(str, topology);
    }

    /**
     * @return the services
     */
    public Map<String, Service> getServices() {
        return services;
    }

    /**
     * @return the users
     */
    public Map<String, User> getUsers() {
        return users;
    }

    /**
     * @param users the users to set
     */
    public void setUsers(Map<String, User> users) {
        this.users = users;
    }

    /**
     * Delete on the service of the machine the vulnerabilities that should be corrected
     *
     * @param correctedVulnerabilities the vulnerabilities to correct
     */
    public void correctVulnerabilities(List<Vulnerability> correctedVulnerabilities) {
        for (String key : services.keySet()) {
            Service service = services.get(key);
            for (Vulnerability vulnerability : correctedVulnerabilities) {
                if (service.getVulnerabilities().containsKey(vulnerability.cve)) {
                    service.getVulnerabilities().remove(vulnerability.cve);
                }
            }
        }
    }

    /**
     * Return the service if it exists or create a new service if it doesn't
     *
     * @param key the key of the service
     * @return the service
     */
    public Service getNewOrExistingService(String key) {
        Service result = getExistingService(key);
        if (result != null) {
            return services.get(key);
        } else {
            result = new Service(key);
            result.setMachine(this);
            this.services.put(key, result);
            return result;
        }
    }

    /**
     * Return the service if it exists or return null if it doesn't
     *
     * @param key the name of the service
     * @return the service
     */
    public Service getExistingService(String key) {
        if (services.containsKey(key)) {
            return services.get(key);
        } else {
            return null;
        }
    }

    /**
     * Get an existing service from port and protocol. If the service is not found, return null
     *
     * @param protocol the protocol
     * @param port     the port of the service
     * @return the service
     */
    public Service getExistingServiceFromProtocolAndPort(FirewallRule.Protocol protocol, int port) {
        Service result = null;
        for (String key : services.keySet()) {
            if (services.get(key).getProtocol() == protocol && services.get(key).getPortNumber() == port) {
                result = services.get(key);
                break;
            }
        }
        return result;
    }

    /**
     * @return the dom element corresponding to this host with the format of the tva report file
     */
    public Element toDomXMLElement() {
        Element root = new Element("machine");

        Element nameElement = new Element("name");
        nameElement.setText(this.getName());
        root.addContent(nameElement);

        Element cpeElement = new Element("cpe");
        cpeElement.setText("cpe:/");
        root.addContent(cpeElement);

        //Interfaces
        Element interfacesElement = new Element("interfaces");
        root.addContent(interfacesElement);
        for (String key : getInterfaces().keySet()) {
            Interface intface = getInterfaces().get(key);
            interfacesElement.addContent(intface.toDomElement());
        }

        //Services
        Element servicesElement = new Element("services");
        root.addContent(servicesElement);
        for (String key : services.keySet()) {
            Service service = services.get(key);
            servicesElement.addContent(service.toDomXMLElement());
        }

        //Routes
        Element routesElement = new Element("routes");
        root.addContent(routesElement);
        for (int i = 0; i < this.getRoutingTable().getRouteList().size(); i++) {
            Route route = this.getRoutingTable().getRouteList().get(i);
            routesElement.addContent(route.toDomXMLElement());
        }

        //Firwall
        root.addContent(getInputFirewallRulesTable().toDomXMLElement());
        root.addContent(getOutputFirewallRulesTable().toDomXMLElement());

        return root;
    }

    /**
     * Load the host from a DOM element (extracted from an XML file)
     *
     * @param domElement the host root dom element
     * @param topology   the current network topology
     * @throws Exception
     */
    public void loadFromDomElement(Element domElement, Topology topology, Database db) throws Exception {
        Element nameElement = domElement.getChild("name");
        if (nameElement != null)
            this.setName(nameElement.getText());

        Element securityRequirementElement = domElement.getChild("security_requirement");
        if (securityRequirementElement != null) {
            double securityRequirementValue = Double.parseDouble(securityRequirementElement.getText());
            SecurityRequirement securityRequirement = new SecurityRequirement("sec-req-xml", securityRequirementValue);
            this.addSecurityRequirements(securityRequirement);
        }

        //Host interfaces
        Element interfacesElement = domElement.getChild("interfaces");
        if (interfacesElement != null) {
            List<Element> interfaceListElement = interfacesElement.getChildren("interface");
            for (Element interfaceElement : interfaceListElement) {
                Element interfaceNameElement = interfaceElement.getChild("name");
                Element interfaceAddressElement = interfaceElement.getChild("ipaddress");
                Element interfaceVlanElement = interfaceElement.getChild("vlan");
                if (interfaceNameElement != null && interfaceAddressElement != null) {
                    String interfaceName = interfaceNameElement.getText();
                    String interfaceAddress = interfaceAddressElement.getText();
                    Interface inface;

                    if (interfaceVlanElement != null && !interfaceVlanElement.getText().isEmpty()) {
                        inface = new Interface(interfaceName, interfaceAddress, this, topology.getNewOrExistingVlan(interfaceVlanElement.getChildText("label")));
                    } else {
                        inface = new Interface(interfaceName, interfaceAddress, this);
                    }

                    this.getInterfaces().put(interfaceName, inface);

                    Element networkElement = interfaceElement.getChild("network");
                    Element maskElement = interfaceElement.getChild("mask");
                    if (networkElement != null && maskElement != null) {
                        inface.setNetwork(new Network(new IPAddress(networkElement.getText()), new IPAddress(maskElement.getText())));
                    }

                    Element directlyConnectedElement = interfaceElement.getChild("directly-connected");
                    if (directlyConnectedElement != null) {
                        Element connectedToInternetElement = directlyConnectedElement.getChild("internet");
                        if (connectedToInternetElement != null) {
                            inface.setConnectedToTheInternet(true);
                        }
                    }
                }
            }
        }

        //Machine services
        Element servicesElement = domElement.getChild("services");
        if (servicesElement != null) {
            List<Element> servicesElementList = servicesElement.getChildren("service");
            for (Element serviceElement : servicesElementList) {
                Element serviceNameElement = serviceElement.getChild("name");
                if (serviceNameElement != null) {
                    String serviceName = serviceNameElement.getText();
                    Service service;
                    if (!this.services.containsKey(serviceName)) {
                        service = new Service(serviceName);
                        this.services.put(serviceName, service);
                        service.setMachine(this);
                    } else {
                        service = this.services.get(serviceName);
                    }


                    Element serviceIPElement = serviceElement.getChild("ipaddress");
                    if (serviceIPElement != null && !serviceIPElement.getText().isEmpty() && service.getIpAddress() == null) {
                        service.setIpAddress(new IPAddress(serviceIPElement.getText()));
                    }

                    Element servicePortElement = serviceElement.getChild("port");
                    if (servicePortElement != null && !servicePortElement.getText().isEmpty() && service.getPortNumber() == 0)
                        service.setPortNumber(Service.portStringToInt(servicePortElement.getText()));

                    Element serviceProtocolElement = serviceElement.getChild("protocol");
                    if (serviceProtocolElement != null && !serviceProtocolElement.getText().isEmpty() && service.getProtocol() == null)
                        service.setProtocol(FirewallRule.Protocol.getProtocolFromString(serviceProtocolElement.getText()));

                    Element serviceCPEElement = serviceElement.getChild("CPE");
                    if (serviceCPEElement != null)
                        service.setCPE(serviceCPEElement.getText());

                    Element serviceAccountElement = serviceElement.getChild("user");
                    if (serviceAccountElement != null) {
                        service.setAccount(this.getAccountByName(serviceAccountElement.getText()));
                    }

                    Element serviceVersionElement = serviceElement.getChild("version");
                    if (serviceVersionElement != null)
                        service.setVersion(serviceVersionElement.getText());

                    Element vulnerabilitiesElement = serviceElement.getChild("vulnerabilities");
                    if (vulnerabilitiesElement != null) {
                        List<Element> vulnsElements = vulnerabilitiesElement.getChildren("vulnerability");
                        for (Element vulnElement : vulnsElements) {
                            Element typeElement = vulnElement.getChild("type");
                            Element goalElement = vulnElement.getChild("goal");
                            Element cveElement = vulnElement.getChild("cve");

                            Vulnerability vuln = new Vulnerability(cveElement.getText());
                            vuln.exploitGoal = goalElement.getText();
                            vuln.exploitType = typeElement.getText();
                            vuln.loadParametersFromDatabase(db.getConn());

                            service.getVulnerabilities().put(vuln.cve, vuln);

                        }
                    }

                    Element serviceDeployedPatchElement = serviceElement.getChild("deployed-patchs");
                    if (serviceDeployedPatchElement != null) {
                        List<Element> patchsElements = serviceDeployedPatchElement.getChildren("patch");
                        for (Element patchElement : patchsElements) {
                            Patch patch = new Patch(patchElement.getText());
                            service.getDeployedPatches().add(patch);
                        }
                    }
                }
            }
        }


        Element routesElement = domElement.getChild("routes");
        if (routesElement != null)
            this.getRoutingTable().loadFromDomElement(routesElement, this);

        Element incommingFirewallElement = domElement.getChild("input-firewall");
        if (incommingFirewallElement != null)
            this.getInputFirewallRulesTable().loadFromDomElement(incommingFirewallElement);

        Element outgoingFirewallElement = domElement.getChild("output-firewall");
        if (outgoingFirewallElement != null)
            this.getOutputFirewallRulesTable().loadFromDomElement(outgoingFirewallElement);
    }

    /**
     * @param text the name of the account to find
     * @return the account whose name is text on this host
     */
    private Account getAccountByName(String text) {
        if (this.accounts.get(text) != null)
            return this.accounts.get(text);
        else {
            Account account = new Account(text);
            account.setMachine(this);
            this.accounts.put(text, account);
            return account;
        }
    }

    @Override
    public String toString() {
        if (getFirstIPAddress() != null)
            return getName() + "(" + getFirstIPAddress().getAddress() + ")";
        return getName();
    }

    /**
     * @return the metric
     */
    public double getMetric() {
        double result = 0.;
        for (SecurityRequirement securityRequirement : securityRequirements) {
            result += securityRequirement.getMetric();
        }
        return result;
    }

    /**
     * @return the securityRequirements
     */
    public List<SecurityRequirement> getSecurityRequirements() {
        return securityRequirements;
    }

    /**
     * Remove all security requirements of this host
     */
    public void removeAllSecurityRequirements() {
        this.securityRequirements = new ArrayList<>();
    }

    /**
     * @param securityRequirement the securityRequirements to add
     */
    public void addSecurityRequirements(SecurityRequirement securityRequirement) {
        this.securityRequirements.add(securityRequirement);
    }

    /**
     * @param ruleToDeploy a firewall rule that can be deployed on this host
     * @return true if the parameter firewall rule is conflicting with the currently deployed rules on this host
     */
    public List<FirewallRule> firewallRuleConflict(FirewallRule ruleToDeploy) {
        FirewallRulesTable table;
        if (ruleToDeploy.getTable() == FirewallRule.Table.INPUT) {
            table = this.getInputFirewallRulesTable();
        } else {
            table = this.getOutputFirewallRulesTable();
        }

        return table.getConflictsFirewallRulesWith(ruleToDeploy);
    }

}
