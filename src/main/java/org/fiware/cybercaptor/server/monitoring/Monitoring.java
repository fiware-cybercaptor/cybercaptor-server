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
package org.fiware.cybercaptor.server.monitoring;

import org.fiware.cybercaptor.server.attackgraph.AttackPath;
import org.fiware.cybercaptor.server.attackgraph.MulvalAttackGraph;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.remediation.cost.GlobalParameters;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents the monitoring (an information system, an attack graph and attack paths).
 *
 * @author Francois -Xavier Aguessy
 */
public class Monitoring {

    /**
     * The information system
     */
    private InformationSystem informationSystem;

    /**
     * The mulval attack graph
     */
    private MulvalAttackGraph attackGraph;

    /**
     * The list of attack path
     */
    private List<AttackPath> attackPathList = new ArrayList<AttackPath>();

    /**
     * The global parameters
     */
    private GlobalParameters globalParameters = new GlobalParameters();

    /**
     * The path to the cost parameters folder
     */
    private String pathToCostParametersFolder = "";

    /**
     * Create a monitoring object with the folder where the cost parameters may be stored
     *
     * @param pathToCostParametersFolder the path
     * @throws Exception the exception
     */
    public Monitoring(String pathToCostParametersFolder) throws Exception {
        this.setPathToCostParametersFolder(pathToCostParametersFolder);
        File file = new File(pathToCostParametersFolder + "/global-parameters.xml");
        if (file.exists())
            getGlobalParameters().loadFromXMLFile(pathToCostParametersFolder + "/global-parameters.xml");
    }

    /**
     * Load the attack graph, the attack paths and the network topology from an xml file
     *
     * @param XMLFilePath the xML file path
     * @param db          the db
     * @throws Exception the exception
     */
    public void loadFromXML(String XMLFilePath, Database db) throws Exception {
        FileInputStream file = new FileInputStream(XMLFilePath);
        SAXBuilder sxb = new SAXBuilder();
        Document document = sxb.build(file);
        Element root = document.getRootElement();

        Element attackGraphElement = root.getChild("attack_graph");
        setAttackGraph(new MulvalAttackGraph());
        getAttackGraph().addArcsAndVerticesFromDomElement(attackGraphElement);

        List<Element> attackPathsElements = root.getChildren("attack_path");
        if (!attackPathsElements.isEmpty()) {
            for (Element attackPathElement : attackPathsElements) {
                if (attackPathElement != null) {
                    AttackPath attackPath = new AttackPath();
                    attackPath.loadFromDomElementAndAttackGraph(attackPathElement, getAttackGraph());
                    this.getAttackPathList().add(attackPath);
                }
            }
        }
        AttackPath.sortAttackPaths(this.getAttackPathList());
        Element topologyElement = root.getChild("topology");
        setInformationSystem(new InformationSystem());
        getInformationSystem().loadFromDomElement(topologyElement, db);

        //this.attackGraph.addAttackGraphToTopology(informationSystem);

    }

    /**
     * Get the information system
     *
     * @return the information system
     */
    public InformationSystem getInformationSystem() {
        return informationSystem;
    }

    /**
     * Set the information system
     *
     * @param informationSystem new information system
     */
    public void setInformationSystem(InformationSystem informationSystem) {
        this.informationSystem = informationSystem;
    }

    /**
     * Gets attack graph.
     *
     * @return the attack graph
     */
    public MulvalAttackGraph getAttackGraph() {
        return attackGraph;
    }

    /**
     * Sets attack graph.
     *
     * @param attackGraph the attack graph
     */
    public void setAttackGraph(MulvalAttackGraph attackGraph) {
        this.attackGraph = attackGraph;
    }

    /**
     * Gets attack path list.
     *
     * @return the attack path list
     */
    public List<AttackPath> getAttackPathList() {
        return attackPathList;
    }

    /**
     * Sets attack path list.
     *
     * @param attackPathList the attack path list
     */
    public void setAttackPathList(List<AttackPath> attackPathList) {
        this.attackPathList = attackPathList;
    }

    /**
     * Gets global parameters.
     *
     * @return the global parameters
     */
    public GlobalParameters getGlobalParameters() {
        return globalParameters;
    }

    /**
     * Sets global parameters.
     *
     * @param globalParameters the global parameters
     */
    public void setGlobalParameters(GlobalParameters globalParameters) {
        this.globalParameters = globalParameters;
    }

    /**
     * Gets path to cost parameters folder.
     *
     * @return the path to cost parameters folder
     */
    public String getPathToCostParametersFolder() {
        return pathToCostParametersFolder;
    }

    /**
     * Sets path to cost parameters folder.
     *
     * @param pathToCostParametersFolder the path to cost parameters folder
     */
    public void setPathToCostParametersFolder(String pathToCostParametersFolder) {
        this.pathToCostParametersFolder = pathToCostParametersFolder;
    }
}
