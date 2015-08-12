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

package org.fiware.cybercaptor.server.api;

import org.fiware.cybercaptor.server.attackgraph.AttackGraph;
import org.fiware.cybercaptor.server.attackgraph.AttackPath;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.monitoring.Monitoring;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.remediation.DeployableRemediation;
import org.jdom2.Element;
import org.json.JSONObject;

import java.util.List;

/**
 * API Class used to manage attack paths
 *
 * @author Francois-Xavier Aguessy
 */
public class AttackPathManagement {

    /**
     * Extract
     *
     * @param attackGraph the attack graph
     * @return the scores extracted from the attack graph in the information system
     */
    public static List<AttackPath> scoreAttackPaths(AttackGraph attackGraph, double previousMaxScore) {
        try {
            String outputFolderPath = ProjectProperties.getProperty("output-path");
            attackGraph.saveToXmlFile(outputFolderPath + "/attack-graph-to-score.xml");
            return attackGraph.scoreAttackGraphAndGetAttackPaths(outputFolderPath + "/scored-attack-paths.xml", previousMaxScore);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * @param monitoring a monitoring object
     * @return the XML element related to all the attack paths contained in the monitoring object
     */
    public static Element getAttackPathsXML(Monitoring monitoring) {
        if (monitoring == null)
            return null;
        List<AttackPath> attackPaths = monitoring.getAttackPathList();
        Element root = new Element("attack_paths");
        for (AttackPath attackPath : attackPaths) {
            Element element = attackPath.toDomXMLElement();
            root.addContent(element);
        }

        return root;
    }

    /**
     * @param monitoring a monitoring object
     * @param id         the id of the attack path to print
     * @return the XML element related to the selected attack path contained in the monitoring object
     */
    public static Element getAttackPathXML(Monitoring monitoring, Integer id) {
        if (monitoring == null)
            return null;
        List<AttackPath> attackPaths = monitoring.getAttackPathList();

        if (id >= 0 && id < attackPaths.size()) {
            return attackPaths.get(id).toDomXMLElement();
        }
        return null;
    }

    /**
     * @param monitoring a monitoring object
     * @param id         the id of the attack path to print
     * @return the JSON element related to the topological attack path contained in the monitoring object
     */
    public static JSONObject getAttackPathTopologicalJson(Monitoring monitoring, Integer id) {
        if (monitoring == null)
            throw new IllegalStateException("The monitoring object is null");
        List<AttackPath> attackPaths = monitoring.getAttackPathList();

        if (id >= 0 && id < attackPaths.size()) {
            AttackPath attackPath = attackPaths.get(id);
            try {
                return attackPath.getRelatedTopologyGraph(monitoring.getInformationSystem()).toJsonObject();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        throw new IllegalStateException("This attack path can not be found.");
    }

    /**
     * @param monitoring a monitoring object
     * @return the JSON element related to the topological attack graph contained in the monitoring object
     */
    public static JSONObject getAttackGraphTopologicalJson(Monitoring monitoring) {
        if (monitoring == null)
            throw new IllegalStateException("The monitoring object is null");
        AttackGraph attackGraph = monitoring.getAttackGraph();

        try {
            return attackGraph.getRelatedTopologyGraph(monitoring.getInformationSystem()).toJsonObject();
        } catch (Exception e) {
            e.printStackTrace();
        }

        throw new IllegalStateException("This attack path can not be found.");
    }

    /**
     * @param monitoring a monitoring object
     * @param id         the id of the attack path to remediate
     * @param db         the remediation database
     * @return the XML element related to the remediations to the selected attack path contained in the monitoring ojbect
     */
    public static Element getRemediationXML(Monitoring monitoring, Integer id, Database db) {
        if (monitoring == null)
            return null;
        List<AttackPath> attackPaths = monitoring.getAttackPathList();
        if (id >= 0 && id < attackPaths.size()) {
            AttackPath attackPath = attackPaths.get(id);
            try {
                List<DeployableRemediation> remediations = attackPath.getDeployableRemediations(monitoring.getInformationSystem(), db.getConn(), monitoring.getPathToCostParametersFolder());
                Element root = new Element("remediations");
                for (DeployableRemediation remediation : remediations) {
                    root.addContent(remediation.toXMLElement());
                }
                return root;
            } catch (Exception e) {
                System.err.println("Error while computing remediations");
                e.printStackTrace();
            }
        }
        return null;
    }
}
