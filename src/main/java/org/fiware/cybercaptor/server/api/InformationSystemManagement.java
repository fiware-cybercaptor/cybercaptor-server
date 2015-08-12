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

package org.fiware.cybercaptor.server.api;

import org.fiware.cybercaptor.server.attackgraph.AttackGraph;
import org.fiware.cybercaptor.server.attackgraph.MulvalAttackGraph;
import org.fiware.cybercaptor.server.attackgraph.SecurityRequirement;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.monitoring.Monitoring;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.remediation.DeployableRemediation;
import org.fiware.cybercaptor.server.remediation.DeployableRemediationAction;
import org.fiware.cybercaptor.server.remediation.Patch;
import org.fiware.cybercaptor.server.remediation.Rule;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.vulnerability.Vulnerability;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An API class used to manage everything related to the information system and attack graph generation
 *
 * @author Francois-Xavier Aguessy
 */
public class InformationSystemManagement {
    /**
     * Load the information system from an XML File
     *
     * @param XMLInformationSystemFile the XML file path
     * @return the InformationSystem object
     */
    public static InformationSystem loadTopologyXMLFile(String XMLInformationSystemFile, Database db) {

        InformationSystem result = new InformationSystem();
        try {
            result.loadFromXMLFile(XMLInformationSystemFile, db);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Execute MulVAL on the topology and return the attack graph
     *
     * @param informationSystem the input network
     * @return the associated attack graph object
     */
    public static AttackGraph prepareInputsAndExecuteMulVal(InformationSystem informationSystem) {
        if (informationSystem == null)
            return null;
        try {
            //Load MulVAL properties

            String mulvalPath = ProjectProperties.getProperty("mulval-path");
            String xsbPath = ProjectProperties.getProperty("xsb-path");
            String outputFolderPath = ProjectProperties.getProperty("output-path");

            File mulvalInputFile = new File(ProjectProperties.getProperty("mulval-input"));

            File mulvalOutputFile = new File(outputFolderPath + "/AttackGraph.xml");
            if (mulvalOutputFile.exists()) {
                mulvalOutputFile.delete();
            }
            Logger.getAnonymousLogger().log(Level.INFO, "Genering MulVAL inputs");
            informationSystem.exportToMulvalDatalogFile(mulvalInputFile.getAbsolutePath());

            Logger.getAnonymousLogger().log(Level.INFO, "Launching MulVAL");
            ProcessBuilder processBuilder = new ProcessBuilder(mulvalPath + "/utils/graph_gen.sh", mulvalInputFile.getAbsolutePath(), "-l");

            if (ProjectProperties.getProperty("mulval-rules-path") != null) {
                processBuilder.command().add("-r");
                processBuilder.command().add(ProjectProperties.getProperty("mulval-rules-path"));
            }

            processBuilder.directory(new File(outputFolderPath));
            processBuilder.environment().put("MULVALROOT", mulvalPath);
            String path = System.getenv("PATH");
            processBuilder.environment().put("PATH", mulvalPath + "/utils/:" + xsbPath + ":" + path);
            Process process = processBuilder.start();
            process.waitFor();

            if (!mulvalOutputFile.exists()) {
                Logger.getAnonymousLogger().log(Level.INFO, "Empty attack graph!");
                return null;
            }

            MulvalAttackGraph ag = new MulvalAttackGraph(mulvalOutputFile.getAbsolutePath());

            ag.loadMetricsFromTopology(informationSystem);

            return ag;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Execute MulVAL on the topology and return the attack graph
     *
     * @return the associated attack graph object
     */
    public static AttackGraph generateAttackGraphWithMulValUsingAlreadyGeneratedMulVALInputFile() {
        try {
            //Load MulVAL properties

            String mulvalPath = ProjectProperties.getProperty("mulval-path");
            String xsbPath = ProjectProperties.getProperty("xsb-path");
            String outputFolderPath = ProjectProperties.getProperty("output-path");

            File mulvalInputFile = new File(ProjectProperties.getProperty("mulval-input"));

            File mulvalOutputFile = new File(outputFolderPath + "/AttackGraph.xml");
            if (mulvalOutputFile.exists()) {
                mulvalOutputFile.delete();
            }

            Logger.getAnonymousLogger().log(Level.INFO, "Launching MulVAL");
            ProcessBuilder processBuilder = new ProcessBuilder(mulvalPath + "/utils/graph_gen.sh", mulvalInputFile.getAbsolutePath(), "-l");

            if (ProjectProperties.getProperty("mulval-rules-path") != null) {
                processBuilder.command().add("-r");
                processBuilder.command().add(ProjectProperties.getProperty("mulval-rules-path"));
            }

            processBuilder.directory(new File(outputFolderPath));
            processBuilder.environment().put("MULVALROOT", mulvalPath);
            String path = System.getenv("PATH");
            processBuilder.environment().put("PATH", mulvalPath + "/utils/:" + xsbPath + ":" + path);
            Process process = processBuilder.start();
            process.waitFor();

            if (!mulvalOutputFile.exists()) {
                Logger.getAnonymousLogger().log(Level.INFO, "Empty attack graph!");
                return null;
            }

            MulvalAttackGraph ag = new MulvalAttackGraph(mulvalOutputFile.getAbsolutePath());

            return ag;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * @param informationSystem The initial topology
     * @param remediation       the remediation deployment that must be simulated
     * @param db                the vulnerability database
     * @return a clone of the topology, in which the remediation is applied
     */
    public static InformationSystem simulateRemediationOnNewInforationSystem(InformationSystem informationSystem, DeployableRemediation remediation, Database db) {
        InformationSystem simulatedTopology = null;
        try {
            simulatedTopology = informationSystem.clone();

            for (int i = 0; i < remediation.getActions().size(); i++) {
                DeployableRemediationAction action = remediation.getActions().get(i);
                Logger.getAnonymousLogger().log(Level.INFO, "Simulate the remediation " + action.getRemediationAction().getActionType() + " on machine " + action.getHost());
                switch (action.getRemediationAction().getActionType()) {
                    case APPLY_PATCH:
                        for (int j = 0; j < action.getRemediationAction().getRemediationParameters().size(); j++) {
                            Patch patch = (Patch) action.getRemediationAction().getRemediationParameters().get(j);
                            List<Vulnerability> correctedVulnerabilities = patch.getCorectedVulnerabilities(db.getConn());
                            simulatedTopology.existingMachineByNameOrIPAddress(action.getHost().getName()).correctVulnerabilities(correctedVulnerabilities);
                        }
                        break;
                    case DEPLOY_FIREWALL_RULE:
                        FirewallRule rule = (FirewallRule) action.getRemediationAction().getRemediationParameters().get(0);
                        if (rule.getTable() == FirewallRule.Table.INPUT) {
                            simulatedTopology.existingMachineByNameOrIPAddress(action.getHost().getName()).getInputFirewallRulesTable().getRuleList().add(0, rule);
                        } else if (rule.getTable() == FirewallRule.Table.OUTPUT) {
                            simulatedTopology.existingMachineByNameOrIPAddress(action.getHost().getName()).getOutputFirewallRulesTable().getRuleList().add(0, rule);
                        }
                        break;
                    case DEPLOY_SNORT_RULE:
                        for (int j = 0; j < action.getRemediationAction().getRemediationParameters().size(); j++) {
                            Rule snortRule = (Rule) action.getRemediationAction().getRemediationParameters().get(j);
                            List<Vulnerability> correctedVulnerabilities = snortRule.getCorectedVulnerabilities(db.getConn());
                            //TODO: In fact, the vulnerability is not really corrected but rather suppressed on the path...
                            simulatedTopology.existingMachineByNameOrIPAddress(action.getRemediationAction().getRelatedVertex().concernedMachine.getName()).correctVulnerabilities(correctedVulnerabilities);
                        }
                        break;
                    default:
                        break;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return simulatedTopology;
    }

    /**
     * Execute the python script that builds MulVAL inputs
     *
     * @return boolean true if the execution was right
     */
    public static boolean prepareMulVALInputs() {
        try {
            //Load python script properties

            String pythonPath = ProjectProperties.getProperty("python-path");
            String mulvalInputScriptFolder = ProjectProperties.getProperty("mulval-input-script-folder");
            String mulvalInputScriptPath = mulvalInputScriptFolder + "main.py";

            String hostInterfacePath = ProjectProperties.getProperty("host-interfaces-path");
            String vlansPath = ProjectProperties.getProperty("vlans-path");
            String routingPath = ProjectProperties.getProperty("routing-path");
            String flowMatrixPath = ProjectProperties.getProperty("flow-matrix-path");
            String vulnerabilityScanPath = ProjectProperties.getProperty("vulnerability-scan-path");
            String mulvalInputPath = ProjectProperties.getProperty("mulval-input");
            String topologyPath = ProjectProperties.getProperty("topology-path");


            File mulvalInputFile = new File(mulvalInputPath);
            if (mulvalInputFile.exists()) {
                mulvalInputFile.delete();
            }

            Logger.getAnonymousLogger().log(Level.INFO, "Genering MulVAL inputs");

            //TODO: use parameter nessus-files-path rather than vulnerability-scan-path, in order to manage when
            // mutliple nessus files are provided.
            ProcessBuilder processBuilder = new ProcessBuilder(pythonPath, mulvalInputScriptPath,
                    "--hosts-interfaces-file", hostInterfacePath,
                    "--vlans-file", vlansPath,
                    "--flow-matrix-file", flowMatrixPath,
                    "--vulnerability-scan", vulnerabilityScanPath,
                    "--routing-file", routingPath,
                    "--mulval-output-file", mulvalInputFile.getAbsolutePath(),
                    "--to-fiware-xml-topology", topologyPath
            );
            processBuilder.directory(new File(mulvalInputScriptFolder));
            StringBuilder command = new StringBuilder();
            for (String str : processBuilder.command())
                command.append(str + " ");
            Logger.getAnonymousLogger().log(Level.INFO, "Launch generation of MulVAL inputs with command : \n" + command.toString());
            processBuilder.redirectOutput(new File(ProjectProperties.getProperty("output-path") + "/input-generation.log"));
            processBuilder.redirectError(new File(ProjectProperties.getProperty("output-path") + "/input-generation.log"));
            Process process = processBuilder.start();
            process.waitFor();


            if (!mulvalInputFile.exists()) {
                Logger.getAnonymousLogger().log(Level.WARNING, "A problem happened in the generation of mulval inputs");
                return false;
            }

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


    /**
     * Load the json of hosts with security requirements
     *
     * @param monitoring
     * @param hostsJson
     */
    public static void loadHostsSecurityRequirementsFromJson(Monitoring monitoring, JSONObject hostsJson) throws Exception {
        JSONArray hostsJsonArray = hostsJson.getJSONArray("hosts");
        for (int i = 0; i < hostsJsonArray.length(); i++) {
            JSONObject hostJson = hostsJsonArray.getJSONObject(i);
            if (hostJson != null) {
                String hostName = hostJson.getString("name");
                InformationSystemHost host = monitoring.getInformationSystem().getHostByNameOrIPAddress(hostName);
                if (host == null)
                    throw new IllegalStateException("The host " + hostName + " can not be found ");

                host.removeAllSecurityRequirements();

                JSONArray securityRequirementsArray = hostJson.getJSONArray("security_requirements");
                for (int j = 0; j < securityRequirementsArray.length(); j++) {
                    JSONObject securityRequirementJson = securityRequirementsArray.getJSONObject(j);
                    SecurityRequirement securityRequirement = new SecurityRequirement(securityRequirementJson.getString("name"), SecurityRequirement.getMetricValueFromPlainText(securityRequirementJson.getString("metric")));
                    host.addSecurityRequirements(securityRequirement);
                }

            }
        }
    }
}
