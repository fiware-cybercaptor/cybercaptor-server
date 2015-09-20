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

import org.fiware.cybercaptor.server.dra.Alert;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.remediation.dynamic.DynamicRemediation;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.Namespace;
import org.jdom2.input.SAXBuilder;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * API Class used to manage IDMEF alerts
 *
 * @author Francois-Xavier Aguessy
 */
public class IDMEFManagement {
    /**
     * Load the IDMEF from an XML file (containing the alerts in IDMEF format)
     * cf https://www.ietf.org/rfc/rfc4765.txt.
     * Serialize this list of alerts in a file, in order to send them to the client when it
     * makes the proper request.
     *
     * @param idmefXMLString the XML string of the alerts
     * @throws JDOMException
     * @throws IOException
     */
    public static void loadIDMEFAlertsFromXML(String idmefXMLString) throws JDOMException, IOException, ClassNotFoundException {
        String alertsTemporaryPath = ProjectProperties.getProperty("alerts-temporary-path");
        if (alertsTemporaryPath == null || alertsTemporaryPath.isEmpty()) {
            alertsTemporaryPath = ProjectProperties.getProperty("output-path") + "/alerts.bin";
        }
        if (alertsTemporaryPath == null || alertsTemporaryPath.isEmpty()) {
            throw new IllegalStateException("The path where the alerts should be saved is invalid.");
        }

        //Load the alerts history
        File alertsFile = new File(alertsTemporaryPath);
        List<Alert> alerts;
        if (alertsFile.exists()) {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(alertsTemporaryPath));
            try {
                alerts = (List<Alert>) ois.readObject();
            } catch (InvalidClassException exception) {
                // The sources have been changed since the alerts where saved, reinitialize the database
                alerts = new ArrayList<Alert>();
            }
        } else {
            alerts = new ArrayList<Alert>();
        }


        //Load the alerts from the XML
        SAXBuilder sxb = new SAXBuilder();
        Document document = sxb.build(new StringReader(idmefXMLString));
        Namespace idmefNamespace = Namespace.getNamespace("http://iana.org/idmef");
        Element root = document.getRootElement();
        for (Element alertElement : root.getChildren("Alert", idmefNamespace)) {
            Alert alert = new Alert(alertElement);
            alerts.add(alert);
        }

        //Save to the alerts in temporary file
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(alertsFile));
        oos.writeObject(alerts);
        Logger.getAnonymousLogger().log(Level.INFO, alerts.size() + " alerts are now stored in temporary file.");
    }

    /**
     * Get the JSON object of the alerts stored on the disk that have not been already sent
     *
     * @param informationSystem the information system
     * @return the JSON object of the alerts
     */
    public static JSONObject getAlerts(InformationSystem informationSystem) throws IOException, ClassNotFoundException {
        String alertsTemporaryPath = ProjectProperties.getProperty("alerts-temporary-path");
        if (alertsTemporaryPath == null || alertsTemporaryPath.isEmpty()) {
            alertsTemporaryPath = ProjectProperties.getProperty("output-path") + "/alerts.bin";
        }
        if (alertsTemporaryPath == null || alertsTemporaryPath.isEmpty()) {
            throw new IllegalStateException("The path where the alerts should be saved is invalid.");
        }

        //Load the alerts history
        File alertsFile = new File(alertsTemporaryPath);
        List<Alert> alerts;
        if (alertsFile.exists()) {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(alertsTemporaryPath));
            alerts = (List<Alert>) ois.readObject();
        } else {
            alerts = new ArrayList<Alert>();
        }
        Logger.getAnonymousLogger().log(Level.INFO, alerts.size() + " alerts loaded.");

        //Build the json list of alerts
        JSONObject json = new JSONObject();
        JSONArray alerts_array = new JSONArray();

        for (Alert alert : alerts) {
            if (!alert.isSent()) {
                JSONObject alert_object = new JSONObject();
                alert_object.put("name", alert.getName());
                alert_object.put("timestamp", alert.getTimestamp().getTime());
                alert_object.put("date", alert.getTimestamp().toString());

                //sources
                JSONArray sources_array = new JSONArray();
                for (String source : alert.getSources()) {
                    sources_array.put(source);
                }
                alert_object.put("sources", sources_array);

                //targets
                JSONArray targets_array = new JSONArray();
                for (String target : alert.getTargets()) {
                    targets_array.put(target);
                }
                alert_object.put("targets", targets_array);

                //CVE
                JSONArray CVE_array = new JSONArray();
                for (String cve : alert.getCveLinks().keySet()) {
                    JSONObject cveElement = new JSONObject();
                    cveElement.put("CVE", cve);
                    cveElement.put("link", alert.getCveLinks().get(cve));
                    CVE_array.put(cveElement);
                }
                alert_object.put("CVEs", CVE_array);

                //Remediations
                JSONArray remediations_array = new JSONArray();
                try {
                    for (List<DynamicRemediation> dynamicRemediationActions : alert.computeRemediations(informationSystem)) {
                        JSONArray remediations_actions_array = new JSONArray();
                        for (DynamicRemediation dynamicRemediation : dynamicRemediationActions) {
                            JSONObject dynamicRemediationActionObject = dynamicRemediation.toJsonObject();
                            remediations_actions_array.put(dynamicRemediationActionObject);
                        }
                        remediations_array.put(remediations_actions_array);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                alert_object.put("dynamic_remediations", remediations_array);

                alerts_array.put(alert_object);
            }
            alert.setSent(true);
        }

        //Save to the modified alerts in the temporary file
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(alertsFile));
        oos.writeObject(alerts);
        Logger.getAnonymousLogger().log(Level.INFO, alerts.size() + " alerts are now stored in temporary file.");

        json.put("alerts", alerts_array);

        return json;
    }
}
