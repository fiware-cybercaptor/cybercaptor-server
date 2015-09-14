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
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.Namespace;
import org.jdom2.input.SAXBuilder;

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
            alerts = (List<Alert>) ois.readObject();
        } else {
            alerts = new ArrayList<Alert>();
        }
        Logger.getAnonymousLogger().log(Level.INFO, alerts.size() + " alerts stored in temporary file.");


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
    }
}
