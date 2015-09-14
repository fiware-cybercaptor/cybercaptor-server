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

package org.fiware.cybercaptor.server.dra;

import org.apache.commons.net.ntp.TimeStamp;
import org.jdom2.Element;
import org.jdom2.Namespace;

import java.io.Serializable;
import java.util.*;

/**
 * Class that represents an Alert (can be loaded from an idmef:Alert DOM object).
 * cf. https://www.ietf.org/rfc/rfc4765.txt
 *
 * @author Francois-Xavier Aguessy
 */
public class Alert implements Serializable {

    /**
     * The list of sources for this alert
     */
    private final List<String> sources = new ArrayList<String>();
    /**
     * The list of destinations for this alert
     */
    private final List<String> destinations = new ArrayList<String>();
    /**
     * The CVEs and their links, related to this alert
     */
    private final Map<String, String> cveLinks = new HashMap<String, String>();
    /**
     * The timestamp of this alert
     */
    private Date timestamp;
    /**
     * Whether or not this alert has been sent to the visualization interface
     */
    private boolean sent = false;
    /**
     * Alert Name (=classification text IDMEF)
     */
    private String name;

    /**
     * Load an alert from a idmef:Alert element
     *
     * @param alertElement the DOM element idmef:Alert
     */
    public Alert(Element alertElement) {
        Namespace idmefNamespace = Namespace.getNamespace("http://iana.org/idmef");
        if (alertElement == null || !alertElement.getName().equals("Alert")) {
            throw new IllegalStateException("The IDMEF alert to parse is not valid");
        }

        Element createTimeElement = alertElement.getChild("CreateTime", idmefNamespace);
        if (createTimeElement != null) {
            timestamp = new TimeStamp(createTimeElement.getAttributeValue("ntpstamp").replaceAll("0x", "")).getDate();
        }
        Element detectTimeElement = alertElement.getChild("DetectTime", idmefNamespace);
        if (detectTimeElement != null) {
            timestamp = new TimeStamp(detectTimeElement.getAttributeValue("ntpstamp").replaceAll("0x", "")).getDate();
        }
        if (timestamp == null)
            throw new IllegalStateException("invalid timestamp for the IDMEF alert");

        //sources
        for (Element sourceElement : alertElement.getChildren("Source", idmefNamespace)) {
            Element sourceNode = sourceElement.getChild("Node", idmefNamespace);
            if (sourceNode != null) {
                Element sourceAddress = sourceNode.getChild("Address", idmefNamespace);
                //If there is an address
                if (sourceAddress != null) {
                    Element sourceIP = sourceAddress.getChild("address", idmefNamespace);
                    Element sourceMask = sourceAddress.getChild("netmask", idmefNamespace);
                    if (sourceIP != null && sourceMask != null) {
                        this.sources.add(sourceIP.getText() + "/" + sourceMask);
                    } else if (sourceIP != null) {
                        this.sources.add(sourceIP.getText());
                    }
                } else { // There is no address, their must be a "name"
                    Element sourceName = sourceNode.getChild("name", idmefNamespace);
                    if (sourceName != null) {
                        this.sources.add(sourceName.getText());
                    }
                }
            }
        }

        //targets
        for (Element targetElement : alertElement.getChildren("Target", idmefNamespace)) {
            Element targetNode = targetElement.getChild("Node", idmefNamespace);
            if (targetNode != null) {
                Element targetAddress = targetNode.getChild("Address", idmefNamespace);
                //If there is an address
                if (targetAddress != null) {
                    Element targetIP = targetAddress.getChild("address", idmefNamespace);
                    Element targetMask = targetAddress.getChild("netmask", idmefNamespace);
                    if (targetIP != null && targetMask != null) {
                        this.sources.add(targetIP.getText() + "/" + targetMask);
                    } else if (targetIP != null) {
                        this.sources.add(targetIP.getText());
                    }
                } else { // There is no address, their must be a "name"
                    Element targetName = targetNode.getChild("name", idmefNamespace);
                    if (targetName != null) {
                        this.sources.add(targetName.getText());
                    }
                }
            }
        }

        //add classification information
        Element classificationElement = alertElement.getChild("Classification", idmefNamespace);
        if (classificationElement != null) {
            this.name = classificationElement.getAttributeValue("text");
            for (Element referenceElement : classificationElement.getChildren("Reference", idmefNamespace)) {
                switch (referenceElement.getAttributeValue("origin")) {
                    case "cve":
                        cveLinks.put(referenceElement.getChild("name", idmefNamespace).getText(), referenceElement.getChild("url", idmefNamespace).getText());
                        break;
                }
            }
        }
    }
}
