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

package org.fiware.cybercaptor.server.remediation.cost;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import java.io.FileInputStream;
import java.io.FileOutputStream;


/**
 * Class representing the global parameters provided by the administrators
 * (they will be used in the calculation of the cost)
 *
 * @author Francois-Xavier Aguessy
 */

public class GlobalParameters {
    /**
     * The global parameters file name
     */
    public final static String FILE_NAME = "global-parameters.xml";
    /**
     * The expenses of the company for the IT
     */
    private double expensesForIT = 100;

    /**
     * Function used to save the parameters in an xml file
     *
     * @param path the path where the xml file should be created
     * @throws Exception
     */
    public void saveToXMLFile(String path) throws Exception {
        Document document = new Document(toDomElement());
        //Save the DOM element in file
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        output.output(document, new FileOutputStream(path));
    }

    /**
     * Get the dom element related to the global parameters
     * @return the related XML DOM element
     */
    public Element toDomElement() {
        Element root = new Element("global_parameters");

        //expensesForIT
        Element expensesForITElement = new Element("expensesForIT");
        expensesForITElement.setText(expensesForIT + "");
        root.addContent(expensesForITElement);

        return root;
    }

    /**
     * Gets expenses for IT.
     *
     * @return the expenses for IT
     */
    public double getExpensesForIT() {
        return expensesForIT;
    }

    /**
     * Sets expenses for IT.
     *
     * @param expensesForIT the expenses for IT
     */
    public void setExpensesForIT(double expensesForIT) {
        this.expensesForIT = expensesForIT;
    }

    /**
     * Function used to load the parameters from an xml file
     *
     * @param path the path where the xml file is stored
     * @throws Exception
     */
    public void loadFromXMLFile(String path) throws Exception {
        FileInputStream file = new FileInputStream(path);
        SAXBuilder sxb = new SAXBuilder();
        Document document = sxb.build(file);
        loadFromDomDocument(document);
    }

    /**
     * Load the Global parameters from a XML DOM Document
     *
     * @param document the XML DOM document
     */
    public void loadFromDomDocument(Document document) {
        Element root = document.getRootElement();

        //remediationCost
        Element expensesForITElement = root.getChild("expensesForIT");
        if (expensesForITElement != null)
            expensesForIT = Double.parseDouble(expensesForITElement.getText());
    }
}
