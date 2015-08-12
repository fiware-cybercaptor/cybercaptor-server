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
package org.fiware.cybercaptor.server.properties;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;

/**
 * Class used to manage the properties of the project (file stored in ~/.remediation/config.properties)
 * which can be modified to change the params used in the whole application
 *
 * @author Francois -Xavier Aguessy
 */
public class ProjectProperties {
    public static final String PROPERTY_FILE_NAME = System.getProperty("user.home") + "/.remediation/config.properties";

    /**
     * Load the property file from the file define in the constant {@link #PROPERTY_FILE_NAME}
     *
     * @return the {@link java.util.Properties} object
     */
    private static Properties loadPropertyFile() {
        File file = new File(PROPERTY_FILE_NAME);
        if (!file.exists()) {
            new File(file.getParent()).mkdirs();//If folder doesn't exist, create it
            System.err.println("Property file does not exists, I will create a new one in " + PROPERTY_FILE_NAME);
            Properties prop = new Properties();
            try {
                prop.store(new FileOutputStream(PROPERTY_FILE_NAME), null);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return prop;
        } else {
            Properties prop = new Properties();
            try {

                prop.load(new FileInputStream(file));
            } catch (Exception e) {
                e.printStackTrace();
            }

            return prop;
        }
    }

    /**
     * Get a property from the property file
     *
     * @param propertyName the property name
     * @return the corresponding property
     */
    public static String getProperty(String propertyName) {
        Properties prop = loadPropertyFile();
        return prop.getProperty(propertyName);

    }

    /**
     * Change a property value
     *
     * @param propertyName name of the property
     * @param value        new value
     */
    public static void setProperty(String propertyName, String value) {
        Properties prop = loadPropertyFile();
        prop.setProperty(propertyName, value);
        try {
            prop.store(new FileOutputStream(PROPERTY_FILE_NAME), null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
