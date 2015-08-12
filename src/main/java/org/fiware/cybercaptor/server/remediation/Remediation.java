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
package org.fiware.cybercaptor.server.remediation;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Abstract class that represent remediations
 *
 * @author Francois -Xavier Aguessy
 */
public abstract class Remediation {
    /**
     * The name of the table in the database
     */
    public static String databaseTableName;

    /**
     * The id of the remediation in the database.
     */
    private int id;

    /**
     * Creates an empty remediation
     */
    public Remediation() {
        super();
    }

    /**
     * Find a remediation in the Database from an id
     *
     * @param conn           The database connection
     * @param id_remediation The id of the remediation
     * @throws java.sql.SQLException the sQL exception
     */
    public Remediation(Connection conn, int id_remediation) throws SQLException {
        loadFromDatabase(conn, id_remediation);
    }

    /**
     * Load the remediation from the remediation database
     *
     * @param conn the connection to the database
     * @param id   the id of the remediation
     * @return true if the loading has succeeded else false
     * @throws SQLException the sQL exception
     */
    public abstract boolean loadFromDatabase(Connection conn, int id) throws SQLException;

    @Override
    public String toString() {
        return "Remediation : " + this.getClass().getName() + " [id=" + getId() + "]";
    }


    /**
     * The id of the remediation in the database
     *
     * @return the id
     */
    public int getId() {
        return id;
    }

    /**
     * Sets id.
     *
     * @param id the id
     */
    public void setId(int id) {
        this.id = id;
    }
}
