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

import org.fiware.cybercaptor.server.vulnerability.Vulnerability;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Class to manage the references options contained in a snort rule
 *
 * @author Francois -Xavier Aguessy
 */
public class RuleReference {
    /**
     * Type of the reference
     */
    private String type = "";

    /**
     * Content of the reference
     */
    private String content = "";

    /**
     * Id in the database of this reference
     */
    private int id = 0;

    /**
     * Instantiates a new Rule reference.
     *
     * @param reference the reference string that must be parsed (example: "cve:CVE-2000-0000")
     */
    RuleReference(String reference) {
        Pattern p = Pattern.compile(",");
        String[] tableau_reference = p.split(reference.trim());
        if (tableau_reference.length == 2) {
            setType(tableau_reference[0]);
            setContent(tableau_reference[1]);

            Matcher matcherCVE = Vulnerability.PATTERN.matcher(getContent());
            if (getType().equals("cve") && !matcherCVE.matches())
                setContent("CVE-" + getContent());
        }
    }

    /**
     * Function to save into the database this reference
     *
     * @param conn The database connection
     * @throws Exception the exception
     */
    public void saveToDatabase(Connection conn) throws Exception {
        if (getType().equals("cve")) { //For the moment, we store only cve references
            Vulnerability cve = new Vulnerability(getContent());
            cve.addToDatabase(conn);
            setId(cve.id);
        }
    }

    /**
     * Function to load from the database a reference from an id
     *
     * @param conn         The database connection
     * @param id_reference the id of the reference
     * @return true if the id is in the database, else false
     * @throws java.sql.SQLException the sQL exception
     */
    public boolean loadFromDatabase(Connection conn, int id_reference) throws SQLException {
        if (id_reference <= 0) {
            return false;
        }
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM vulnerability WHERE id = ?");
        pstmt.setInt(1, id_reference);
        pstmt.execute();
        ResultSet res = pstmt.getResultSet();
        if (res.next()) {
            setId(res.getInt(1));
            setType(res.getString(2));
            setContent(res.getString(3));
            res.close();
            return true;

        } else {
            return false;
        }
    }

    /**
     * Gets type.
     *
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * Sets type.
     *
     * @param type the type
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Gets content.
     *
     * @return the content
     */
    public String getContent() {
        return content;
    }

    /**
     * Sets content.
     *
     * @param content the content
     */
    public void setContent(String content) {
        this.content = content;
    }

    /**
     * Gets id.
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
