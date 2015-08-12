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
import java.util.ArrayList;
import java.util.List;

/**
 * Class representing a patch
 *
 * @author Francois-Xavier Aguessy
 */
public class Patch extends Remediation {

    /**
     * The name of the table in the database
     */
    public static String databaseTableName = "patchs";

    /**
     * The patch link
     */
    private String link = "";

    /**
     * The patch description
     */
    private String description = "";

    /**
     * The patch name
     */
    private String name = "";

    /**
     * Find a patch in the Database from an id
     *
     * @param conn     The database connection
     * @param id_patch The id of the patch
     * @throws java.sql.SQLException
     */
    public Patch(Connection conn, int id_patch) throws SQLException {
        loadFromDatabase(conn, id_patch);
    }

    /**
     * Create a patch with its link and its description
     *
     * @param link        Link to the patch
     * @param description Description of the patch
     */
    public Patch(String link, String description) {
        this.link = link;
        this.setDescription(description);
    }

    /**
     * Create a patch with its name
     */
    public Patch(String name) {
        this.name = name;
    }

    /**
     * @return the link
     */
    public String getLink() {
        return link;
    }

    /**
     * @param link the link to set
     */
    public void setLink(String link) {
        this.link = link;
    }

    /**
     * @return the description
     */
    public String getDescription() {
        return description;
    }

    /**
     * @param description the description to set
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Load a patch from the database with an id
     *
     * @param conn     The Database connection
     * @param id_patch The id of the patch
     * @return true if the patch was in the database, else false
     * @throws java.sql.SQLException
     */
    public boolean loadFromDatabase(Connection conn, int id_patch) throws SQLException {
        if (id_patch <= 0) {
            return false;
        }
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM patchs WHERE id = ?");
        pstmt.setInt(1, id_patch);
        pstmt.execute();
        ResultSet res = pstmt.getResultSet();
        if (res.next()) {
            setId(res.getInt(1));
            link = res.getString(2);
            setDescription(res.getString(3));
            res.close();
            return true;

        } else {
            return false;
        }
    }

    /**
     * Save the patch in the database
     *
     * @param conn The database connection
     * @throws Exception
     */
    public void saveToDatabase(Connection conn) throws Exception {
        if (link.isEmpty() && getId() == 0) {
            return;
        }

        if (!inDatabase(conn)) { //This patch is not yet in the DB, so we had it
            PreparedStatement pstmt = conn.prepareStatement("INSERT INTO patchs(link,description) VALUES(?,?)");
            pstmt.setString(1, link);
            pstmt.setString(2, getDescription());
            pstmt.execute();
            ResultSet resultSetId = pstmt.getGeneratedKeys();
            setId(resultSetId.getInt(1));
            resultSetId.close();
        }
    }

    /**
     * Find whether or not the patch is in the database and update the object in database
     *
     * @param conn the database connection
     * @return true if the patch is in the database, else false
     * @throws java.sql.SQLException
     */
    public boolean inDatabase(Connection conn) throws SQLException {
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM patchs WHERE link LIKE ? OR id LIKE ?");
        pstmt.setString(1, link);
        pstmt.setInt(2, getId());
        pstmt.execute();
        ResultSet res = pstmt.getResultSet();
        boolean result = false;
        if (res.next()) { //This patch is already in the DB
            setId(res.getInt(1));
            String old_description = res.getString(3);
            res.close();
            //We update the description if it was empty
            if (getDescription() != null && !getDescription().equals(old_description) && !getDescription().isEmpty()) {
                PreparedStatement pstmt2 = conn.prepareStatement("UPDATE patchs SET description = ? WHERE id = ?");
                pstmt2.setString(1, getDescription());
                pstmt2.setInt(2, getId());
                pstmt2.execute();
                pstmt2.close();
            }
            result = true;
        }
        pstmt.close();
        res.close();
        return result;
    }

    /**
     * Get all vulnerabilities corrected by the patch from the Database
     *
     * @param conn The database Connection
     * @return a list of vulnerabilities corrected by the patch
     * @throws java.sql.SQLException
     */
    public List<Vulnerability> getCorectedVulnerabilities(Connection conn) throws Exception {
        List<Vulnerability> result = new ArrayList<Vulnerability>();
        if (this.inDatabase(conn)) {
            PreparedStatement pstmt = conn.prepareStatement("SELECT id_vulnerability FROM patchs_vulnerability WHERE id_patch = ?");
            pstmt.setInt(1, getId());
            pstmt.execute();
            ResultSet res = pstmt.getResultSet();
            while (res.next()) { //Get all the rules that are related to this vulnerability
                Vulnerability vuln = new Vulnerability(conn, res.getInt(1));
                result.add(vuln);
            }
            pstmt.close();
            res.close();
        }
        return result;
    }

}
