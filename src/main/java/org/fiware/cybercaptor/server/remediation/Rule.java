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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


/**
 * Class to manage a Snort rule
 *
 * @author Francois -Xavier Aguessy
 */
public class Rule extends Remediation {

    /**
     * The name of the table in the database
     */
    public static String databaseTableName = "rules";

    /**
     * The Snort id of the rule
     */
    private int sid = 0;

    /**
     * The gid of the rule
     */
    private int gid = 0;

    /**
     * The rule text
     */
    private String rule = "";

    /**
     * The rule description
     */
    private String description = "";

    /**
     * The list of the possible CVE that are referenced by the rule
     */
    private List<RuleReference> reference_list;

    /**
     * Find a rule in the Database from an id
     *
     * @param conn    The database connection
     * @param id_rule The id of the rule
     * @throws java.sql.SQLException the sQL exception
     */
    public Rule(Connection conn, int id_rule) throws SQLException {
        loadFromDatabase(conn, id_rule);
    }

    /**
     * Create a rule from the rule and a list of snort options
     *
     * @param ruleString The text of the rule
     * @param options    the options contained in the rule parsed in an 2D array
     */
    public Rule(String ruleString, HashMap<String, List<String>> options) {
        setRule(ruleString);
        setReference_list(new ArrayList<RuleReference>());

        //First we get sid and gid
        if (options.containsKey("sid")) {
            setSid(Integer.parseInt(options.get("sid").get(0)));
            setGid(1); //Default GID
        }
        if (options.containsKey("gid")) {
            setSid(Integer.parseInt(options.get("gid").get(0)));
        }

        if (options.containsKey("reference")) {
            for (int i = 0; i < options.get("reference").size(); i++) {
                getReference_list().add(new RuleReference(options.get("reference").get(i)));
            }
        }
    }


    /**
     * Save the rule and its reference in the database
     *
     * @param conn The database connection
     * @throws Exception the exception
     */
    public void saveToDatabase(Connection conn) throws Exception { //Add the rule to the database

        if (!inDatabase(conn)) { //This rule is not yet in the DB, so we had it
            PreparedStatement pstmt2 = conn.prepareStatement("INSERT INTO rules(rule,sid,gid) VALUES(?,?,?)");
            pstmt2.setString(1, getRule());
            pstmt2.setInt(2, getSid());
            pstmt2.setInt(3, getGid());
            pstmt2.execute();
            ResultSet resultSetId = pstmt2.getGeneratedKeys();
            setId(resultSetId.getInt(1));
            resultSetId.close();
        }

        updateDatabase(conn);

    }

    /**
     * Update database.
     *
     * @param conn the conn
     * @throws Exception the exception
     */
    public void updateDatabase(Connection conn) throws Exception {
        if (inDatabase(conn)) {
            //We add the description if it is not empty
            if (!getDescription().isEmpty()) {
                PreparedStatement pstmt2 = conn.prepareStatement("UPDATE rules SET description = ? WHERE id = ?");
                pstmt2.setString(1, getDescription());
                pstmt2.setInt(2, getId());
                pstmt2.execute();
            }


            //Add all references to the db and when a reference is added, we bind it to the rule in the db
            for (int i = 0; i < getReference_list().size(); i++) {
                RuleReference ref = getReference_list().get(i);
                ref.saveToDatabase(conn);
                if (ref.getId() != 0 && getId() != 0) { //If the reference and the rule are in the db
                    PreparedStatement pstmt = conn.prepareStatement("REPLACE INTO rules_vulnerability(id_rule,id_vulnerability) VALUES (?,?) ");
                    pstmt.setInt(1, getId());
                    pstmt.setInt(2, ref.getId());
                    pstmt.execute();
                }

            }
        }
    }

    /**
     * Find whether or not the rule is in the database and update the object in database
     *
     * @param conn the database connection
     * @return true if the rule is in the database, else false
     * @throws java.sql.SQLException the exception
     */
    public boolean inDatabase(Connection conn) throws Exception {
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM rules WHERE rule LIKE ?");
        pstmt.setString(1, getRule());
        pstmt.execute();
        boolean result = false;
        ResultSet res = pstmt.getResultSet();
        if (res.next()) { //This rule is already in the DB
            setId(res.getInt(1));
            int old_sid = res.getInt(3);
            int old_gid = res.getInt(4);
            res.close();
            //We update the sid and gid if they were 0
            if ((old_sid == 0 && getSid() != 0) || (old_gid == 0 && getGid() != 0)) {
                PreparedStatement pstmt2 = conn.prepareStatement("UPDATE rules SET sid = ? , gid = ? WHERE id = ?");
                pstmt2.setInt(1, getSid());
                pstmt2.setInt(2, getGid());
                pstmt2.setInt(3, getId());
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
     * Load a rule from the database with an id
     *
     * @param conn    The Database connection
     * @param id_rule The id of the rule
     * @return true if the rule was in the database, else false
     * @throws java.sql.SQLException
     */
    public boolean loadFromDatabase(Connection conn, int id_rule) throws SQLException {
        if (id_rule <= 0) {
            return false;
        }
        PreparedStatement pstmt = conn.prepareStatement("SELECT id, rule, description, sid, gid FROM rules WHERE id = ?");
        pstmt.setInt(1, id_rule);
        pstmt.execute();
        ResultSet res = pstmt.getResultSet();
        if (res.next()) {
            setId(res.getInt(1));
            setRule(res.getString(2));
            setDescription(res.getString(3));
            setSid(res.getInt(4));
            setGid(res.getInt(5));
            res.close();
            return true;

        } else {
            return false;
        }
    }

    @Override
    public String toString() {
        return "Rule [sid=" + getSid() + ", gid=" + getGid() + ", description=" + getDescription() + ", rule=" + getRule() + "]";
    }

    /**
     * Import the informations from a documentation file and add it to the object
     *
     * @param pathToDocumentationFolder The path where the documentations files are stored
     * @throws Exception the exception
     */
    public void getInformationsFromDocumentationFiles(String pathToDocumentationFolder) throws Exception {
        if (getSid() == 0 || getGid() == 0) //If the rule has no sid or no gid
            return;

        String filePath;
        if (getGid() == 1)
            filePath = pathToDocumentationFolder + "/" + getSid() + ".txt";
        else
            filePath = pathToDocumentationFolder + "/" + getGid() + "-" + getSid() + ".txt";
        File documentationFile = new File(filePath);

        if (!documentationFile.exists())//If the documentation files doesn't exist, we can't do anything
            return;
        //The file exist
        BufferedReader buff = new BufferedReader(new FileReader(filePath));

        String line;
        while ((line = buff.readLine()) != null) {
            if (line.trim().equals("Detailed Information:")) {
                String file_description = "";
                while ((line = buff.readLine()) != null && !line.trim().equals("--")) { //While we are not a the end of the file, and the line is not empty
                    if (!line.trim().isEmpty())
                        file_description += line + " ";
                }
                this.setDescription(file_description);
            }
        }
        buff.close();
    }

    /**
     * Get all vulnerabilities corrected by the rule from the Database
     *
     * @param conn The database Connection
     * @return a list of vulnerabilities corrected by the rule
     * @throws java.sql.SQLException the exception
     */
    public List<Vulnerability> getCorectedVulnerabilities(Connection conn) throws Exception {
        List<Vulnerability> result = new ArrayList<Vulnerability>();
        if (this.inDatabase(conn)) {
            PreparedStatement pstmt = conn.prepareStatement("SELECT id_vulnerability FROM rules_vulnerability WHERE id_rule = ?");
            pstmt.setInt(1, getId());
            pstmt.execute();
            ResultSet res = pstmt.getResultSet();
            while (res.next()) { //Get all the rules that are related to this vulnerability
                Vulnerability vuln = new Vulnerability(conn, res.getInt(1));
                result.add(vuln);
            }
        }
        return result;
    }

    /**
     * Gets sid.
     *
     * @return the sid
     */
    public int getSid() {
        return sid;
    }

    /**
     * Sets sid.
     *
     * @param sid the sid
     */
    public void setSid(int sid) {
        this.sid = sid;
    }

    /**
     * Gets gid.
     *
     * @return the gid
     */
    public int getGid() {
        return gid;
    }

    /**
     * Sets gid.
     *
     * @param gid the gid
     */
    public void setGid(int gid) {
        this.gid = gid;
    }

    /**
     * Gets rule.
     *
     * @return the rule
     */
    public String getRule() {
        return rule;
    }

    /**
     * Sets rule.
     *
     * @param rule the rule
     */
    public void setRule(String rule) {
        this.rule = rule;
    }

    /**
     * Gets description.
     *
     * @return the description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets description.
     *
     * @param description the description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Gets reference _ list.
     *
     * @return the reference _ list
     */
    public List<RuleReference> getReference_list() {
        return reference_list;
    }

    /**
     * Sets reference _ list.
     *
     * @param reference_list the reference _ list
     */
    public void setReference_list(List<RuleReference> reference_list) {
        this.reference_list = reference_list;
    }
}
