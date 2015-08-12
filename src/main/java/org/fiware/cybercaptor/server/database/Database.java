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
package org.fiware.cybercaptor.server.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;


/**
 * Class to manage the Database used to store remediations and vulnerabilities.
 * It currently uses a sqlite database, but it's easy to change if still using java jdbc.
 *
 * @author Francois-Xavier Aguessy
 */
public class Database {
    /**
     * Time out to load the database
     */
    private final int timeout = 30;
    /**
     * The jdbc connection
     */
    private Connection conn;

    /**
     * Constructor of Database class
     *
     * @param path the path of the sqlite database
     * @throws Exception if problem to create the database
     */
    public Database(String path) throws Exception {
        super();
        loadFromFile(path);
    }

    /**
     * Load the sqlite database from a file
     *
     * @param path the path of the sqlite file to load
     * @throws Exception
     */
    public void loadFromFile(String path) throws Exception {

        // register the driver
        String sDriverName = "org.sqlite.JDBC";
        Class.forName(sDriverName);

        // now we set up a set of fairly basic string variables to use in the body of the code proper
        String sJdbc = "jdbc:sqlite";
        String sDbUrl = sJdbc + ":" + path;

        // create a database connection
        this.conn = DriverManager.getConnection(sDbUrl);

    }

    /**
     * Close the connection to the database
     */
    public void finalize() {
        try {
            getConn().close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * SQL instructions to create the tables of the database
     *
     * @throws Exception
     */
    public void createDB() throws Exception {
        executeQuery("CREATE TABLE IF NOT EXISTS vulnerability (id INTEGER PRIMARY KEY AUTOINCREMENT, cve TEXT UNIQUE, description TEXT, cvss_id INTEGER)");
        executeQuery("CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT,description TEXT, sid INTEGER, gid INTEGER);");
        executeQuery("CREATE TABLE IF NOT EXISTS rules_vulnerability (id_rule INTEGER, id_vulnerability INTEGER);");
        executeQuery("CREATE UNIQUE INDEX IF NOT EXISTS index_rules_vulnerability ON rules_vulnerability (id_rule ASC, id_vulnerability ASC);");
        executeQuery("CREATE TABLE IF NOT EXISTS patchs (id INTEGER PRIMARY KEY AUTOINCREMENT, link TEXT, description TEXT);");
        executeQuery("CREATE TABLE IF NOT EXISTS patchs_vulnerability (id_patch INTEGER, id_vulnerability INTEGER);");
        executeQuery("CREATE UNIQUE INDEX IF NOT EXISTS index_patchs_vulnerability ON patchs_vulnerability (id_patch ASC, id_vulnerability ASC);");
        executeQuery("CREATE TABLE IF NOT EXISTS cre (id INTEGER PRIMARY KEY AUTOINCREMENT, cre_id TEXT, id_vulnerability INTEGER, id_remediation_type INTEGER , id_remediation INTEGER);");
        executeQuery("CREATE UNIQUE INDEX IF NOT EXISTS index_cre ON cre (id_remediation ASC, id_vulnerability ASC, id_remediation_type ASC);");
        executeQuery("CREATE TABLE IF NOT EXISTS cvss (id INTEGER PRIMARY KEY AUTOINCREMENT, score REAL, access_vector TEXT, access_complexity TEXT , authentication TEXT, confidentiality_impact TEXT, integrity_impact TEXT, availability_impact TEXT);");
        executeQuery("CREATE UNIQUE INDEX IF NOT EXISTS index_cvss ON cvss (id ASC);");
        executeQuery("CREATE TABLE IF NOT EXISTS cpe (id INTEGER PRIMARY KEY AUTOINCREMENT, cpe_id TEXT);");
        executeQuery("CREATE TABLE IF NOT EXISTS cpe_vulnerability (id_cpe INTEGER, id_vulnerability INTEGER);");
        executeQuery("CREATE UNIQUE INDEX IF NOT EXISTS index_cpe_vulnerability ON cpe_vulnerability (id_cpe ASC, id_vulnerability ASC);");

    }

    /**
     * function to execute a simple query
     *
     * @param query the query to execute
     * @throws java.sql.SQLException
     */
    public void executeQuery(String query) throws SQLException {
        Statement stmt = getConn().createStatement();
        stmt.setQueryTimeout(timeout);
        stmt.executeUpdate(query);
        stmt.close();
    }

    /**
     * @return the connection element
     */
    public Connection getConn() {
        return conn;
    }
}
