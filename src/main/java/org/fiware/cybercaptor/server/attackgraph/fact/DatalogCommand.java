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

package org.fiware.cybercaptor.server.attackgraph.fact;

import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class representing a datalog command contained in a MulVAL attack graph vertex
 *
 * @author Francois-Xavier Aguessy
 */
public class DatalogCommand implements Cloneable {

    /**
     * The pattern of the command
     */
    public static Pattern pattern = Pattern.compile("^([a-zA-Z\\\\=]+)\\((.*)\\)$");

    /**
     * The related fact
     */
    public Fact fact = null;

    /**
     * The Datalog command
     */
    public String command;

    /**
     * The params of the command
     */
    public String[] params;

    /**
     * Create a Datalog Command from a fact string
     *
     * @param fact_string the fact string
     */
    public DatalogCommand(String fact_string, Fact fact) {
        Matcher matcherRule = pattern.matcher(fact_string);
        if (matcherRule.matches()) {
            this.command = matcherRule.group(1);
            this.params = matcherRule.group(2).split(",");//si une chaine de caractère contient des virgules entre quote, cela ne fonctionne pas
            for (int i = 0; i < this.params.length; i++) { //If the param start and ends with a quote, we delete it.
                if ((this.params[i].startsWith("'") && this.params[i].endsWith("'")) || (this.params[i].startsWith("\"") && this.params[i].endsWith("\""))) {
                    this.params[i] = this.params[i].substring(1, this.params[i].length() - 1);
                }
            }
        }
        this.fact = fact;
    }

    /**
     * Check if a fact string is a Datalog fact
     *
     * @param fact the fact string
     * @return true if the fact string is a Datalog fact else false
     */
    public static boolean isADatalogFact(String fact) {
        Matcher matcherRule = pattern.matcher(fact);
        return matcherRule.matches();
    }

    /**
     * @param informationSystem the information system
     * @return the possible paths (several if for example packets come from internet and there is several
     * router to enter in the network) between the machines of a hacl Datalog command
     * @throws Exception
     */
    public List<List<InformationSystemHost>> getRoutesBetweenHostsOfHacl(InformationSystem informationSystem) throws Exception {
        if (!this.command.equals("hacl"))
            throw new Exception("This datalog command is not a hacl");

        if (this.params[0].equals("internet") || this.params[0].equals("1.1.1.1")) {
            InformationSystemHost to = informationSystem.getHostByNameOrIPAddress(this.params[1]);
            return informationSystem.routesFromInternetTo(to);
        } else if (this.params[1].equals("internet") || this.params[1].equals("1.1.1.1")) {
            InformationSystemHost from = informationSystem.getHostByNameOrIPAddress(this.params[0]);
            List<List<InformationSystemHost>> result = new ArrayList<List<InformationSystemHost>>();
            result.add(informationSystem.routeToInternetFrom(from));
            return result;
        } else {
            InformationSystemHost from = informationSystem.getHostByNameOrIPAddress(this.params[0]);
            InformationSystemHost to = informationSystem.getHostByNameOrIPAddress(this.params[1]);
            List<List<InformationSystemHost>> result = new ArrayList<List<InformationSystemHost>>();
            result.add(informationSystem.routeBetweenHosts(from, to));
            return result;
        }
    }

    @Override
    public DatalogCommand clone() throws CloneNotSupportedException {
        DatalogCommand copie = (DatalogCommand) super.clone();
        copie.params = new String[this.params.length];
        System.arraycopy(this.params, 0, copie.params, 0, copie.params.length);
        return copie;
    }

    @Override
    public String toString() {
        return "DatalogFact [command=" + command + ", params="
                + Arrays.toString(params) + "]";
    }
}
