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
package org.fiware.cybercaptor.server.informationsystem;


import org.fiware.cybercaptor.server.topology.asset.Host;

import java.util.ArrayList;
import java.util.List;


/**
 * Class representing a user
 *
 * @author Francois-Xavier Aguessy
 */
public class User implements Cloneable {
    /**
     * The machine used by the user
     */
    private Host machine;

    /**
     * The list of accounts of the user
     */
    private List<Account> accounts = new ArrayList<Account>();

    /**
     * The name of the user
     */
    private String name;

    /**
     * Create a user with its name
     *
     * @param name the user name
     */
    public User(String name) {
        this.setName(name);
    }

    @Override
    public User clone() throws CloneNotSupportedException {
        return (User) super.clone();
    }

    /**
     * Get the machine used by the user
     */
    public Host getMachine() {
        return machine;
    }

    /**
     * Set the machine used by the user
     *
     * @param machine the new machine
     */
    public void setMachine(Host machine) {
        this.machine = machine;
    }

    /**
     * Get the list of accounts of the user
     */
    public List<Account> getAccounts() {
        return accounts;
    }

    /**
     * Set the list of accounts of the user
     *
     * @param accounts the new accounts
     */
    public void setAccounts(List<Account> accounts) {
        this.accounts = accounts;
    }

    /**
     * Get the name of the user
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of the user
     *
     * @param name the new name
     */
    public void setName(String name) {
        this.name = name;
    }
}
