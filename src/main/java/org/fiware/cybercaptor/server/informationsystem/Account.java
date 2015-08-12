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

/**
 * Class that represents a user account
 *
 * @author Francois-Xavier Aguessy
 */
public class Account implements Cloneable {
    /**
     * The machine on which is the account
     */
    private Host machine;

    /**
     * The user name
     */
    private String name;

    /**
     * Create an account from a account name
     *
     * @param name the name of the account
     */
    public Account(String name) {
        this.setName(name);
    }

    /**
     * Get the machine on which is the account
     */
    public Host getMachine() {
        return machine;
    }

    /**
     * Set the machine of the account
     *
     * @param machine the machine to set to this account
     */
    public void setMachine(Host machine) {
        this.machine = machine;
    }

    /**
     * Get the username
     */
    public String getName() {
        return name;
    }

    /**
     * Set the user name
     *
     * @param name the user name
     */
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getMachine() == null) ? 0 : getMachine().hashCode());
        result = prime * result + ((getName() == null) ? 0 : getName().hashCode());
        return result;
    }

    @Override
    public Account clone() throws CloneNotSupportedException {
        Account copie = (Account) super.clone();
        return copie;
    }
}
