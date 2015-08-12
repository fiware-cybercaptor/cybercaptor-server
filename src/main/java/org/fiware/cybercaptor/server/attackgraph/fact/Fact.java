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
 * along with FIWARE Cyber Security Generic Enabler.                                    *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/
package org.fiware.cybercaptor.server.attackgraph.fact;

import org.fiware.cybercaptor.server.attackgraph.Vertex;


/**
 * Class to represent a datalog fact of a MulVAL attack graph
 *
 * @author Francois-Xavier Aguessy
 */
public class Fact implements Cloneable {
    /**
     * The string of the fact
     */
    public String factString = "";
    /**
     * The type of fact
     */
    public FactType type;
    /**
     * If the fact contains a rule, refer to this rule
     */
    public Rule factRule = null;
    /**
     * If the fact contains a Datalog command, refer to this Datalog command
     */
    public DatalogCommand datalogCommand = null;
    /**
     * The related attack graph vertex
     */
    public Vertex attackGraphVertex = null;

    /**
     * Create a new fact from a string
     *
     * @param fact the fact string
     */
    public Fact(String fact, Vertex vertex) {
        this.factString = fact;
        if (Rule.isARule(fact)) {
            factRule = new Rule(fact);
            type = FactType.RULE;
        } else if (DatalogCommand.isADatalogFact(fact)) {
            this.datalogCommand = new DatalogCommand(fact, this);
            type = FactType.DATALOG_FACT;
        }
        this.attackGraphVertex = vertex;
    }

    @Override
    public Fact clone() throws CloneNotSupportedException {
        Fact copie = (Fact) super.clone();
        if (copie.factRule != null)
            copie.factRule = this.factRule.clone();
        if (this.datalogCommand != null) {
            copie.datalogCommand = this.datalogCommand.clone();
            copie.datalogCommand.fact = copie;
        }

        return copie;
    }

    @Override
    public String toString() {
        return "Fact [factDatalog=" + datalogCommand + ", factRule=" + factRule
                + ", factString=" + factString + ", type=" + type + "]";
    }

    /**
     * Possible types of facts
     */
    public static enum FactType {
        RULE, DATALOG_FACT
    }

}
