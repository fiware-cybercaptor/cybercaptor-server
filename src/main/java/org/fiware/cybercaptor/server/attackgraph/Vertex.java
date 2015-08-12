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
package org.fiware.cybercaptor.server.attackgraph;

import org.fiware.cybercaptor.server.attackgraph.fact.DatalogCommand;
import org.fiware.cybercaptor.server.attackgraph.fact.Fact;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.informationsystem.Service;
import org.fiware.cybercaptor.server.vulnerability.Vulnerability;

import java.util.ArrayList;
import java.util.List;

/**
 * Class to represent a vertex of an attack graph
 *
 * @author Francois-Xavier Aguessy
 */
public class Vertex implements Cloneable {
    /**
     * Identifier of the Vertex
     */
    public int id = 0;
    /**
     * The fact of the vertex
     */
    public Fact fact = null;
    /**
     * A metric
     */
    public float mulvalMetric = 0;
    /**
     * The vertex type
     */
    public VertexType type;
    /**
     * The vertex parents
     */
    public List<Vertex> parents = new ArrayList<Vertex>();
    /**
     * The vertex children
     */
    public List<Vertex> children = new ArrayList<Vertex>();
    /**
     * The impact metrics of this vertex
     */
    public List<ImpactMetric> impactMetrics = new ArrayList<ImpactMetric>();
    /**
     * The related vulnerability if this vertex contains a vulnerability
     */
    public Vulnerability relatedVulnerabilibty = null;
    /**
     * The machine represented by the vertex (if appropriate)
     */
    public InformationSystemHost concernedMachine = null;
    /**
     * The service represented by the vertex (if appropriate)
     */
    public Service concernedService = null;

    /**
     * Create a vertex from an id
     *
     * @param id the index of the vertex
     */
    public Vertex(int id) {
        this.id = id;
    }

    /**
     * Set the type of the vertex from a string
     *
     * @param type the type in string
     */
    public void setType(String type) {
        switch (type) {
            case "AND":
                this.type = VertexType.AND;
                break;
            case "OR":
                this.type = VertexType.OR;
                break;
            case "LEAF":
                this.type = VertexType.LEAF;
                break;
        }
    }

    /**
     * Compute the parents of the vertex
     * @param graph the complete attack graph
     */
    public void computeParentsAndChildren(AttackGraph graph) {
        this.parents = new ArrayList<Vertex>();//initialize the list of parents
        this.children = new ArrayList<Vertex>();//initialize the list of children
        for (int i = 0; i < graph.arcs.size();i++) {
            Arc arc = graph.arcs.get(i);
            if(arc.destination == this) {
                this.parents.add(arc.source);
            }
            else if(arc.source == this) {
                this.children.add(arc.destination);
            }
        }
    }

    /**
     * Get the machine which is referenced by this vertex of the attack graph
     * @param informationSystem the information system in which is the machine to find
     * @return the machine of the information system referenced by this vertex
     * @throws Exception
     */
    public InformationSystemHost getRelatedMachine(InformationSystem informationSystem) throws Exception {
        if (concernedMachine != null)
            return concernedMachine;
        InformationSystemHost result = null;
        if (this.fact != null) {
            if (this.fact.type == Fact.FactType.DATALOG_FACT && this.fact.datalogCommand != null) {
                DatalogCommand command = this.fact.datalogCommand;
                switch (command.command) {
                    case "vulExists":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "execCode":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "netAccess":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "canAccessHost":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "hacl":
                        if (command.params.length >= 2) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[1]);
                        }
                        break;
                    case "accessMaliciousInput":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "networkServiceInfo":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "principalCompromised":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByUserName(command.params[0]);
                        }
                        break;
                    case "attackerLocated":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "accessFile":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
                        }
                        break;
                    case "hasAccount":
                        if (command.params.length >= 1) {
                            result = informationSystem.existingMachineByNameOrIPAddress(command.params[1]);
                        }
                        break;
                }
            }
        }
        this.concernedMachine = result;
        return result;
    }

    @Override
    public Vertex clone() throws CloneNotSupportedException {
        Vertex copie = (Vertex) super.clone();
        copie.type = this.type;
        copie.fact = this.fact.clone();
        copie.fact.attackGraphVertex = copie;
        copie.relatedVulnerabilibty = this.relatedVulnerabilibty;
        copie.concernedMachine = this.concernedMachine;
        copie.concernedService = this.concernedService;
        copie.children = new ArrayList<Vertex>();
        copie.parents = new ArrayList<Vertex>();
        return copie;
    }

    @Override
    public String toString() {
        /*return "Vertex [fact=" + fact + ", id=" + id + ", metric=" + metric
				+ ", type=" + type + "]";*/
        return this.id + ":" + this.fact.factString;
    }

    /**
     * @param isRule         true if the looked for child is a rule, false if it is a datalog command
     * @param ruleOrFactType the content of the command or of the rule
     * @return the child if it exists, else null
     */
    public Vertex childOfType(boolean isRule, String ruleOrFactType) {
        for (Vertex child : this.children) {
            if (child != null && child.fact != null) {
                if (isRule && child.fact.type == Fact.FactType.RULE) { //A RULE
                    if (child.fact.factRule != null && child.fact.factRule.ruleText != null && child.fact.factRule.ruleText.contains(ruleOrFactType))
                        return child;
                } else if (!isRule && child.fact.type == Fact.FactType.DATALOG_FACT) { // A datalog fact
                    if (child.fact.datalogCommand != null && child.fact.datalogCommand.command != null && child.fact.datalogCommand.command.contains(ruleOrFactType))
                        return child;
                }
            }
        }

        return null;
    }

    /**
     * @param isRule         true if the looked for parent is a rule, false if it is a datalog command
     * @param ruleOrFactType the content of the command or of the rule
     * @return the parent if it exists, else null
     */
    public Vertex parentOfType(boolean isRule, String ruleOrFactType) {
        for (Vertex parent : this.parents) {
            if (parent != null && parent.fact != null) {
                if (isRule && parent.fact.type == Fact.FactType.RULE) { //A RULE
                    if (parent.fact.factRule != null && parent.fact.factRule.ruleText != null && parent.fact.factRule.ruleText.contains(ruleOrFactType))
                        return parent;
                } else if (!isRule && parent.fact.type == Fact.FactType.DATALOG_FACT) { // A datalog fact
                    if (parent.fact.datalogCommand != null && parent.fact.datalogCommand.command != null && parent.fact.datalogCommand.command.contains(ruleOrFactType))
                        return parent;
                }
            }
        }

        return null;
    }

    /**
     * Represent the possible type of vertices
     */
    public static enum VertexType {
        AND, OR, LEAF
    }
}
