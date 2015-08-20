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

import org.jdom2.Element;

import java.util.ArrayList;
import java.util.List;

/**
 * Class representing a deployable remediation = a list of {@link DeployableRemediationAction}
 * (remediations that can be deployed on a host) with a cost.
 *
 * @author Francois -Xavier Aguessy
 */
public class DeployableRemediation {
    /**
     * The actions of the deployable remediation
     */
    private List<DeployableRemediationAction> actions = new ArrayList<DeployableRemediationAction>();

    /**
     * The cost of the deployable remediation
     */
    private double cost = 0;

    /**
     * Compute the cost of the deployable list of remediations
     *
     * @return the cost of this deployable remediation
     * @throws Exception the exception
     */
    public double computeCost() throws Exception {
        if (getCost() == 0) {
            for (int i = 0; i < getActions().size(); i++) {
                setCost(getCost() + getActions().get(i).getRemediationAction().getOperationalCost());
            }
        }
        return getCost();
    }

    /**
     * To XML element.
     *
     * @return the dom element corresponding to this deployable remediation
     */
    public Element toXMLElement() {
        Element root = new Element("remediation");

        Element costElement = new Element("cost");
        costElement.setText(this.getCost() + "");
        root.addContent(costElement);

        //actions
        Element actionsElement = new Element("remediation_actions");
        root.addContent(actionsElement);
        for (int i = 0; i < getActions().size(); i++) {
            DeployableRemediationAction action = getActions().get(i);

            actionsElement.addContent(action.toXMLElement());
        }

        return root;
    }

    /**
     * The list of deployable actions (one action on one machine)
     *
     * @return the actions
     */
    public List<DeployableRemediationAction> getActions() {
        return actions;
    }

    /**
     * Sets actions.
     *
     * @param actions the actions
     */
    public void setActions(List<DeployableRemediationAction> actions) {
        this.actions = actions;
    }

    /**
     * The cost of deploying all these actions
     *
     * @return the cost
     */
    public double getCost() {
        return cost;
    }

    /**
     * Sets cost.
     *
     * @param cost the cost
     */
    public void setCost(double cost) {
        this.cost = cost;
    }

    /**
     * Validate that this remediation has been applied to be taken into account
     * in the remediation automation.
     */
    public void validate() {
        //TODO; "validate" this remediation
    }
}


