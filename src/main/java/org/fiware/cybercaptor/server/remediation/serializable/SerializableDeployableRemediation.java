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

package org.fiware.cybercaptor.server.remediation.serializable;

import org.fiware.cybercaptor.server.remediation.DeployableRemediation;
import org.fiware.cybercaptor.server.remediation.DeployableRemediationAction;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to store a serializable topological deployable remediation (container of list of remediation actions).
 *
 * @author Francois-Xavier Aguessy
 */
public class SerializableDeployableRemediation implements Serializable {
    /**
     * The actions of the deployable remediation
     */
    private List<SerializableDeployableRemediationAction> actions = new ArrayList<SerializableDeployableRemediationAction>();

    public SerializableDeployableRemediation(DeployableRemediation deployableRemediation) {
        for (DeployableRemediationAction action : deployableRemediation.getActions()) {
            this.actions.add(new SerializableDeployableRemediationAction(action));
        }
    }

    /**
     * Get the actions
     *
     * @return the actions
     */
    public List<SerializableDeployableRemediationAction> getActions() {
        return actions;
    }

    /**
     * Test if a deployable remediation is similar to a serializable one
     * @param deployableRemediation the remediation to test
     * @return true if they are similar
     */
    public boolean isSimilarTo(DeployableRemediation deployableRemediation) {
        boolean result = true;
        for(DeployableRemediationAction deployableRemediationAction : deployableRemediation.getActions()) {
            boolean resultForAction = false;
            for(SerializableDeployableRemediationAction serializableDeployableRemediation : this.getActions()) {
                resultForAction |= serializableDeployableRemediation.equals(deployableRemediationAction);
            }
            result &= resultForAction;
        }

        return result;
    }
}
