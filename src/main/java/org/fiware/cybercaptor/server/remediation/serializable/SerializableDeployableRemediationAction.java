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

import org.fiware.cybercaptor.server.remediation.DeployableRemediationAction;
import org.fiware.cybercaptor.server.remediation.Patch;
import org.fiware.cybercaptor.server.remediation.Rule;

import java.io.Serializable;

/**
 * Class to store a serializable deployable remediation that is used for remediation automation
 * Used to memorize remediations that have been applied by operators.
 * This allows to serialize the deployable remediation, to store it, and to test if
 * another remediation is similar to this one.
 *
 * @author Francois -Xavier Aguessy
 */
public class SerializableDeployableRemediationAction implements Serializable {
    /**
     * The remediation action type
     */
    private final String remediationActionType;
    /**
     * The remediation action
     */
    private final String remediationAction;

    /**
     * The host on which the remediation is deployed.
     */
    private final String host;


    /**
     * Create a serializable deployable remediation (action + host)
     *
     * @param deployableRemediationAction the deployable remediation (action + host)
     */
    public SerializableDeployableRemediationAction(DeployableRemediationAction deployableRemediationAction) {
        remediationActionType = deployableRemediationAction.getRemediationAction().getActionType().toString();
        StringBuilder patchStringBuilder = new StringBuilder();
        switch (deployableRemediationAction.getRemediationAction().getActionType()) {
            case APPLY_PATCH:
                for (Object patchObject : deployableRemediationAction.getRemediationAction().getRemediationParameters()) {
                    Patch patch = (Patch) patchObject;
                    patchStringBuilder.append(patch.getLink());
                    if (deployableRemediationAction.getRemediationAction().getRemediationParameters().iterator().hasNext()) {
                        patchStringBuilder.append("|");
                    }
                }
                remediationAction = patchStringBuilder.toString();
                break;
            case DEPLOY_FIREWALL_RULE:
                remediationAction = deployableRemediationAction.getRemediationAction().getRemediationParameters().get(0).toString();
                break;
            case DEPLOY_SNORT_RULE:
                patchStringBuilder = new StringBuilder();
                for (Object ruleObject : deployableRemediationAction.getRemediationAction().getRemediationParameters()) {
                    Rule rule = (Rule) ruleObject;
                    patchStringBuilder.append(rule.getRule());
                    if (deployableRemediationAction.getRemediationAction().getRemediationParameters().iterator().hasNext()) {
                        patchStringBuilder.append("|");
                    }
                }
                remediationAction = patchStringBuilder.toString();
                break;
            default:
                remediationAction = "unset";
                break;
        }
        if (deployableRemediationAction.getHost() != null && deployableRemediationAction.getHost().getName() != null) {
            this.host = deployableRemediationAction.getHost().getName();
        } else {
            this.host = "";
        }
    }

    /**
     * Gets remediation action type.
     *
     * @return the remediation action type
     */
    public String getRemediationActionType() {
        return remediationActionType;
    }

    /**
     * Gets remediation action.
     *
     * @return the remediation action
     */
    public String getRemediationAction() {
        return remediationAction;
    }

    /**
     * Gets host.
     *
     * @return the host
     */
    public String getHost() {
        return host;
    }

    /**
     * Test if a serializable remediation action is equals to a serializable deployable remediation
     *
     * @param deployableRemediationAction a deployable remediation action
     * @return true if the remediations are equals
     */
    public boolean equals(DeployableRemediationAction deployableRemediationAction) {
        SerializableDeployableRemediationAction serializableDeployableRemediation = new SerializableDeployableRemediationAction(deployableRemediationAction);
        boolean result = true;

        result &= serializableDeployableRemediation.getRemediationActionType().equals(this.getRemediationActionType());
        result &= serializableDeployableRemediation.getRemediationAction().equals(this.getRemediationAction());
        result &= serializableDeployableRemediation.getHost().equals(this.getHost());

        return result;
    }
}
