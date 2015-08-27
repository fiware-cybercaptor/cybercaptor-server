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

import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.jdom2.Element;

/**
 * Class representing a deployable remediation action: a {@link RemediationAction}
 * that can be deployed on a specific host.
 *
 * @author Francois -Xavier Aguessy
 */
public class DeployableRemediationAction {
    /**
     * The remediation action
     */
    private RemediationAction remediationAction;

    /**
     * The host on which the remediation can be deployed.
     */
    private InformationSystemHost host;

    /**
     * The machine on which the remediation will be deployed
     */
    /**
     * Gets host.
     *
     * @return the host
     */
    public InformationSystemHost getHost() {
        return host;
    }

    /**
     * Sets host.
     *
     * @param host the host to set
     */
    public void setHost(InformationSystemHost host) {
        this.host = host;
    }

    /**
     * To xML element.
     *
     * @return the dom element corresponding to this deployable remediation action
     */
    public Element toXMLElement() {
        Element root = new Element("deployable_remediation");

        Element machineElement = new Element("machine");
        machineElement.setText(this.getHost().getName() + "");
        root.addContent(machineElement);

        //actions
        Element actionElement = new Element("action");
        root.addContent(actionElement);
        Element typeElement = new Element("type");
        actionElement.addContent(typeElement);

        switch (getRemediationAction().getActionType()) {
            case APPLY_PATCH:
                typeElement.setText("patch");
                Element patchsElement = new Element("patchs");
                actionElement.addContent(patchsElement);
                for (int i = 0; i < getRemediationAction().getRemediationParameters().size(); i++) {
                    Patch patch = (Patch) getRemediationAction().getRemediationParameters().get(i);
                    Element patchElement = new Element("patch");
                    patchElement.setText(patch.getLink());
                    patchsElement.addContent(patchElement);
                }
                break;

            case DEPLOY_FIREWALL_RULE:
                typeElement.setText("firewall-rule");

                Element fwRuleElement = new Element("rule");
                actionElement.addContent(fwRuleElement);
                fwRuleElement.setText(((FirewallRule) getRemediationAction().getRemediationParameters().get(0)).toIptablesAddRule());
                break;

            case DEPLOY_SNORT_RULE:
                typeElement.setText("snort-rules");

                Element snortRulesElement = new Element("rules");
                actionElement.addContent(snortRulesElement);

                for (int i = 0; i < getRemediationAction().getRemediationParameters().size(); i++) {
                    Rule rule = (Rule) getRemediationAction().getRemediationParameters().get(i);

                    Element snortRuleElement = new Element("rule");
                    snortRulesElement.addContent(snortRuleElement);
                    snortRuleElement.setText(rule.getRule());

                }
                break;

            default:
                typeElement.setText("no-remediation");
                break;
        }

        return root;
    }

    /**
     * The remediation action
     *
     * @return the remediation action
     */
    public RemediationAction getRemediationAction() {
        return remediationAction;
    }

    /**
     * Sets remediation action.
     *
     * @param remediationAction the remediation action
     */
    public void setRemediationAction(RemediationAction remediationAction) {
        this.remediationAction = remediationAction;
    }

    @Override
    public String toString() {
        return getRemediationAction().getActionType() + " on " + getHost();
    }
}
