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

package org.fiware.cybercaptor.server.remediation.dynamic;

import org.fiware.cybercaptor.server.dra.Alert;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.json.JSONObject;

/**
 * Class that represents a firewall filtering rule
 * that allow to block a specific host that is doing to do an attack.
 *
 * @author Francois -Xavier Aguessy
 */
public class DynamicFirewallRule extends DynamicRemediation {
    /**
     * The firewall rule that should be deployed
     */
    private final FirewallRule firewallRule;

    /**
     * Instantiates a new Dynamic firewall rule.
     *
     * @param alert        the alert
     * @param firewallRule the firewall rule
     */
    public DynamicFirewallRule(Alert alert, FirewallRule firewallRule) {
        super(alert);
        this.firewallRule = firewallRule;
    }

    /**
     * Gets firewall rule.
     *
     * @return the firewall rule
     */
    public FirewallRule getFirewallRule() {
        return firewallRule;
    }

    @Override
    public JSONObject toJsonObject() {
        JSONObject result = new JSONObject();

        result.put("type", "DynamicFirewallRule");

        result.put("iptables_rule", getFirewallRule().toIptablesAddRule());

        result.put("action", getFirewallRule().getAction());
        result.put("source_ip", getFirewallRule().getSource());
        result.put("source_mask", getFirewallRule().getSourceMask());
        result.put("source_port", getFirewallRule().getSourcePortRange());
        result.put("destination_ip", getFirewallRule().getDestination());
        result.put("destination_mask", getFirewallRule().getDestinationMask());
        result.put("destination_port", getFirewallRule().getDestinationPortRange());
        result.put("protocol", getFirewallRule().getProtocol());

        return result;
    }
}
