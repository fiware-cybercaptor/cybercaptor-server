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
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.json.JSONObject;

/**
 * Class that represents a packet redirection remediation :
 * All packets of the attack source should be rerouted either to a black-hole
 * either to a DDOS-mitigation equipment
 *
 * @author Francois -Xavier Aguessy
 */
public class PacketRedirectionRemediation extends DynamicRemediation {
    /**
     * The ip address (or network address) of the source of attack
     */
    private final IPAddress source;
    /**
     * The network mask of the source of attack
     */
    private final IPAddress sourceMask;

    /**
     * Instantiates a new Packet redirection remediation.
     *
     * @param alert      the alert
     * @param source     the source
     * @param sourceMask the source mask
     */
    public PacketRedirectionRemediation(Alert alert, IPAddress source, IPAddress sourceMask) {
        super(alert);
        this.source = source;
        this.sourceMask = sourceMask;
    }

    /**
     * Gets source.
     *
     * @return the source
     */
    public IPAddress getSource() {
        return source;
    }

    /**
     * Gets source mask.
     *
     * @return the source mask
     */
    public IPAddress getSourceMask() {
        return sourceMask;
    }

    @Override
    public JSONObject toJsonObject() {
        JSONObject result = new JSONObject();

        result.put("type", "PacketRedirectionRemediation");

        result.put("iptables_rule", this.toIptablesRule());
        result.put("linux_black_hole_rule", "ip route add blackhole " + getSource() + "/" + getSourceMask().getMaskFromIPv4Address());

        result.put("action", "REDIRECT black-hole-address/ddos-filtering-equipment-address");
        result.put("source_ip", getSource());
        result.put("source_mask", getSourceMask());

        return result;
    }

    /**
     * Transform this remediation to a iptables rule
     *
     * @return the ip tables rule to redirect all trafic from source to a DDOS mitigation server
     */
    private String toIptablesRule() {
        return "iptables -t nat -A PREROUTING " +
                "-s " + getSource().getAddress() +
                "/" + getSourceMask().getMaskFromIPv4Address() +
                " -j DNAT --to-destination <ddos-mitigation-server>";
    }

}
