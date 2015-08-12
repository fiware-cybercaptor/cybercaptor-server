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

package org.fiware.cybercaptor.server.topology;

import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.PortRange;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.fail;

/**
 * Class to test filtering.
 *
 * @author François-Xavier Aguessy
 */
public class FilteringTest {

    private TopologyTest topologyTest;

    /**
     * Create filtering rules.
     */
    public void createFilteringRules() {
        //Creating test topology :
        /*
		 * Test topology :
		 * 
		 * 					   <INTERNET>
		 * 						   |
		 *     VLAN 1			   |		   			VLAN 2
		 *  -----------------	   |	    ----------------------------
		 * | host1 -- host2 -|-- router1 --|- host3 -- host4 -- router2 |
		 *  -----------------	   |	    ------------------------|----
		 *  					   |								|
		 *  				       |								|
		 * 						 host5							  host6
		 */
        topologyTest = new TopologyTest();
        topologyTest.createTestTopology();

        topologyTest.getHost1().getInputFirewallRulesTable().setDefaultAction(FirewallRule.Action.DROP);
        topologyTest.getHost1().getInputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("80"));
        topologyTest.getHost1().getInputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("443"));

        topologyTest.getHost1().getOutputFirewallRulesTable().setDefaultAction(FirewallRule.Action.DROP);
        topologyTest.getHost1().getOutputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("any"), topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("3306"));
        topologyTest.getHost1().getOutputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("any"), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("8080"));
        topologyTest.getHost1().getOutputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("any"), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("22"));

        topologyTest.getHost2().getInputFirewallRulesTable().setDefaultAction(FirewallRule.Action.DROP);
        topologyTest.getHost2().getInputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.ANY, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("3306"));

        topologyTest.getHost3().getOutputFirewallRulesTable().setDefaultAction(FirewallRule.Action.DROP);
        topologyTest.getHost3().getOutputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("ANY"), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("80"));
        topologyTest.getHost3().getOutputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("ANY"), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("443"));

        topologyTest.getHost4().getInputFirewallRulesTable().setDefaultAction(FirewallRule.Action.DROP);
        topologyTest.getHost4().getInputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost4().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("ANY"), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("80"));
        topologyTest.getHost4().getInputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost4().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("ANY"), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("443"));

        topologyTest.getHost5().getInputFirewallRulesTable().setDefaultAction(FirewallRule.Action.ACCEPT);

        topologyTest.getHost6().getInputFirewallRulesTable().setDefaultAction(FirewallRule.Action.DROP);
        topologyTest.getHost6().getInputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost6().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("22"));

        topologyTest.getRouter2().getOutputFirewallRulesTable().setDefaultAction(FirewallRule.Action.DROP);
        topologyTest.getRouter2().getOutputFirewallRulesTable().addFirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost6().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("22"));

        topologyTest.getRouter1().getOutputFirewallRulesTable().setDefaultAction(FirewallRule.Action.ACCEPT);
        topologyTest.getRouter1().getOutputFirewallRulesTable().addFirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.ANY, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("2222"));

    }

    /**
     * Test send a packet from a host to another.
     */
    @Test
    public void testSendAPacketFromAHostToAnother() {
        createFilteringRules();
        try {
            //Send packets inside a host
            Assert.assertTrue(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost1().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 2000, FirewallRule.Protocol.TCP));
            Assert.assertTrue(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost1().getFirstIPAddress(), 22, topologyTest.getHost1().getFirstIPAddress(), 1025, FirewallRule.Protocol.TCP));

            //Test several packets to (open and close) ports from an other host [input]
            Assert.assertTrue(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost2().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 80, FirewallRule.Protocol.TCP));
            Assert.assertTrue(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost2().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 443, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost2().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 22, FirewallRule.Protocol.TCP));

            //Test several packets from (open and close) ports to other hosts
            Assert.assertTrue(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost2().getFirstIPAddress(), 3306, FirewallRule.Protocol.TCP));
            Assert.assertTrue(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost3().getFirstIPAddress(), 8080, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost3().getFirstIPAddress(), 8081, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost2().getFirstIPAddress(), 80, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost3().getFirstIPAddress(), 3306, FirewallRule.Protocol.TCP));

            Assert.assertTrue(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost3().getFirstIPAddress(), 1030, topologyTest.getHost1().getFirstIPAddress(), 80, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost3().getFirstIPAddress(), 1030, topologyTest.getHost1().getFirstIPAddress(), 8080, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketFromAHostToAnotherSucceed(topologyTest.getHost3().getFirstIPAddress(), 1030, topologyTest.getHost1().getFirstIPAddress(), 80, FirewallRule.Protocol.UDP));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem with filtering : " + e.getMessage());
        }
    }

    /**
     * Test hosts that prevent to send a packet.
     */
    @Test
    public void testHostThatPreventToSendAPacket() {
        createFilteringRules();
        try {
            //Send packets inside a host
            Assert.assertNull(topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 1024, FirewallRule.Protocol.TCP, 64));
            Assert.assertNull(topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 22, topologyTest.getHost1().getFirstIPAddress(), 1025, FirewallRule.Protocol.TCP, 64));


            //Test several packets to (open and close) ports from an other host [input]
            Assert.assertNull(topologyTest.getHost2().hostThatPreventToSendAPacket(topologyTest.getHost2().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertNull(topologyTest.getHost2().hostThatPreventToSendAPacket(topologyTest.getHost2().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 443, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getHost1(), topologyTest.getHost2().hostThatPreventToSendAPacket(topologyTest.getHost2().getFirstIPAddress(), 1025, topologyTest.getHost1().getFirstIPAddress(), 22, FirewallRule.Protocol.TCP, 64));

            //Test several packets from (open and close) ports to other hosts
            Assert.assertNull(topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost2().getFirstIPAddress(), 3306, FirewallRule.Protocol.TCP, 64));
            Assert.assertNull(topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost3().getFirstIPAddress(), 8080, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getHost1(), topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost3().getFirstIPAddress(), 8081, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getHost1(), topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost2().getFirstIPAddress(), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getHost1(), topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost3().getFirstIPAddress(), 3306, FirewallRule.Protocol.TCP, 64));

            Assert.assertNull(topologyTest.getHost3().hostThatPreventToSendAPacket(topologyTest.getHost3().getFirstIPAddress(), 1030, topologyTest.getHost1().getFirstIPAddress(), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getHost3(), topologyTest.getHost3().hostThatPreventToSendAPacket(topologyTest.getHost3().getFirstIPAddress(), 1030, topologyTest.getHost1().getFirstIPAddress(), 8080, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getHost3(), topologyTest.getHost3().hostThatPreventToSendAPacket(topologyTest.getHost3().getFirstIPAddress(), 1030, topologyTest.getHost1().getFirstIPAddress(), 80, FirewallRule.Protocol.UDP, 64));

            //Test other packets
            Assert.assertNull(topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost6().getFirstIPAddress(), 22, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getRouter2(), topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, topologyTest.getHost6().getFirstIPAddress(), 8080, FirewallRule.Protocol.TCP, 64));

            //Try to send packets to the internet
            Assert.assertEquals(topologyTest.getHost1(), topologyTest.getHost1().hostThatPreventToSendAPacket(topologyTest.getHost1().getFirstIPAddress(), 1030, new IPAddress("157.159.103.20"), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertNull(topologyTest.getHost2().hostThatPreventToSendAPacket(topologyTest.getHost2().getFirstIPAddress(), 1030, new IPAddress("157.159.103.20"), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertNull(topologyTest.getHost3().hostThatPreventToSendAPacket(topologyTest.getHost3().getFirstIPAddress(), 1030, new IPAddress("157.159.103.20"), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertNull(topologyTest.getHost4().hostThatPreventToSendAPacket(topologyTest.getHost4().getFirstIPAddress(), 1030, new IPAddress("157.159.103.20"), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertNull(topologyTest.getHost5().hostThatPreventToSendAPacket(topologyTest.getHost5().getFirstIPAddress(), 1030, new IPAddress("157.159.103.20"), 80, FirewallRule.Protocol.TCP, 64));
            Assert.assertEquals(topologyTest.getRouter2(), topologyTest.getHost6().hostThatPreventToSendAPacket(topologyTest.getHost6().getFirstIPAddress(), 1030, new IPAddress("157.159.103.20"), 80, FirewallRule.Protocol.TCP, 64));

            Assert.assertEquals(topologyTest.getRouter1(), topologyTest.getHost4().hostThatPreventToSendAPacket(topologyTest.getHost4().getFirstIPAddress(), 1030, new IPAddress("157.159.103.20"), 2222, FirewallRule.Protocol.TCP, 64));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem with filtering : " + e.getMessage());
        }
    }

    /**
     * Test send a packet on a route.
     */
    @Test
    public void testSendAPacketOnARoute() {
        createFilteringRules();
        try {
            //Send packets inside a host
            List<Host> route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost1(), topologyTest.getHost1());
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1025, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1024, FirewallRule.Protocol.TCP));
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 22, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1025, FirewallRule.Protocol.TCP));


            //Test several packets to (open and close) ports from an other host [input]
            route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost2(), topologyTest.getHost1());
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1025, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 80, FirewallRule.Protocol.TCP));
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1025, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 443, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1025, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 22, FirewallRule.Protocol.TCP));

            //Test several packets from (open and close) ports to other hosts
            route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost1(), topologyTest.getHost2());
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 3306, FirewallRule.Protocol.TCP));

            route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost1(), topologyTest.getHost3());
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 8080, FirewallRule.Protocol.TCP));

            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 8081, FirewallRule.Protocol.TCP));

            route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost1(), topologyTest.getHost2());
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 80, FirewallRule.Protocol.TCP));

            route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost1(), topologyTest.getHost3());
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 3306, FirewallRule.Protocol.TCP));

            route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost3(), topologyTest.getHost1());
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 80, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 8080, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 80, FirewallRule.Protocol.UDP));


            //Test other packets
            route = topologyTest.getTopology().routeBetweenHosts(topologyTest.getHost1(), topologyTest.getHost6());
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, topologyTest.getHost6().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 22, FirewallRule.Protocol.TCP));


            //Try to send packets to the internet
            route = topologyTest.getHost1().getRouteToInternet();
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 80, FirewallRule.Protocol.TCP));

            route = topologyTest.getHost2().getRouteToInternet();
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost2().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 80, FirewallRule.Protocol.TCP));

            route = topologyTest.getHost3().getRouteToInternet();
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost3().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 80, FirewallRule.Protocol.TCP));

            route = topologyTest.getHost4().getRouteToInternet();
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost4().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 80, FirewallRule.Protocol.TCP));

            route = topologyTest.getHost5().getRouteToInternet();
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost5().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 80, FirewallRule.Protocol.TCP));

            route = topologyTest.getHost6().getRouteToInternet();
            System.out.println(route);
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost6().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 80, FirewallRule.Protocol.TCP));

            route = topologyTest.getHost4().getRouteToInternet();
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(route, topologyTest.getHost4().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 1030, new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 2222, FirewallRule.Protocol.TCP));

            //Try to send packets from the internet
            List<List<Host>> routes = topologyTest.getHost1().getRoutesFromInternet();

            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(routes.get(0), new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 1030, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 80, FirewallRule.Protocol.TCP));
            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(routes.get(0), new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 1030, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 443, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(routes.get(0), new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 1030, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 82, FirewallRule.Protocol.TCP));

            routes = topologyTest.getHost6().getRoutesFromInternet();

            Assert.assertTrue(topologyTest.getTopology().sendAPacketOnARoute(routes.get(0), new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 1030, topologyTest.getHost6().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 22, FirewallRule.Protocol.TCP));
            Assert.assertFalse(topologyTest.getTopology().sendAPacketOnARoute(routes.get(0), new IPAddress("157.159.103.20"), IPAddress.getIPv4NetMask(0), 1030, topologyTest.getHost6().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), 82, FirewallRule.Protocol.TCP));


        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem with filtering : " + e.getMessage());
        }
    }

    /**
     * Test firewall rules conflict.
     */
    @Test
    public void testFirewallRulesConflict() {
        createFilteringRules();
        try {

            //FIRST, CONFLICT WITH THE NEW RULE WHICH IS INCLUDED INTO THE ALREADY DEPLOYED RULES
            //Send packets inside a host
            FirewallRule ruleToTest;

            //Identical rule
            ruleToTest = new FirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("80"), null);
            Assert.assertFalse(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Opposite rule
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("80"), null);
            Assert.assertTrue(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Source Portrange included
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("80"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("80"), null);
            Assert.assertTrue(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Destination Portrange different
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("22"), null);
            Assert.assertFalse(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Destination Portrange bigger
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("80"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("ANY"), null);
            Assert.assertFalse(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Second rule of the table
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("443"), null);
            Assert.assertTrue(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Second rule of the table
            ruleToTest = new FirewallRule(FirewallRule.Action.ACCEPT, FirewallRule.Protocol.TCP, topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("443"), null);
            Assert.assertFalse(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));


            //THEN, CONFLICT WITH AN OLD RULE WHICH IS INCLUDED INTO THE TO-DEPLOY RULE
            //Send packets inside a host

            //Destination Portrange included
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("ANY"), null);
            Assert.assertTrue(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Source Portrange included
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("80"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("80"), null);
            Assert.assertTrue(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));

            //Destination Portrange bigger
            ruleToTest = new FirewallRule(FirewallRule.Action.DROP, FirewallRule.Protocol.TCP, IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), PortRange.fromString("ANY"), topologyTest.getHost1().getFirstIPAddress(), IPAddress.getIPv4NetMask(32), PortRange.fromString("ANY"), null);
            Assert.assertTrue(topologyTest.getHost1().getInputFirewallRulesTable().ruleConflictWithTable(ruleToTest));


        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem with filtering : " + e.getMessage());
        }
    }

}
