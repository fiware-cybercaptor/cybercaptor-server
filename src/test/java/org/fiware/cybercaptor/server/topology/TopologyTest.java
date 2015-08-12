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
import org.fiware.cybercaptor.server.topology.asset.VLAN;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.fail;

/**
 * Class to test the topology.
 *
 * @author François -Xavier Aguessy
 */
public class TopologyTest {

    /**
     * The topology
     */
    private Topology topology;

    /**
     * the test hosts
     */
    private Host host1;
    private Host host2;
    private Host host3;
    private Host host4;
    private Host host5;
    private Host host6;
    private Host router1;
    private Host router2;

    /**
     * Create test topology.
     *
     * @return the topology
     */
    public Topology createTestTopology() {
        topology = new Topology();

        //Create 6 hosts + 2 router
        host1 = new Host("host1", getTopology());
        host2 = new Host("host2", getTopology());
        host3 = new Host("host3", getTopology());
        host4 = new Host("host4", getTopology());
        host5 = new Host("host5", getTopology());
        host6 = new Host("host6", getTopology());
        router1 = new Host("router1", getTopology());
        router2 = new Host("router2", getTopology());

        getTopology().addHost(getHost1());
        getTopology().addHost(getHost2());
        getTopology().addHost(getHost3());
        getTopology().addHost(getHost4());
        getTopology().addHost(getHost5());
        getTopology().addHost(getHost6());
        getTopology().addHost(getRouter1());
        getTopology().addHost(getRouter2());

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
        try {
            VLAN vlan1 = new VLAN("100", "VLAN 1");
            getTopology().addVlan(vlan1);
            Interface eth0router1 = getRouter1().addInterface("eth0", "10.0.0.1", vlan1);
            Interface eth0host1 = getHost1().addInterface("eth0", "10.0.0.2", vlan1);
            Interface eth0host2 = getHost2().addInterface("eth0", "10.0.0.3", vlan1);
            getHost1().getRoutingTable().addDefaultGateway(eth0router1.getAddress(), eth0host1);
            getHost2().getRoutingTable().addDefaultGateway(eth0router1.getAddress(), eth0host2);

            VLAN vlan2 = new VLAN("200", "VLAN 2");
            getTopology().addVlan(vlan2);
            Interface eth1router1 = getRouter1().addInterface("eth1", "10.0.1.1", vlan2);
            Interface eth0host3 = getHost3().addInterface("eth0", "10.0.1.2", vlan2);
            Interface eth0host4 = getHost4().addInterface("eth0", "10.0.1.3", vlan2);
            Interface eth0router2 = getRouter2().addInterface("eth0", "10.0.1.4", vlan2);
            getHost3().getRoutingTable().addDefaultGateway(eth1router1.getAddress(), eth0host3);
            getHost4().getRoutingTable().addDefaultGateway(eth1router1.getAddress(), eth0host4);
            getRouter2().getRoutingTable().addDefaultGateway(eth0router1.getAddress(), eth0router2);

            Interface eth2router1 = getRouter1().addInterface("eth2", "157.159.103.10");
            eth2router1.setConnectedToTheInternet(true);

            Interface eth0host5 = getHost5().addInterface("eth0", "10.10.10.2");
            Interface eth3router1 = getRouter1().addInterface("eth3", "10.10.10.1", eth0host5.getVlan());
            getHost5().getRoutingTable().addDefaultGateway(eth3router1.getAddress(), eth0host5);

            Interface eth0host6 = getHost6().addInterface("eth0", "20.20.20.2");
            Interface eth1router2 = getRouter2().addInterface("eth1", "20.20.20.1", eth0host6.getVlan());
            getHost6().getRoutingTable().addDefaultGateway(eth1router2.getAddress(), eth0host6);

            getRouter1().getRoutingTable().addRoute(eth1router2.getAddress(), IPAddress.getIPv4NetMask(24), eth0router2.getAddress(), eth1router1);
            getRouter1().getRoutingTable().addRoute(eth1router1.getAddress(), IPAddress.getIPv4NetMask(24), eth1router1.getAddress(), eth1router1);
            getRouter1().getRoutingTable().addRoute(eth3router1.getAddress(), IPAddress.getIPv4NetMask(24), eth3router1.getAddress(), eth1router1);
            getRouter1().getRoutingTable().addRoute(IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), IPAddress.getIPv4NetMask(0), eth2router1);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Probleme while building topology :" + e.getMessage());
        }
        return getTopology();
    }

    /**
     * Test hosts.
     */
    @Test
    public void testHosts() {
        createTestTopology();
        Assert.assertEquals(8, getTopology().getHosts().size());
        Assert.assertNotNull(getTopology().existingHostByName("host1"));
        Assert.assertNotNull(getTopology().existingHostByName("host2"));
        Assert.assertNotNull(getTopology().existingHostByName("host3"));
        Assert.assertNotNull(getTopology().existingHostByName("host4"));
        Assert.assertNotNull(getTopology().existingHostByName("host5"));
        Assert.assertNotNull(getTopology().existingHostByName("host6"));
        Assert.assertNotNull(getTopology().existingHostByName("router1"));
        Assert.assertNotNull(getTopology().existingHostByName("router2"));
        Assert.assertNull(getTopology().existingHostByName("host7"));
    }

    /**
     * Test vlans size.
     */
    @Test
    public void testVlansSize() {
        createTestTopology();
        Assert.assertEquals(2, getTopology().getVlans().size());
    }

    /**
     * Test routing between hosts.
     */
    @Test
    public void testRoutingBetweenHosts() {
        createTestTopology();
        try {
            List<Host> route = getTopology().routeBetweenHosts(getHost1(), getHost2());
            Assert.assertEquals(2, route.size());
            Assert.assertEquals(getHost1(), route.get(0));
            Assert.assertEquals(getHost2(), route.get(1));

            route = getTopology().routeBetweenHosts(getHost2(), getHost1());
            Assert.assertEquals(2, route.size());
            Assert.assertEquals(getHost2(), route.get(0));
            Assert.assertEquals(getHost1(), route.get(1));

            route = getTopology().routeBetweenHosts(getHost1(), getRouter1());
            Assert.assertEquals(2, route.size());
            Assert.assertEquals(getHost1(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));

            route = getTopology().routeBetweenHosts(getHost1(), getHost5());
            Assert.assertEquals(3, route.size());
            Assert.assertEquals(getHost1(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));
            Assert.assertEquals(getHost5(), route.get(2));

            route = getTopology().routeBetweenHosts(getHost5(), getHost1());
            Assert.assertEquals(3, route.size());
            Assert.assertEquals(getHost5(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));
            Assert.assertEquals(getHost1(), route.get(2));

            route = getTopology().routeBetweenHosts(getHost1(), getHost4());
            Assert.assertEquals(3, route.size());
            Assert.assertEquals(getHost1(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));
            Assert.assertEquals(getHost4(), route.get(2));

            route = getTopology().routeBetweenHosts(getHost4(), getHost1());
            Assert.assertEquals(3, route.size());
            Assert.assertEquals(getHost4(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));
            Assert.assertEquals(getHost1(), route.get(2));

            route = getTopology().routeBetweenHosts(getHost1(), getHost6());
            Assert.assertEquals(4, route.size());
            Assert.assertEquals(getHost1(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));
            Assert.assertEquals(getRouter2(), route.get(2));
            Assert.assertEquals(getHost6(), route.get(3));

            route = getTopology().routeBetweenHosts(getHost6(), getHost1());
            Assert.assertEquals(4, route.size());
            Assert.assertEquals(getHost6(), route.get(0));
            Assert.assertEquals(getRouter2(), route.get(1));
            Assert.assertEquals(getRouter1(), route.get(2));
            Assert.assertEquals(getHost1(), route.get(3));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem with routes : " + e.getMessage());
        }
    }

    /**
     * Test cloning.
     */
    @Test
    public void testCloning() {
        createTestTopology();
        try {
            //Test cloning of topology
            Topology cloneTopology = getTopology().clone();
            Assert.assertNotSame(cloneTopology.existingHostByName("host1"), getTopology().existingHostByName("host1"));
            Assert.assertEquals(cloneTopology.existingHostByName("host1").getName(), getTopology().existingHostByName("host1").getName());
            Assert.assertEquals(cloneTopology.existingHostByName("host1").getFirstIPAddress(), getTopology().existingHostByName("host1").getFirstIPAddress());

            Assert.assertNotSame(cloneTopology.existingHostByName("router1"), getTopology().existingHostByName("router1"));
        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem while cloning the topology: " + e.getMessage());
        }
    }

    /**
     * Test route to internet.
     */
    @Test
    public void testRouteToInternet() {
        createTestTopology();
        try {
            List<Host> route = getHost1().getRouteToInternet();
            Assert.assertEquals(2, route.size());
            Assert.assertEquals(getHost1(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));

            route = getHost5().getRouteToInternet();
            Assert.assertEquals(2, route.size());
            Assert.assertEquals(getHost5(), route.get(0));
            Assert.assertEquals(getRouter1(), route.get(1));

            route = getHost6().getRouteToInternet();
            Assert.assertEquals(3, route.size());
            Assert.assertEquals(getHost6(), route.get(0));
            Assert.assertEquals(getRouter2(), route.get(1));
            Assert.assertEquals(getRouter1(), route.get(2));


            //Topology without internet
            Topology topologyWithoutInternet = new Topology();
            Host t2host1 = new Host("t2host1", topologyWithoutInternet);
            Host t2router1 = new Host("t2router1", topologyWithoutInternet);
            Interface t2eth0host1 = t2host1.addInterface("eth0", "10.0.0.1");
            Interface t2eth0router1 = t2router1.addInterface("eth0", "10.0.0.2", t2eth0host1.getVlan());
            t2host1.getRoutingTable().addDefaultGateway(t2eth0router1.getAddress(), t2eth0host1);
            t2router1.getRoutingTable().addRoute(t2eth0host1.getAddress(), IPAddress.getIPv4NetMask(32), t2eth0host1.getAddress(), t2eth0router1);

            route = t2host1.getRouteToInternet();
            Assert.assertEquals(0, route.size());

        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem while testing the routes to internet: " + e.getMessage());
        }
    }

    /**
     * Test routes from internet.
     */
    @Test
    public void testRoutesFromInternet() {
        createTestTopology();
        try {
            List<List<Host>> routes = getHost1().getRoutesFromInternet();
            Assert.assertEquals(1, routes.size());
            List<Host> route = routes.get(0);
            Assert.assertEquals(getRouter1(), route.get(0));
            Assert.assertEquals(getHost1(), route.get(1));

            routes = getHost5().getRoutesFromInternet();
            Assert.assertEquals(1, routes.size());
            route = routes.get(0);
            Assert.assertEquals(2, route.size());
            Assert.assertEquals(getRouter1(), route.get(0));
            Assert.assertEquals(getHost5(), route.get(1));

            routes = getHost6().getRoutesFromInternet();
            Assert.assertEquals(1, routes.size());
            route = routes.get(0);
            Assert.assertEquals(3, route.size());
            Assert.assertEquals(getRouter1(), route.get(0));
            Assert.assertEquals(getRouter2(), route.get(1));
            Assert.assertEquals(getHost6(), route.get(2));


            //Topology without internet
            Topology topologyWithoutInternet = new Topology();
            Host t2host1 = new Host("t2host1", topologyWithoutInternet);
            Host t2router1 = new Host("t2router1", topologyWithoutInternet);
            Interface t2eth0host1 = t2host1.addInterface("eth0", "10.0.0.1");
            Interface t2eth0router1 = t2router1.addInterface("eth0", "10.0.0.2", t2eth0host1.getVlan());
            t2host1.getRoutingTable().addDefaultGateway(t2eth0router1.getAddress(), t2eth0host1);
            t2router1.getRoutingTable().addRoute(t2eth0host1.getAddress(), IPAddress.getIPv4NetMask(32), t2eth0host1.getAddress(), t2eth0router1);

            routes = t2host1.getRoutesFromInternet();
            Assert.assertEquals(0, routes.size());

        } catch (Exception e) {
            e.printStackTrace();
            fail("Problem while testing the routes from internet: " + e.getMessage());
        }
    }

    /**
     * Gets topology.
     *
     * @return the topology
     */
    public Topology getTopology() {
        return topology;
    }

    /**
     * Gets host 1.
     *
     * @return the host 1
     */
    public Host getHost1() {
        return host1;
    }

    /**
     * Gets host 2.
     *
     * @return the host 2
     */
    public Host getHost2() {
        return host2;
    }

    /**
     * Gets host 3.
     *
     * @return the host 3
     */
    public Host getHost3() {
        return host3;
    }

    /**
     * Gets host 4.
     *
     * @return the host 4
     */
    public Host getHost4() {
        return host4;
    }

    /**
     * Gets host 5.
     *
     * @return the host 5
     */
    public Host getHost5() {
        return host5;
    }

    /**
     * Gets host 6.
     *
     * @return the host 6
     */
    public Host getHost6() {
        return host6;
    }

    /**
     * Gets router 1.
     *
     * @return the router 1
     */
    public Host getRouter1() {
        return router1;
    }

    /**
     * Gets router 2.
     *
     * @return the router 2
     */
    public Host getRouter2() {
        return router2;
    }
}
