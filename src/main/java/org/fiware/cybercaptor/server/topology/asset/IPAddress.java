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
package org.fiware.cybercaptor.server.topology.asset;

import java.util.regex.Pattern;

/**
 * Class that represents an IP address
 *
 * @author Francois-Xavier Aguessy
 */
public class IPAddress implements Cloneable {
    /**
     * The IPv4 address pattern
     */
    public static Pattern pattern = Pattern.compile("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    /**
     * The string of the  IP address
     */
    private String address = "";

    /**
     * Create an IPAddress
     *
     * @param address the string of the ip address
     * @throws Exception
     */
    public IPAddress(String address) throws Exception {
        super();
        if (!isAnIPAddress(address))
            throw new Exception("Invalid IP Address ");
        this.address = address;
    }

    /**
     * Transform a mask like /24 into an ip address 255.255.255.0
     *
     * @param netPrefix the int prefix
     * @return the IPv4 mask
     */
    public static IPAddress getIPv4NetMask(int netPrefix) {
        try {
            if (netPrefix == 0) {
                return new IPAddress("0.0.0.0");
            }
            int shiftby = (1 << 31);
            for (int i = netPrefix - 1; i > 0; i--) {
                shiftby = (shiftby >> 1);
            }
            String maskString = Integer.toString((shiftby >> 24) & 255) + "." + Integer.toString((shiftby >> 16) & 255) + "." + Integer.toString((shiftby >> 8) & 255) + "." + Integer.toString(shiftby & 255);
            return new IPAddress(maskString);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param ipNetwork1   the ip of the first network
     * @param maskNetwork1 he mask of the first network
     * @param ipNetwork2   the ip of the second network
     * @param maskNetwork2 the mask of the second network
     * @return true if the first network is contained in the second network
     */
    public static boolean networkInOtherNetwork(IPAddress ipNetwork1, IPAddress maskNetwork1, IPAddress ipNetwork2, IPAddress maskNetwork2) {
        int intIpNetwork1 = ipNetwork1.toInt();
        int intmaskNetwork1 = maskNetwork1.toInt();
        int intIpNetwork2 = ipNetwork2.toInt();
        int intmaskNetwork2 = maskNetwork2.toInt();
        return (intIpNetwork1 & intmaskNetwork1 & intmaskNetwork2) == (intIpNetwork2 & intmaskNetwork2);
    }

    public static boolean isAnIPAddress(String str) {
        return pattern.matcher(str).matches();
    }

    /**
     * @return the address
     */
    public String getAddress() {
        return address;
    }

    /**
     * Transform an mask ip address like 255.255.255.0 into a mask like /24
     *
     * @return the mask
     */
    public int getMaskFromIPv4Address() {
        int ip_int = this.toInt();
        int i = 31;
        while (i >= 0 && (ip_int << i) == 0) {
            i--;
        }
        return i + 1;

    }

    /**
     * Change an ip address to an 32 bits int
     *
     * @return the 32 bit int
     */
    public int toInt() {
        String[] ip_string = this.getAddress().split("\\.");

        return ((Integer.parseInt(ip_string[0]) & 0xFF) << 24) |
                ((Integer.parseInt(ip_string[1]) & 0xFF) << 16) |
                ((Integer.parseInt(ip_string[2]) & 0xFF) << 8) |
                ((Integer.parseInt(ip_string[3]) & 0xFF));
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        IPAddress other = (IPAddress) obj;
        if (getAddress() == null) {
            if (other.getAddress() != null)
                return false;
        } else if (!getAddress().equals(other.getAddress()))
            return false;
        return true;
    }

    @Override
    public IPAddress clone() throws CloneNotSupportedException {

        return (IPAddress) super.clone();
    }

    @Override
    public String toString() {
        return getAddress();
    }
}
