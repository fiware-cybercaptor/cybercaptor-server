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

package org.fiware.cybercaptor.server.topology.asset.component;

/**
 * Class to manage an tcp or udp port range
 *
 * @author Francois-Xavier Aguessy
 */
public class PortRange implements Cloneable {
    /**
     * If true, the port range contains all available ports (1-65535)
     */
    private boolean any = false;

    /**
     * The minimum port
     */
    private int min;

    /**
     * The maximum port
     */
    private int max;

    /**
     * Create a range with a minimum and a maximum
     *
     * @param min the minimum
     * @param max the maximum
     */
    public PortRange(int min, int max) {
        super();
        this.setMin(min);
        this.setMax(max);
    }

    /**
     * Create a range of an ports
     *
     * @param any true if the port range contains all possible ports
     */
    public PortRange(boolean any) {
        super();
        this.setAny(any);
    }

    /**
     * @param string a port range string
     * @return a new port range from a string containing "any", "all", "22" or "21-23"
     */
    public static PortRange fromString(String string) {
        if (string.toLowerCase().contains("any")) {
            return new PortRange(true);
        } else if (string.toLowerCase().contains("all")) {
            return new PortRange(true);
        } else if (string.toLowerCase().contains("*")) {
            return new PortRange(true);
        } else if (string.toLowerCase().contains("-")) {
            return new PortRange(Integer.parseInt(string.split("-")[0]), Integer.parseInt(string.split("-")[1]));
        } else if (string.toLowerCase().contains("httpport")) {
            return new PortRange(80, 80);
        } else {
            return new PortRange(Integer.parseInt(string), Integer.parseInt(string));
        }
    }

    /**
     * @return the any
     */
    public boolean isAny() {
        return any;
    }

    /**
     * @param any the any to set
     */
    public void setAny(boolean any) {
        this.any = any;
    }

    /**
     * @return the min
     */
    public int getMin() {
        return min;
    }

    /**
     * @param min the min to set
     */
    public void setMin(int min) {
        this.min = min;
    }

    /**
     * @return the max
     */
    public int getMax() {
        return max;
    }

    /**
     * @param max the max to set
     */
    public void setMax(int max) {
        this.max = max;
    }

    /**
     * @param a an integer (port number)
     * @return true if a is in the range else false
     */
    public boolean inRange(int a) {
        return isAny() || (a <= getMax() && a >= getMin());

    }

    /**
     * @param a a port range
     * @return true if a is in the range else false
     */
    public boolean inRange(PortRange a) {
        return isAny() || (a.getMax() <= getMax() && a.getMin() >= getMin());

    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (isAny() ? 1231 : 1237);
        result = prime * result + getMax();
        result = prime * result + getMin();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        PortRange other = (PortRange) obj;
        return isAny() == other.isAny() && getMax() == other.getMax() && getMin() == other.getMin();
    }

    @Override
    public PortRange clone() throws CloneNotSupportedException {
        return (PortRange) super.clone();
    }

    @Override
    public String toString() {
        if (this.isAny())
            return "any";
        else if (getMin() == getMax())
            return getMin() + "";
        else
            return getMin() + "-" + getMax();
    }

}
