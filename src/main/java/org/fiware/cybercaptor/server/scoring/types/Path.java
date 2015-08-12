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

package org.fiware.cybercaptor.server.scoring.types;

/**
 * Class used to represent an attack path
 *
 * @author K. M.
 */
public class Path {

    /**
     * The list of ids
     */
    private double[] Path;

    /**
     * Instantiates a new Path.
     *
     * @param PathLength the path length
     */
    public Path(int PathLength) {
        Path = new double[PathLength + 1];
        Path[0] = -1;
    }

    /**
     * Get path.
     *
     * @return the double [ ]
     */
    public double[] getPath() {
        return Path;
    }

    /**
     * Sets path.
     *
     * @param path the path
     */
    public void setPath(double[] path) {
        Path = path;
    }

}
