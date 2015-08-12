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
 * Class used to represent the arc of a graph
 *
 * @author K. M.
 */
public class Arc {

    /**
     * The source id
     */
    private double Source;

    /**
     * the destination id
     */
    private double Destination;

    /**
     * The Arc dependancy set.
     */
    private Arc[] ArcDependancySet = null;

    /**
     * The Vertex dependancy set.
     */
    private Vertex[] VertexDependancySet = null;

    /**
     * Instantiates a new Arc.
     *
     * @param source      the source id
     * @param destination the destination id
     */
    public Arc(double source, double destination) {
        Source = source;
        Destination = destination;
    }

    /**
     * Gets source.
     *
     * @return the source id
     */
    public double getSource() {
        return Source;
    }

    /**
     * Sets source.
     *
     * @param source the source id
     */
    public void setSource(double source) {
        Source = source;
    }

    /**
     * Gets destination.
     *
     * @return the destination id
     */
    public double getDestination() {
        return Destination;
    }

    /**
     * Sets destination.
     *
     * @param destination the destination id
     */
    public void setDestination(double destination) {
        Destination = destination;
    }

    /**
     * Add vertex dependency.
     *
     * @param vertex the vertex
     */
    public void addVertexDependency(Vertex vertex) {
        if (this.getVertexDependancySet() == null) {
            Vertex[] result = new Vertex[1];
            result[result.length - 1] = vertex;
            this.setVertexDependancySet(result);
        } else {
            Vertex[] result = new Vertex[this.getVertexDependancySet().length + 1];
            System.arraycopy(this.getVertexDependancySet(), 0, result, 0, this.getVertexDependancySet().length);
            result[result.length - 1] = vertex;
            this.setVertexDependancySet(result);
        }
    }

    /**
     * Add vertex dependency.
     *
     * @param vertexList the vertex list
     */
    public void addVertexDependency(Vertex[] vertexList) {
        if (this.getVertexDependancySet() == null) {
            this.setVertexDependancySet(new Vertex[vertexList.length]);
            System.arraycopy(vertexList, 0, this.getVertexDependancySet(), 0, vertexList.length);
        } else {
            Vertex[] result = new Vertex[this.getVertexDependancySet().length + vertexList.length];
            System.arraycopy(this.getVertexDependancySet(), 0, result, 0, this.getVertexDependancySet().length);
            System.arraycopy(vertexList, 0, result, this.getVertexDependancySet().length, result.length - this.getVertexDependancySet().length);
            vertexList = new Vertex[result.length];
            System.arraycopy(result, 0, vertexList, 0, result.length);
        }
    }

    /**
     * Add arc dependency.
     *
     * @param arc the arc
     */
    public void addArcDependency(Arc arc) {
        if (this.getArcDependancySet() == null) {
            Arc[] result = new Arc[1];
            result[result.length - 1] = arc;
            this.setArcDependancySet(result);
        } else {
            Arc[] result = new Arc[this.getArcDependancySet().length + 1];
            System.arraycopy(this.getArcDependancySet(), 0, result, 0, this.getArcDependancySet().length);
            result[result.length - 1] = arc;
            this.setArcDependancySet(result);
        }
    }

    /**
     * Get arc dependancy set.
     *
     * @return the arc [ ]
     */
    public Arc[] getArcDependancySet() {
        return ArcDependancySet;
    }

    /**
     * Sets arc dependancy set.
     *
     * @param arcDependancySet the arc dependancy set
     */
    public void setArcDependancySet(Arc[] arcDependancySet) {
        ArcDependancySet = arcDependancySet;
    }

    /**
     * Get vertex dependancy set.
     *
     * @return the vertex [ ]
     */
    public Vertex[] getVertexDependancySet() {
        return VertexDependancySet;
    }

    /**
     * Sets vertex dependancy set.
     *
     * @param vertexDependancySet the vertex dependancy set
     */
    public void setVertexDependancySet(Vertex[] vertexDependancySet) {
        VertexDependancySet = vertexDependancySet;
    }
}
