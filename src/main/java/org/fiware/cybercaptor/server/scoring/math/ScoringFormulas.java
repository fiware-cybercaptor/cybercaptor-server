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
package org.fiware.cybercaptor.server.scoring.math;

import org.apache.commons.math3.stat.descriptive.moment.Mean;
import org.apache.commons.math3.stat.descriptive.moment.StandardDeviation;
import org.apache.commons.math3.stat.descriptive.summary.Sum;
import org.fiware.cybercaptor.server.attackgraph.ImpactMetric;
import org.fiware.cybercaptor.server.scoring.types.Arc;
import org.fiware.cybercaptor.server.scoring.types.Graph;
import org.fiware.cybercaptor.server.scoring.types.Vertex;

/**
 * Class used to store the scoring formulas
 *
 * @author K. M.
 */
public class ScoringFormulas {

    /**
     * The standard deviation value
     */
    private double standardDeviationValue = 0.0;

    /**
     * The mean Value
     */
    private double meanValue = 0.0;

    /**
     * The Standard deviation.
     */
    private StandardDeviation standardDeviation = new StandardDeviation();

    /**
     * The Mean.
     */
    private Mean mean = new Mean();

    /**
     * The Sum.
     */
    private Sum sum = new Sum();

    /**
     * Compute the global score.
     *
     * @param attackPath the attack path
     * @return the gobal score
     */
    public double globalScore(Graph attackPath) {
        Vertex[] vertices = attackPath.getVertices();
        Arc[] arcs = attackPath.getArcs();
        double RiskScore = riskScore(vertices, arcs);
        double ImpactScore = impactScore(attackPath);
        return RiskScore + ImpactScore;
    }

    /**
     * Compute the risk score.
     *
     * @param vertices the graph vertices
     * @param arcs     the graph arcs
     * @return the risk score
     */
    public double riskScore(Vertex[] vertices, Arc[] arcs) {
        double[] RANDTable;
        double[] RORTable;
        double[] RLEAFTable;
        double RAND = 0, ROR = 0, RLEAF = 0, a = 0, o = 0, l = 0;
        Vertex[] ANDVertices = Graph.getVerticesOnType(vertices, "AND");
        Vertex[] ORVertices = Graph.getVerticesOnType(vertices, "OR");
        Vertex[] LEAFVertices = Graph.getVerticesOnType(vertices, "LEAF");
        if (ANDVertices != null) {
            a = ANDVertices.length;
        }
        if (ORVertices != null) {
            o = ORVertices.length;
        }
        if (LEAFVertices != null) {
            l = LEAFVertices.length;
        }
        if (ANDVertices != null) {
            RANDTable = new double[ANDVertices.length];
            for (int i = 0; i < ANDVertices.length; i++) {
                double OutgoingArcs = Graph.getOutgoingArcsNumber(arcs, ANDVertices[i].getID());
                double IngoingArcs = Graph.getIngoingArcsNumber(arcs, ANDVertices[i].getID());
                double CumulativeScore = ANDVertices[i].getMulvalMetric();
                RANDTable[i] = (CumulativeScore * (OutgoingArcs / IngoingArcs)) / a;
            }
            RAND = getSum().evaluate(RANDTable, 0, RANDTable.length);
        }
        if (ORVertices != null) {
            RORTable = new double[ORVertices.length];
            for (int i = 0; i < ORVertices.length; i++) {
                double OutgoingArcs = Graph.getOutgoingArcsNumber(arcs, ORVertices[i].getID());
                double IngoingArcs = Graph.getIngoingArcsNumber(arcs, ORVertices[i].getID());
                double CumulativeScore = ORVertices[i].getMulvalMetric();
                RORTable[i] = CumulativeScore * OutgoingArcs * IngoingArcs * o;
            }
            ROR = getSum().evaluate(RORTable, 0, RORTable.length);
        }
        if (LEAFVertices != null) {
            RLEAFTable = new double[LEAFVertices.length];
            for (int i = 0; i < LEAFVertices.length; i++) {
                double OutgoingArcs = Graph.getOutgoingArcsNumber(arcs, LEAFVertices[i].getID());
                RLEAFTable[i] = OutgoingArcs / l;//IngoingArcs=0 and CumulativeScore=1 for all LEAF vertices
            }
            RLEAF = getSum().evaluate(RLEAFTable, 0, RLEAFTable.length);
        }
        return RAND + ROR + RLEAF;
    }

    /**
     * Compute the impact score.
     *
     * @param attackPath the graph to score
     * @return the impact score
     */
    public double impactScore(Graph attackPath) {
        double[] ImpactTable = new double[attackPath.getVertices().length];

        for (int i = 0; i < attackPath.getVertices().length; i++) {
            ImpactTable[i] = 0.;
            Vertex vertex = attackPath.getVertices()[i];
            if (vertex.getImpactMetrics() != null) {
                double impactElement = 0.;
                for (int j = 0; j < vertex.getImpactMetrics().length; j++) {
                    ImpactMetric impactMetric = vertex.getImpactMetrics()[j];
                    impactElement += impactMetric.getValue() * impactMetric.getWeight();
                }
                ImpactTable[i] = impactElement;
            }
        }
        return getSum().evaluate(ImpactTable, 0, ImpactTable.length);
    }


    /**
     * Compute the P norm.
     *
     * @param scores the scores to normalize
     * @param p      the p
     * @return the P norm
     */
    public double pNorm(double[] scores, double p) {
        int i;
        double[] powerScores = new double[scores.length];

        for (i = 0; i < scores.length; i++) {
            powerScores[i] = Math.pow(scores[i], p);
        }
        return Math.pow(getSum().evaluate(powerScores, 0, i), 1.0 / p);
    }

    /**
     * compute the Z raw score.
     *
     * @param scores      the scores
     * @param vertexScore the vertex score
     * @return the Z raw score
     */
    public double zRawScore(double[] scores, double vertexScore) {

        setStandardDeviationValue(getStandardDeviation().evaluate(scores));
        setMeanValue(getMean().evaluate(scores));

        return (vertexScore - getMeanValue()) / getStandardDeviationValue();
    }

    /**
     * Compute the Z global raw score.
     *
     * @param globalRawScores    the global raw scores
     * @param currentGlobalScore the current global score
     * @return the Z global raw score
     */
    public double zGlobalRawScore(double[] globalRawScores, double currentGlobalScore) {

        setStandardDeviationValue(getStandardDeviation().evaluate(globalRawScores));
        setMeanValue(getMean().evaluate(globalRawScores));

        return (currentGlobalScore - getMeanValue()) / getStandardDeviationValue();
    }

    /**
     * Compute min max.
     *
     * @param globalRawScore the global raw score
     * @param maxGlobalScore the max global score
     * @return the min max.
     */
    public double MinMax(double globalRawScore, double maxGlobalScore) {
        return (globalRawScore / (1. * maxGlobalScore));
    }

    /**
     * Compute the RNAD.
     *
     * @param globalRawScore the global raw score
     * @param maxGlobalScore the max global score
     * @return the RNAD
     */
    public double RNAD(double globalRawScore, double maxGlobalScore) {

        return Math.abs(((globalRawScore - maxGlobalScore) / maxGlobalScore));
    }

    /**
     * Compute A1
     *
     * @param scores the scores
     * @return A1
     */
    public double A1(double[] scores) {
        return getSum().evaluate(scores, 0, scores.length);
    }

    /**
     * Compute A2
     *
     * @param scores the scores
     * @return A2
     */
    public double A2(double[] scores) {
        return getSum().evaluate(scores, 0, scores.length) / scores.length;
    }

    /**
     * Gets standard deviation value.
     *
     * @return the standard deviation value
     */
    public double getStandardDeviationValue() {
        return standardDeviationValue;
    }

    /**
     * Sets standard deviation value.
     *
     * @param standardDeviationValue the standard deviation value
     */
    public void setStandardDeviationValue(double standardDeviationValue) {
        this.standardDeviationValue = standardDeviationValue;
    }

    /**
     * Gets mean value.
     *
     * @return the mean value
     */
    public double getMeanValue() {
        return meanValue;
    }

    /**
     * Sets mean value.
     *
     * @param meanValue the mean value
     */
    public void setMeanValue(double meanValue) {
        this.meanValue = meanValue;
    }

    /**
     * Gets standard deviation.
     *
     * @return the standard deviation
     */
    public StandardDeviation getStandardDeviation() {
        return standardDeviation;
    }

    /**
     * Sets standard deviation.
     *
     * @param standardDeviation the standard deviation
     */
    public void setStandardDeviation(StandardDeviation standardDeviation) {
        this.standardDeviation = standardDeviation;
    }

    /**
     * Gets mean.
     *
     * @return the mean
     */
    public Mean getMean() {
        return mean;
    }

    /**
     * Sets mean.
     *
     * @param mean the mean
     */
    public void setMean(Mean mean) {
        this.mean = mean;
    }

    /**
     * Gets sum.
     *
     * @return the sum
     */
    public Sum getSum() {
        return sum;
    }

    /**
     * Sets sum.
     *
     * @param sum the sum
     */
    public void setSum(Sum sum) {
        this.sum = sum;
    }
}
