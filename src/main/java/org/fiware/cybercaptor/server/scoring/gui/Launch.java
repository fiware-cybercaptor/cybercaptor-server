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
 * along with FIWARE Cyber Security Generic Enabler.                                    *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/
package org.fiware.cybercaptor.server.scoring.gui;


import org.fiware.cybercaptor.server.attackgraph.ImpactMetric;
import org.fiware.cybercaptor.server.scoring.math.AttackPaths;
import org.fiware.cybercaptor.server.scoring.math.ScoringFormulas;
import org.fiware.cybercaptor.server.scoring.types.Arc;
import org.fiware.cybercaptor.server.scoring.types.Graph;
import org.fiware.cybercaptor.server.scoring.types.Vertex;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import java.io.FileOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class used to launch the scoring function
 *
 * @author K. M.
 */
public class Launch {

    public static ScoringFormulas formulas = new ScoringFormulas();

    /**
     * Function used to launch the scoring function
     *
     * @param vertexIDTable           the vertex ids table
     * @param vertexFactTable         the vertex facts table
     * @param vertexMulvalMetricTable the vertex metrics table
     * @param vertexTypeTable         the vertex types table
     * @param arcSrcTable             the arc sources table
     * @param arcDstTable             the arc destinations table
     * @param ImpactMetrics           the impact metrics table
     * @param pathToAttackPathsFile   the path where the attack paths will be written
     * @param previousMaxScore        the previous max score (used for normalization)
     * @return the score of the attack graph
     * @throws Exception
     */
    public static double main(double[] vertexIDTable, String[] vertexFactTable, double[] vertexMulvalMetricTable, String[] vertexTypeTable, double[] arcSrcTable, double[] arcDstTable, ImpactMetric[][] ImpactMetrics, String pathToAttackPathsFile, double previousMaxScore) throws Exception {

        Arc[] ArcsTable = new Arc[arcSrcTable.length];
        Vertex[] VerticesTable = new Vertex[vertexIDTable.length];


        for (int i = 0; i < ArcsTable.length; i++) {
            ArcsTable[i] = new Arc(-1, -1);
            ArcsTable[i].setSource(arcSrcTable[i]);
            ArcsTable[i].setDestination(arcDstTable[i]);
        }
        for (int i = 0; i < vertexIDTable.length; i++) {
            VerticesTable[i] = new Vertex(-1, "EOF", -1, "EOF");
            VerticesTable[i].setID(vertexIDTable[i]);
            VerticesTable[i].setFact(vertexFactTable[i]);
            VerticesTable[i].setMulvalMetric(vertexMulvalMetricTable[i]);
            VerticesTable[i].setType(vertexTypeTable[i]);
            VerticesTable[i].setImpactMetrics(ImpactMetrics[i]);
        }
        Graph graph = new Graph(ArcsTable, VerticesTable);
        Vertex[] TargetSet = Graph.getVerticesOnTypeAndFact(VerticesTable, "OR");

        System.out.println("Generate Attack Paths");
        Graph[] result = AttackPaths.main(TargetSet, graph); //Disabled following the test launch of attack path algorithm.

        double scoreAttackGraph = formulas.MinMax(formulas.globalScore(graph), previousMaxScore);

        saveToXmlFile(pathToAttackPathsFile, result);
        Logger.getAnonymousLogger().log(Level.INFO, "Attack paths generated");
        return scoreAttackGraph;
    }

    /**
     * Save the list of attack paths into a XML file
     *
     * @param filePath    the paths where the list XML of attack paths can be written
     * @param AttackPaths list of attack paths
     * @throws Exception
     */
    protected static void saveToXmlFile(String filePath, Graph[] AttackPaths) throws Exception {
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        Element MainRoot = new Element("attack_paths");
        Element root;
        if (AttackPaths != null) {
            for (Graph AttackPathBuffer : AttackPaths) {
                Arc[] AttackPathArcs = AttackPathBuffer.getArcs();
                root = new Element("attack_path");
                Element scoringElement = new Element("scoring");
                scoringElement.setText(String.valueOf(formulas.MinMax(formulas.globalScore(AttackPathBuffer), AttackPathBuffer.getVertices().length)));
                root.addContent(scoringElement);
                if (AttackPathArcs != null) {
                    Element arcsElement = new Element("arcs");
                    for (Arc AttackPathArc : AttackPathArcs) {
                        Element arcElement = new Element("arc");
                        arcsElement.addContent(arcElement);
                        Element srcElement = new Element("src");
                        srcElement.setText(String.valueOf(AttackPathArc.getSource()));
                        arcElement.addContent(srcElement);
                        Element dstElement = new Element("dst");
                        dstElement.setText(String.valueOf(AttackPathArc.getDestination()));
                        arcElement.addContent(dstElement);
                    }
                    root.addContent(arcsElement);
                    MainRoot.addContent(root);
                }
            }
        }
        output.output(MainRoot, new FileOutputStream(filePath));
    }
}