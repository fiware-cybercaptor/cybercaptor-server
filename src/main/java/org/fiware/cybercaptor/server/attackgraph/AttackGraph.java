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
package org.fiware.cybercaptor.server.attackgraph;

import org.fiware.cybercaptor.server.attackgraph.Vertex.VertexType;
import org.fiware.cybercaptor.server.attackgraph.fact.DatalogCommand;
import org.fiware.cybercaptor.server.attackgraph.fact.Fact;
import org.fiware.cybercaptor.server.attackgraph.fact.Fact.FactType;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraph;
import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraphArc;
import org.fiware.cybercaptor.server.informationsystem.graph.InformationSystemGraphVertex;
import org.fiware.cybercaptor.server.scoring.gui.Launch;
import org.fiware.cybercaptor.server.vulnerability.Vulnerability;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Class to represent an attack graph
 *
 * @author Francois-Xavier Aguessy
 */
public class AttackGraph implements Cloneable {
    /**
     * A list of vertices
     */
    public HashMap<Integer, Vertex> vertices = new HashMap<Integer, Vertex>();

    /**
     * A list of arcs between the vertices
     */
    public ArrayList<Arc> arcs = new ArrayList<Arc>();

    /**
     * The global score of the attack graph
     */
    public double globalScore = 0;

    /**
     * Check if a vertex exists, if it doesn't, creates a new one
     *
     * @param id_vertex the id of the vertex to check
     * @return a vertex of identifier id_vertex
     */
    public Vertex getExistingOrCreateVertex(int id_vertex) {
        Vertex result = vertices.get(id_vertex);
        if (result == null) {
            result = new Vertex(id_vertex);
            vertices.put(id_vertex, result);
        }
        return result;
    }

    /**
     * Compute the parents and the children of the whole attack graph
     */
    public void computeAllParentsAndChildren() {
        for (Integer key : vertices.keySet()) {
            vertices.get(key).computeParentsAndChildren(this);
        }
    }

    /**
     * @param id the identifier of the vertex in the attack graph
     * @return the vertex from the attack graph
     * @throws Exception
     */
    public Vertex getVertexFromId(int id) throws Exception {
        Vertex vertex = this.vertices.get(id);
        if (vertex == null)
            throw new Exception("The vertex " + id + " is not in this attack graph");
        return vertex;
    }

    /**
     * Simulate the deletion of a vertex and propagate this deletion on the whole attack graph
     *
     * @param vertex The vertex to delete
     * @throws Exception
     */
    public void deleteVertex(Vertex vertex) throws Exception {
        if (!this.vertices.containsKey(vertex.id)) //If the vertex has already been deleted
            return;

        //In all case (AND, OR and LEAF), we delete the vertex
        this.vertices.remove(vertex.id);

        vertex.computeParentsAndChildren(this);

        for (int i = 0; i < vertex.children.size(); i++) {
            Vertex child = vertex.children.get(i);

            deleteArc(vertex, child); //We delete the arc from this vertex to the child
            if (child.type == VertexType.AND) //If the child is an "AND" he must be remove
                deleteVertex(child);
            else if (child.type == VertexType.OR) { //If the child is an "OR" he must be remove only if it was it last parent

                child.computeParentsAndChildren(this);

                if (child.parents.size() == 0) { //If it is the last parent

                    deleteVertex(child);
                }
            }
        }

        for (int i = 0; i < vertex.parents.size(); i++) { //We delete all vertices from the parents to the vertex
            Vertex parent = vertex.parents.get(i);
            parent.computeParentsAndChildren(this);
            if (parent.children.size() == 1 && parent.children.get(0) == vertex && parent.parents.size() == 0) {//We delete a parent if he has no child remaining and no parents
                deleteVertex(parent);
            }

            deleteArc(parent, vertex);


        }

        this.deleteUnreachableVertices();
    }

    /**
     * Delete all arcs from a vertex to another
     *
     * @param fromVertex the source vertex
     * @param toVertex   the destination vertex
     */
    public void deleteArc(Vertex fromVertex, Vertex toVertex) {
        for (int i = 0; i < this.arcs.size(); i++) {
            Arc arc = this.arcs.get(i);
            if (arc.source.id == fromVertex.id && arc.destination.id == toVertex.id) {
                this.arcs.remove(i);
            }
        }
    }

    /**
     * @return the number of vertices in the attack graph
     */
    public int getNumberOfVertices() {
        return this.vertices.size();
    }

    /**
     * @param vuln a vulnerability
     * @return the vertices that have the vuln vulnerability
     */
    public List<Vertex> getVerticesByVulnerability(Vulnerability vuln) {
        List<Vertex> result = new ArrayList<Vertex>();
        for (Integer key : vertices.keySet()) {
            Vertex vertex = vertices.get(key);
            if (vertex.relatedVulnerabilibty != null && vertex.relatedVulnerabilibty.equals(vuln))
                result.add(vertices.get(key));

        }

        return result;
    }

    /**
     * @return the adjacency matrix related to the attack graph
     */
    public int[][] getAdjacencyMatrix() {
        int numberOfVertices = this.getNumberOfVertices();
        int[][] adjacencyMatrix = new int[numberOfVertices][numberOfVertices];
        for (Arc arc : this.arcs) {
            adjacencyMatrix[arc.source.id - 1][arc.destination.id - 1] = 1;
        }
        return adjacencyMatrix;
    }

    /**
     * Use the taboo method to find all the attack paths between the vertex v1 and v2
     *
     * @param v1 the source vertex
     * @param v2 the destination vertex
     * @return the list of all attacks path from v1 to v2
     * @throws Exception
     */
    public List<List<Vertex>> getExistingAttackPathsBetween(Vertex v1, Vertex v2) throws Exception {
        List<List<Vertex>> attackPathsList = new ArrayList<List<Vertex>>();
        int numberOfVertices = this.getHighestVertexId();
        int[] path = new int[numberOfVertices];
        boolean[] taboo = new boolean[numberOfVertices];
        int source = v1.id - 1;
        int destination = v2.id - 1;
        int[][] adjacencyMatrix = getAdjacencyMatrix();

        explore(attackPathsList, path, destination, taboo, adjacencyMatrix, numberOfVertices, source, 0);

        return attackPathsList;
    }

    protected void explore(List<List<Vertex>> attackPathsList, int[] path, int target, boolean[] taboo, int[][] adjacencymatrix, int n, int position, int depth) throws Exception {
        path[depth] = position;
        // end
        if (position == target) {
            List<Vertex> attackPath = new ArrayList<Vertex>();
            for (int i = 0; i <= depth; i++) {
                attackPath.add(this.getVertexFromId(path[i] + 1));
            }
            attackPathsList.add(attackPath);
            return;
        }

        taboo[position] = true; // add a taboo

        // explore the remaining paths
        for (int i = 0; i < n; i++) {
            if (adjacencymatrix[position][i] == 0 || taboo[i]) continue;
            explore(attackPathsList, path, target, taboo, adjacencymatrix, n, i, depth + 1);
        }

        taboo[position] = false; // remove the taboo
    }

    /**
     * Get one path with the minimum of leaves required to arrive to this vertex
     *
     * @param v the current vertex
     * @return the minimum prerequisite leaves to reach v
     * @throws Exception
     */
    public List<Vertex> getMinimumPrerequisiteLeavesTo(Vertex v) throws Exception {
        return getMinimumPrerequisiteLeavesToRecursive(v, new boolean[this.getHighestVertexId()]);
    }

    private List<Vertex> getMinimumPrerequisiteLeavesToRecursive(Vertex v, boolean[] alreadySeen) throws Exception {
        List<Vertex> res = new ArrayList<Vertex>();
        if (v.type == VertexType.LEAF) {
            res.add(v);
            return res;
        }
        if (v.type == VertexType.OR && !alreadySeen[v.id - 1]) {
            v.computeParentsAndChildren(this);
            int minimumNumberOfLeaves = this.getNumberOfVertices() + 1;
            List<Vertex> minimumPath = new ArrayList<Vertex>();
            alreadySeen[v.id - 1] = true;
            for (int i = 0; i < v.parents.size(); i++) {
                List<Vertex> res_parent = this.getMinimumPrerequisiteLeavesToRecursive(v.parents.get(i), alreadySeen);
                if (res_parent.size() < minimumNumberOfLeaves && res_parent.size() != 0) {
                    minimumPath = res_parent;
                    minimumNumberOfLeaves = res_parent.size();
                }
            }
            alreadySeen[v.id - 1] = false;
            res.addAll(minimumPath);
            return res;
        } else if (v.type == VertexType.AND && !alreadySeen[v.id - 1]) {
            v.computeParentsAndChildren(this);
            alreadySeen[v.id - 1] = true;
            List<Vertex> toAdd = new ArrayList<Vertex>();
            for (int i = 0; i < v.parents.size(); i++) {
                List<Vertex> res_parent = this.getMinimumPrerequisiteLeavesToRecursive(v.parents.get(i), alreadySeen);
                if (res_parent.size() == 0)
                    return res;
                else {
                    toAdd.addAll(res_parent);
                }
            }
            res.addAll(toAdd);
            alreadySeen[v.id - 1] = false;
            return res;
        }
        return res;
    }

    /**
     * Delete all unreachable vertices in the attack graph
     *
     * @throws Exception
     */
    public void deleteUnreachableVertices() throws Exception {
        List<Vertex> toDelete = new ArrayList<Vertex>();
        for (int i : vertices.keySet()) {
            List<Vertex> leaves = getMinimumPrerequisiteLeavesTo(vertices.get(i));
            if (leaves.size() == 0)
                toDelete.add(vertices.get(i));
        }
        if (toDelete.size() > 0) {
            for (Vertex aToDelete : toDelete) {
                this.deleteVertex(aToDelete);
            }
            deleteUnreachableVertices();
        }
    }

    /**
     * @param v    an attack graph vertex
     * @param type a datalog fact type (ex "hacl", "vulExists", ...)
     * @return the parent vertex of v with type "type" if it exists
     */
    public Vertex getParentOfVertexWithFactCommand(Vertex v, String type) {
        List<Vertex> parents = v.parents;
        for (Vertex parent : parents) {
            if (parent.fact != null && parent.fact.type == FactType.DATALOG_FACT && parent.fact.datalogCommand != null && parent.fact.datalogCommand.command.equals(type))
                return parent;
        }
        return null;
    }

    /**
     * @return the highest vertex id number
     */
    public int getHighestVertexId() {
        int max = 0;
        for (int i : vertices.keySet()) {
            if (i >= max)
                max = i;
        }
        return max;
    }

    /**
     * @return the dom element corresponding to this attack graph XML file
     */
    public Element toDomElement() {
        Element root = new Element("attack_graph");

        //arcs
        Element arcsElement = new Element("arcs");
        root.addContent(arcsElement);
        for (Arc arc : arcs) {
            Element arcElement = new Element("arc");
            arcsElement.addContent(arcElement);
            Element srcElement = new Element("src");
            srcElement.setText(arc.destination.id + "");
            arcElement.addContent(srcElement);
            Element dstElement = new Element("dst");
            dstElement.setText(arc.source.id + "");
            arcElement.addContent(dstElement);
        }

        //vertices
        Element verticesElement = new Element("vertices");
        root.addContent(verticesElement);
        for (int key : vertices.keySet()) {
            Vertex vertex = vertices.get(key);

            Element vertexElement = new Element("vertex");
            verticesElement.addContent(vertexElement);

            Element idElement = new Element("id");
            idElement.setText(vertex.id + "");
            vertexElement.addContent(idElement);

            Element factElement = new Element("fact");
            factElement.setText(vertex.fact.factString);
            vertexElement.addContent(factElement);

            Element metricElement = new Element("metric");
            metricElement.setText(vertex.mulvalMetric + "");
            vertexElement.addContent(metricElement);

            Element typeElement = new Element("type");
            typeElement.setText(vertex.type.toString().toUpperCase());
            vertexElement.addContent(typeElement);
        }

        return root;
    }

    /**
     * Save the attack graph in an xml file
     *
     * @param filePath the path in which the attack graph is saved
     * @throws Exception
     */
    public void saveToXmlFile(String filePath) throws Exception {
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        output.output(toDomElement(), new FileOutputStream(filePath));
    }

    /**
     * @return the list of possible attack paths
     * @throws Exception
     */
    public List<AttackPath> generateAttackPaths() throws Exception {
        List<AttackPath> result = new ArrayList<AttackPath>();

        List<Vertex> attackerGoals = new ArrayList<Vertex>();
        //Find attacker goals
        for (int i : vertices.keySet()) {
            Vertex vertex = vertices.get(i);
            Fact fact = vertex.fact;
            if (fact != null && fact.type == FactType.DATALOG_FACT) {
                DatalogCommand command = fact.datalogCommand;
                if (command != null && (command.command.equals("execCode") || command.command.equals("accessFile") || command.command.equals("principalCompromised"))) {
                    attackerGoals.add(vertex);
                }
            }
        }

        for (Vertex goal : attackerGoals) {
            result.addAll(this.getPossibleAttackPathsToGoTo(goal));
        }

        for (AttackPath aResult : result) {
            aResult.computeScoring();
        }
        System.out.println("Number of attack path :" + result.size());
        return result;
    }

    private List<AttackPath> getPossibleAttackPathsToGoTo(Vertex goal) throws Exception {
        return getPossibleAttackPathsToGoToRecursive(goal, new boolean[this.getHighestVertexId()]);
    }

    /**
     * @param v           the vertex
     * @param alreadySeen a boolean vector : true if the vertex as already been seen
     * @return the list of possible path attack path to access this vector
     * @throws Exception
     */
    private List<AttackPath> getPossibleAttackPathsToGoToRecursive(Vertex v, boolean[] alreadySeen) throws Exception {
        List<AttackPath> result = new ArrayList<AttackPath>();
        if (v.type == VertexType.LEAF && !alreadySeen[v.id - 1]) {
            AttackPath attackPath = new AttackPath();
            attackPath.vertices.put(v.id, v);
            result.add(attackPath);
        } else if (v.type == VertexType.OR && !alreadySeen[v.id - 1]) {
            v.computeParentsAndChildren(this);
            alreadySeen[v.id - 1] = true;
            for (int i = 0; i < v.parents.size(); i++) {
                List<AttackPath> res_parent = this.getPossibleAttackPathsToGoToRecursive(v.parents.get(i), alreadySeen);
                if (res_parent == null)
                    break;
                for (AttackPath parent : res_parent) {
                    parent.vertices.put(v.id, v);
                    parent.arcs.add(new Arc(v.parents.get(i), v));
                    result.add(parent);
                }
            }
            alreadySeen[v.id - 1] = false;
        } else if (v.type == VertexType.AND && !alreadySeen[v.id - 1]) {
            v.computeParentsAndChildren(this);
            alreadySeen[v.id - 1] = true;
            List<List<AttackPath>> result_all_parents = new ArrayList<List<AttackPath>>();
            for (int i = 0; i < v.parents.size(); i++) {
                List<AttackPath> res_parent = this.getPossibleAttackPathsToGoToRecursive(v.parents.get(i), alreadySeen);

                if (res_parent == null) {
                    alreadySeen[v.id - 1] = false;
                    return new ArrayList<AttackPath>();
                }
                for (AttackPath aRes_parent : res_parent) {
                    aRes_parent.vertices.put(v.id, v);
                    aRes_parent.arcs.add(new Arc(v.parents.get(i), v));
                }
                result_all_parents.add(res_parent);
            }
            result = computeAttackPathForAnANDVertex(result_all_parents, 0);
            alreadySeen[v.id - 1] = false;
        } else {
            return null;
        }
        return result;
    }

    /**
     * [OR] List<AttackPath>		[OR] List<AttackPath>			[OR] List<AttackPath>
     * PARENT1						PARENT2						   PARENT3
     * <p/>
     * AND LEAF : PARENT1.1 AND PARENT2.1 AND PARENT 3.1
     * OR PARENT 1.2 AND PARENT2.1 AND PARENT3.A
     * OR ....
     *
     * @param parentsAttackPathList the list of list of possible attack path of parents of a "AND" node in the attack graph :
     * @param indexInPath           the index if this list
     * @return the list of possible attack path
     */
    private List<AttackPath> computeAttackPathForAnANDVertex(List<List<AttackPath>> parentsAttackPathList, int indexInPath) {
        if (indexInPath > parentsAttackPathList.size() - 1) { //path empty
            return null;
        } else if (indexInPath == parentsAttackPathList.size() - 1) { //one parent remaining
            return parentsAttackPathList.get(indexInPath);
        } else { //more than one parent remaining
            List<AttackPath> currentAttackPathList = parentsAttackPathList.get(indexInPath);

            List<AttackPath> result_without_last_leaf = computeAttackPathForAnANDVertex(parentsAttackPathList, indexInPath + 1);

            List<AttackPath> result = new ArrayList<AttackPath>();

            for (AttackPath resultWithoutLastLeaf : result_without_last_leaf) {
                for (AttackPath aCurrentAttackPathList : currentAttackPathList) {
                    AttackPath newAttackPath = new AttackPath();
                    newAttackPath.vertices.putAll(resultWithoutLastLeaf.vertices);
                    newAttackPath.vertices.putAll(aCurrentAttackPathList.vertices);

                    newAttackPath.arcs.addAll(resultWithoutLastLeaf.arcs);
                    newAttackPath.arcs.addAll(aCurrentAttackPathList.arcs);
                    result.add(newAttackPath);
                }

            }

            return result;

        }
    }

    @Override
    public AttackGraph clone() throws CloneNotSupportedException {
        AttackGraph copie = (AttackGraph) super.clone();

        //Copie the vertices

        copie.vertices = new HashMap<Integer, Vertex>();
        for (Integer i : this.vertices.keySet()) {
            copie.vertices.put(i, this.vertices.get(i).clone());
        }

        copie.arcs = new ArrayList<Arc>();

        //Change all the vertices references in the arcs
        for (int i = 0; i < this.arcs.size(); i++) {
            Vertex destination = copie.vertices.get(this.arcs.get(i).destination.id);
            Vertex source = copie.vertices.get(this.arcs.get(i).source.id);
            Arc arc = new Arc(source, destination);
            copie.arcs.add(arc);
        }


        //change all the references in the vertices
        for (Integer i : copie.vertices.keySet()) {
            Vertex copieVertex = copie.vertices.get(i);
            copieVertex.computeParentsAndChildren(copie);
        }

        return copie;
    }

    @Override
    public String toString() {
        String result = "";

        result += "\nVertices = \n";
        for (Integer key : vertices.keySet()) {
            result += vertices.get(key) + "\n";
        }

        result += "AttackGraph : \n Arcs=\n";
        for (Arc arc : arcs) {
            result += arc + "\n";
        }

        return result;
    }

    /**
     * @param outputPath the path in which the XML attack paths are saved
     * @return The list of attack path extracted from this attack graph
     * @throws Exception
     */
    public List<AttackPath> scoreAttackGraphAndGetAttackPaths(String outputPath, double previousMaxScore) throws Exception {
        double[] vertexIDTable = new double[this.getNumberOfVertices()];
        String[] vertexFactTable = new String[this.getNumberOfVertices()];
        double[] vertexMulvalMetricTable = new double[this.getNumberOfVertices()];
        String[] vertexTypeTable = new String[this.getNumberOfVertices()];

        double[] arcSrcTable = new double[this.arcs.size()];
        double[] arcDstTable = new double[this.arcs.size()];
        ImpactMetric[][] impactMetrics = new ImpactMetric[this.getNumberOfVertices()][];

        int i = 0;
        System.out.println("Generate input for scoring function");
        for (Integer key : this.vertices.keySet()) {
            Vertex vertex = this.vertices.get(key);

            vertexIDTable[i] = vertex.id;
            vertexFactTable[i] = vertex.fact.factString;
            vertexMulvalMetricTable[i] = vertex.mulvalMetric;
            vertexTypeTable[i] = vertex.type.toString().toUpperCase();
            impactMetrics[i] = new ImpactMetric[vertex.impactMetrics.size()];
            for(int j = 0; j < vertex.impactMetrics.size() ; j++) {
                impactMetrics[i][j] = vertex.impactMetrics.get(j);
            }

            i++;
        }

        for (int j = 0; j < this.arcs.size(); j++) {
            Arc arc = this.arcs.get(j);
            arcDstTable[j] = arc.source.id;
            arcSrcTable[j] = arc.destination.id;
        }
        System.out.println("Compute global score and compute attack paths");
        this.globalScore = Launch.main(vertexIDTable, vertexFactTable, vertexMulvalMetricTable, vertexTypeTable,
                arcSrcTable, arcDstTable, impactMetrics, outputPath, previousMaxScore);

        return AttackPath.loadAttackPathsFromFile(outputPath, this);
    }

    /**
     * Browse all vertices and check if the vertex can have a metric (is an execCode)
     *
     * @param informationSystem the information system
     * @throws Exception
     */
    public void loadMetricsFromTopology(InformationSystem informationSystem) throws Exception {
        for (Integer key : vertices.keySet()) {
            Vertex vertex = vertices.get(key);
            if (vertex.fact != null && vertex.fact.type == FactType.DATALOG_FACT && vertex.fact.datalogCommand.command.equals("execCode")) {
                //We are in an execCode
                String hostName = vertex.fact.datalogCommand.params[0];
                if (hostName != null && !hostName.isEmpty()) {
                    InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(hostName);
                    if (host != null) {
                        ImpactMetric metric = new ImpactMetric(host.getMetric(), 1);
                        vertex.impactMetrics.add(metric);
                    }
                }

            }
        }
    }

    /**
     * @param is the information system
     * @return the security requirements impacted by this attack path
     * @throws Exception
     */
    public List<SecurityRequirement> computeRelatedImactedSecurityRequirements(InformationSystem is) throws Exception {
        List<SecurityRequirement> impactedRequirements = new ArrayList<SecurityRequirement>();

        for (int i : this.vertices.keySet()) {
            Vertex vertex = this.vertices.get(i);
            if (vertex.fact != null && vertex.fact.type == FactType.DATALOG_FACT) {
                DatalogCommand command = vertex.fact.datalogCommand;
                if (command.command.equals("execCode")) {
                    String machineName = command.params[0];
                    InformationSystemHost machine = is.existingMachineByNameOrIPAddress(machineName);
                    if (machine != null) {
                        for (int j = 0; j < machine.getSecurityRequirements().size(); j++) {
                            SecurityRequirement secReq = machine.getSecurityRequirements().get(j);
                            if (!impactedRequirements.contains(secReq)) {
                                impactedRequirements.add(secReq);
                            }
                        }
                    }
                }

            }
        }

        return impactedRequirements;

    }

    /**
     * @param informationSystem the information system
     * @return The topology Graph associated to this attack path
     * @throws Exception
     */
    public InformationSystemGraph getRelatedTopologyGraph(InformationSystem informationSystem) throws Exception {
        InformationSystemGraph result = new InformationSystemGraph();

        List<Vertex> vertices = new ArrayList<Vertex>(this.vertices.values());
        for (Vertex vertex : vertices) {
            if (vertex.fact.type == FactType.DATALOG_FACT && vertex.fact.datalogCommand != null) {
                DatalogCommand command = vertex.fact.datalogCommand;
                switch (command.command) {
                    case "hacl":
                        InformationSystemGraphVertex from = null;
                        InformationSystemGraphVertex to = null;
                        String relatedVulneravility = null;
                        if (command.params[0].equals("internet") || command.params[0].equals("1.1.1.1") || command.params[0].equals("internet_host")) {
                            from = result.getMachineVertex(informationSystem.getHostByNameOrIPAddress("internet_host"));
                        } else {
                            InformationSystemHost machine = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                            if (machine != null) {
                                from = result.getMachineVertex(machine);
                            }
                        }
                        if (command.params[1].equals("internet") || command.params[1].equals("1.1.1.1"))
                            to = result.getMachineVertex(informationSystem.getHostByNameOrIPAddress("1.1.1.1"));
                        else {
                            InformationSystemHost machine = informationSystem.getHostByNameOrIPAddress(command.params[1]);
                            if (machine != null) {
                                to = result.getMachineVertex(machine);
                            }
                        }
                        if (from != null && to != null) {
                            InformationSystemGraphArc arc = new InformationSystemGraphArc();
                            arc.setSource(from);
                            arc.setDestination(to);
                            vertex.computeParentsAndChildren(this);
                            //Try to find (if applicable) the related vulnerability
                            Vertex directAccessChild = vertex.childOfType(true, "direct network access");
                            if (directAccessChild == null) {
                                directAccessChild = vertex.childOfType(true, "multi-hop access");
                            }
                            if (directAccessChild != null) {
                                directAccessChild.computeParentsAndChildren(this);
                                Vertex netAccessChild = directAccessChild.childOfType(false, "netAccess");
                                if (netAccessChild != null) {
                                    netAccessChild.computeParentsAndChildren(this);
                                    Vertex remoteExploitChild = netAccessChild.childOfType(true, "remote exploit of a server program");
                                    if (remoteExploitChild != null) {
                                        remoteExploitChild.computeParentsAndChildren(this);
                                        Vertex vulnExistParent = remoteExploitChild.parentOfType(false, "vulExists");
                                        if (vulnExistParent != null && vulnExistParent.fact.datalogCommand.params.length > 2) {
                                            relatedVulneravility = vulnExistParent.fact.datalogCommand.params[1];
                                        }
                                    }
                                }

                            }

                            if (relatedVulneravility != null)
                                arc.setRelatedVulnerability(relatedVulneravility);

                            if (!result.getArcs().contains(arc))
                                result.getArcs().add(arc);
                        }
                        break;
                    case "attackerLocated":
                        InformationSystemGraphVertex attackerVertex = null;
                        if (command.params[0].equals("internet") || command.params[0].equals("1.1.1.1"))
                            attackerVertex = result.getMachineVertex(informationSystem.getHostByNameOrIPAddress("1.1.1.1"));
                        else {
                            InformationSystemHost machine = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                            if (machine != null) {
                                attackerVertex = result.getMachineVertex(machine);
                            }
                        }
                        if (attackerVertex != null)
                            attackerVertex.setMachineOfAttacker(true);
                        break;
                    case "vulExists":
                        InformationSystemHost machine = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        if (machine != null) {
                            result.getMachineVertex(machine).setCompromised(true);
                        }
                        break;
                }
            }
        }

        return result;
    }
}
