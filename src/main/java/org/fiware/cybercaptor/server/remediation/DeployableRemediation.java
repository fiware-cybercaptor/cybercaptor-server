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
package org.fiware.cybercaptor.server.remediation;

import org.fiware.cybercaptor.server.attackgraph.AttackPath;
import org.fiware.cybercaptor.server.attackgraph.serializable.SerializableAttackPath;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.remediation.serializable.SerializableDeployableRemediation;
import org.jdom2.Element;

import java.io.*;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class representing a deployable remediation = a list of {@link DeployableRemediationAction}
 * (remediations that can be deployed on a host) with a cost.
 *
 * @author Francois -Xavier Aguessy
 */
public class DeployableRemediation {
    /**
     * The actions of the deployable remediation
     */
    private List<DeployableRemediationAction> actions = new ArrayList<DeployableRemediationAction>();

    /**
     * The cost of the deployable remediation
     */
    private double cost = 0;

    /**
     * The corrected attack path
     */
    private AttackPath correctedPath;

    /**
     * The information system
     */
    private InformationSystem informationSystem;

    /**
     * Create a deployable remediation with the attack path it is correcting
     *
     * @param correctedPath the corrected attack path.
     */

    public DeployableRemediation(AttackPath correctedPath, InformationSystem informationSystem) {
        this.correctedPath = correctedPath;
        this.informationSystem = informationSystem;
    }

    /**
     * Compute the cost of the deployable list of remediations
     *
     * @return the cost of this deployable remediation
     * @throws Exception the exception
     */
    public double computeCost() throws Exception {
        if (getCost() == 0) {
            for (int i = 0; i < getActions().size(); i++) {
                setCost(getCost() + getActions().get(i).getRemediationAction().getOperationalCost());
            }
        }
        return getCost();
    }

    /**
     * To XML element.
     *
     * @return the dom element corresponding to this deployable remediation
     */
    public Element toXMLElement() {
        Element root = new Element("remediation");

        Element costElement = new Element("cost");
        costElement.setText(this.getCost() + "");
        root.addContent(costElement);

        Element habitIndexElement = new Element("habit_index");
        habitIndexElement.setText(this.getHabitIndex() + "");
        root.addContent(habitIndexElement);

        //actions
        Element actionsElement = new Element("remediation_actions");
        root.addContent(actionsElement);
        for (int i = 0; i < getActions().size(); i++) {
            DeployableRemediationAction action = getActions().get(i);

            actionsElement.addContent(action.toXMLElement());
        }

        return root;
    }

    private double getHabitIndex() {
        Logger.getAnonymousLogger().log(Level.INFO, this.actions.toString() + " has been validated to correct the path.");
        String remediationsHistoryPath = ProjectProperties.getProperty("remediations-history-path");
        if (remediationsHistoryPath == null || remediationsHistoryPath.isEmpty()) {
            Logger.getAnonymousLogger().log(Level.WARNING, "The remediations-history-path has not been set" +
                    ", the remediation history will not be kept.");
            return 0;
        }
        double habitIndex = 0;

        //Load the remediations history
        File remediationsHistoryFile = new File(remediationsHistoryPath);
        List<AbstractMap.SimpleEntry<SerializableAttackPath, SerializableDeployableRemediation>> attackPathsRemediations;
        if (remediationsHistoryFile.exists()) {
            ObjectInputStream ois;
            try {
                ois = new ObjectInputStream(new FileInputStream(remediationsHistoryPath));
                attackPathsRemediations = (List<AbstractMap.SimpleEntry<SerializableAttackPath, SerializableDeployableRemediation>>) ois.readObject();
                for (AbstractMap.SimpleEntry<SerializableAttackPath, SerializableDeployableRemediation> attackPathRemediation : attackPathsRemediations) {
                    SerializableAttackPath serializableAttackPath = attackPathRemediation.getKey();
                    SerializableDeployableRemediation serializableRemediation = attackPathRemediation.getValue();
                    if (serializableAttackPath.isSimilarTo(new SerializableAttackPath(correctedPath, informationSystem)) && serializableRemediation.isSimilarTo(this))
                        habitIndex++;
                }
                return habitIndex;
            } catch (Exception e) {
                Logger.getAnonymousLogger().log(Level.WARNING, "Error while loading the remediation history: " + e.getMessage());
            }
        } else {
            return 0;
        }
        return 0;
    }

    /**
     * The list of deployable actions (one action on one machine)
     *
     * @return the actions
     */
    public List<DeployableRemediationAction> getActions() {
        return actions;
    }

    /**
     * Sets actions.
     *
     * @param actions the actions
     */
    public void setActions(List<DeployableRemediationAction> actions) {
        this.actions = actions;
    }

    /**
     * The cost of deploying all these actions
     *
     * @return the cost
     */
    public double getCost() {
        return cost;
    }

    /**
     * Sets cost.
     *
     * @param cost the cost
     */
    public void setCost(double cost) {
        this.cost = cost;
    }

    /**
     * Validate that this remediation has been applied to be taken into account
     * in the remediation automation.
     */
    public void validate(InformationSystem informationSystem) throws Exception {
        Logger.getAnonymousLogger().log(Level.INFO, this.actions.toString() + " has been validated to correct the path.");
        String remediationsHistoryPath = ProjectProperties.getProperty("remediations-history-path");
        if (remediationsHistoryPath == null || remediationsHistoryPath.isEmpty()) {
            Logger.getAnonymousLogger().log(Level.WARNING, "The remediations-history-path has not been set" +
                    ", the remediation history will not be kept.");
            return;
        }

        //Load the remediations history
        File remediationsHistoryFile = new File(remediationsHistoryPath);
        List<AbstractMap.SimpleEntry<SerializableAttackPath, SerializableDeployableRemediation>> attackPathsRemediations;
        if (remediationsHistoryFile.exists()) {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(remediationsHistoryPath));
            attackPathsRemediations = (List<AbstractMap.SimpleEntry<SerializableAttackPath, SerializableDeployableRemediation>>) ois.readObject();
        } else {
            attackPathsRemediations = new ArrayList<AbstractMap.SimpleEntry<SerializableAttackPath, SerializableDeployableRemediation>>();
        }
        Logger.getAnonymousLogger().log(Level.INFO, attackPathsRemediations.size() + " remediated paths in the history file.");

        //Add the current remediation + attack path to the history
        SerializableAttackPath serializableAttackPath = new SerializableAttackPath(this.correctedPath, informationSystem);
        SerializableDeployableRemediation serializableRemediation = new SerializableDeployableRemediation(this);
        attackPathsRemediations.add(new AbstractMap.SimpleEntry<SerializableAttackPath, SerializableDeployableRemediation>(serializableAttackPath, serializableRemediation));

        //Save to the remediations history file
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(remediationsHistoryFile));
        oos.writeObject(attackPathsRemediations);
    }
}


