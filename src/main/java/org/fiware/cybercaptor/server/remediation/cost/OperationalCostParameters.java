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

package org.fiware.cybercaptor.server.remediation.cost;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

import java.io.FileInputStream;
import java.io.FileOutputStream;


/**
 * Class that represents the remediation operational cost parameters (direct cost to deploy the deployable remediation)
 * there is a global OperationalCostsParameters for each remediation type, but it can also be customised for each remediation
 *
 * @author Francois -Xavier Aguessy
 */
public class OperationalCostParameters {
    /**
     * The average cost of the remediation
     */
    private double remediationCost = 0;
    /**
     * The duration of testing if all business applications are still working
     */
    private double businessApplicationsTestsDuration = 0;

    /**
     * The middle cost of 1 hour of work
     */
    private double workCost = 0;

    /**
     * The cost of 1Ghz during 1 year
     */
    private double computationPowerCost = 0;

    /**
     * The cost of 1Go during 1 year
     */
    private double storageCost = 0;

    /**
     * The duration of the deployment of the remediation
     */
    private double deploymentDuration = 0;

    /**
     * The duration of uninstalling a remediation on the test machine
     */
    private double remediationUninstallDuration = 0;

    /**
     * The duraction of unavailibility of the service during the deployment of the remediation
     */
    private double serviceUnavailabilityDeploymentDuration = 0;

    /**
     * The cost of restarting the service used by the remediation
     */
    private double restartCost = 0;

    /**
     * The duration of to restart the service used by the remediation
     */
    private double restartDuration = 0;

    /**
     * The power in Ghz used to maintain the remediation, during 1 year
     */
    private double usedPower = 0;

    /**
     * The storage in Go used to maintain the remediation, during 1 year
     */
    private double usedStorage = 0;

    /**
     * The maintenance duration during one year (contains the time to process the data produced by the remediation)
     */
    private double maintenanceDuration = 0;

    /**
     * A rate that represents the skill necessary to test the business applications
     */
    private double skillRateTests = 1;

    /**
     * A rate that represents the skill necessary to deploy the remediation
     */
    private double skillRateDeployment = 1;

    /**
     * A rate that represents the skill necessary to maintain the remediation
     */
    private double skillRateMaintenance = 1;

    /**
     * Gets remediation cost.
     *
     * @return the remediation cost
     */
    public double getRemediationCost() {
        return remediationCost;
    }

    /**
     * Sets remediation cost.
     *
     * @param remediationCost the remediation cost
     */
    public void setRemediationCost(double remediationCost) {
        this.remediationCost = remediationCost;
    }

    /**
     * Gets business applications tests duration.
     *
     * @return the business applications tests duration
     */
    public double getBusinessApplicationsTestsDuration() {
        return businessApplicationsTestsDuration;
    }

    /**
     * Sets business applications tests duration.
     *
     * @param businessApplicationsTestsDuration the business applications tests duration
     */
    public void setBusinessApplicationsTestsDuration(
            double businessApplicationsTestsDuration) {
        this.businessApplicationsTestsDuration = businessApplicationsTestsDuration;
    }

    /**
     * Gets work cost.
     *
     * @return the work cost
     */
    public double getWorkCost() {
        return workCost;
    }

    /**
     * Sets work cost.
     *
     * @param workCost the work cost
     */
    public void setWorkCost(double workCost) {
        this.workCost = workCost;
    }

    /**
     * Gets computation power cost.
     *
     * @return the computation power cost
     */
    public double getComputationPowerCost() {
        return computationPowerCost;
    }

    /**
     * Sets computation power cost.
     *
     * @param computationPowerCost the computation power cost
     */
    public void setComputationPowerCost(double computationPowerCost) {
        this.computationPowerCost = computationPowerCost;
    }

    /**
     * Gets storage cost.
     *
     * @return the storage cost
     */
    public double getStorageCost() {
        return storageCost;
    }

    /**
     * Sets storage cost.
     *
     * @param storageCost the storage cost
     */
    public void setStorageCost(double storageCost) {
        this.storageCost = storageCost;
    }

    /**
     * Gets deployment duration.
     *
     * @return the deployment duration
     */
    public double getDeploymentDuration() {
        return deploymentDuration;
    }

    /**
     * Sets deployment duration.
     *
     * @param deploymentDuration the deployment duration
     */
    public void setDeploymentDuration(double deploymentDuration) {
        this.deploymentDuration = deploymentDuration;
    }

    /**
     * Gets remediation uninstall duration.
     *
     * @return the remediation uninstall duration
     */
    public double getRemediationUninstallDuration() {
        return remediationUninstallDuration;
    }

    /**
     * Sets remediation uninstall duration.
     *
     * @param remediationUninstallDuration the remediation uninstall duration
     */
    public void setRemediationUninstallDuration(double remediationUninstallDuration) {
        this.remediationUninstallDuration = remediationUninstallDuration;
    }

    /**
     * Gets service unavailability deployment duration.
     *
     * @return the service unavailability deployment duration
     */
    public double getServiceUnavailabilityDeploymentDuration() {
        return serviceUnavailabilityDeploymentDuration;
    }

    /**
     * Sets service unavailability deployment duration.
     *
     * @param serviceUnavailabilityDeploymentDuration the service unavailability deployment duration
     */
    public void setServiceUnavailabilityDeploymentDuration(
            double serviceUnavailabilityDeploymentDuration) {
        this.serviceUnavailabilityDeploymentDuration = serviceUnavailabilityDeploymentDuration;
    }

    /**
     * Gets restart cost.
     *
     * @return the restart cost
     */
    public double getRestartCost() {
        return restartCost;
    }

    /**
     * Sets restart cost.
     *
     * @param restartCost the restart cost
     */
    public void setRestartCost(double restartCost) {
        this.restartCost = restartCost;
    }

    /**
     * Gets restart duration.
     *
     * @return the restart duration
     */
    public double getRestartDuration() {
        return restartDuration;
    }

    /**
     * Sets restart duration.
     *
     * @param restartDuration the restart duration
     */
    public void setRestartDuration(double restartDuration) {
        this.restartDuration = restartDuration;
    }

    /**
     * Gets used power.
     *
     * @return the used power
     */
    public double getUsedPower() {
        return usedPower;
    }

    /**
     * Sets used power.
     *
     * @param usedPower the used power
     */
    public void setUsedPower(double usedPower) {
        this.usedPower = usedPower;
    }

    /**
     * Gets used storage.
     *
     * @return the used storage
     */
    public double getUsedStorage() {
        return usedStorage;
    }

    /**
     * Sets used storage.
     *
     * @param usedStorage the used storage
     */
    public void setUsedStorage(double usedStorage) {
        this.usedStorage = usedStorage;
    }

    /**
     * Gets maintenance duration.
     *
     * @return the maintenance duration
     */
    public double getMaintenanceDuration() {
        return maintenanceDuration;
    }

    /**
     * Sets maintenance duration.
     *
     * @param maintenanceDuration the maintenance duration
     */
    public void setMaintenanceDuration(double maintenanceDuration) {
        this.maintenanceDuration = maintenanceDuration;
    }

    /**
     * Gets skill rate tests.
     *
     * @return the skill rate tests
     */
    public double getSkillRateTests() {
        return skillRateTests;
    }

    /**
     * Sets skill rate tests.
     *
     * @param skillRateTests the skill rate tests
     */
    public void setSkillRateTests(double skillRateTests) {
        this.skillRateTests = skillRateTests;
    }

    /**
     * Gets skill rate deployment.
     *
     * @return the skill rate deployment
     */
    public double getSkillRateDeployment() {
        return skillRateDeployment;
    }

    /**
     * Sets skill rate deployment.
     *
     * @param skillRateDeployment the skill rate deployment
     */
    public void setSkillRateDeployment(double skillRateDeployment) {
        this.skillRateDeployment = skillRateDeployment;
    }

    /**
     * Gets skill rate maintenance.
     *
     * @return the skill rate maintenance
     */
    public double getSkillRateMaintenance() {
        return skillRateMaintenance;
    }

    /**
     * Sets skill rate maintenance.
     *
     * @param skillRateMaintenance the skill rate maintenance
     */
    public void setSkillRateMaintenance(double skillRateMaintenance) {
        this.skillRateMaintenance = skillRateMaintenance;
    }

    /**
     * Function used to save the parameters in an xml file
     *
     * @param path the path where the xml file should be created
     * @throws Exception the exception
     */
    public void saveToXMLFile(String path) throws Exception {
        Element root = new Element("operational_costs_parameters");
        Document document = new Document(root);

        //businessApplicationsTestsDuration
        Element businessApplicationsTestsDurationElement = new Element("businessApplicationsTestsDuration");
        businessApplicationsTestsDurationElement.setText(getBusinessApplicationsTestsDuration() + "");
        root.addContent(businessApplicationsTestsDurationElement);

        //workCost
        Element workCostElement = new Element("workCost");
        workCostElement.setText(getWorkCost() + "");
        root.addContent(workCostElement);

        //remediationCost
        Element remediationCostElement = new Element("remediationCost");
        remediationCostElement.setText(getRemediationCost() + "");
        root.addContent(remediationCostElement);

        //computationPowerCost
        Element computationPowerCostElement = new Element("computationPowerCost");
        computationPowerCostElement.setText(getComputationPowerCost() + "");
        root.addContent(computationPowerCostElement);

        //storageCost
        Element storageCostElement = new Element("storageCost");
        storageCostElement.setText(getStorageCost() + "");
        root.addContent(storageCostElement);

        //deploymentDuration
        Element deploymentDurationElement = new Element("deploymentDuration");
        deploymentDurationElement.setText(getDeploymentDuration() + "");
        root.addContent(deploymentDurationElement);

        //remediationUninstallDuration
        Element remediationUninstallDurationElement = new Element("remediationUninstallDuration");
        remediationUninstallDurationElement.setText(getRemediationUninstallDuration() + "");
        root.addContent(remediationUninstallDurationElement);

        //serviceUnavailabilityDeploymentDuration
        Element serviceUnavailabilityDeploymentDurationElement = new Element("serviceUnavailabilityDeploymentDuration");
        serviceUnavailabilityDeploymentDurationElement.setText(getServiceUnavailabilityDeploymentDuration() + "");
        root.addContent(serviceUnavailabilityDeploymentDurationElement);


        //restartCost
        Element restartCostElement = new Element("restartCost");
        restartCostElement.setText(getRestartCost() + "");
        root.addContent(restartCostElement);

        //restartDuration
        Element restartDurationElement = new Element("restartDuration");
        restartDurationElement.setText(getRestartDuration() + "");
        root.addContent(restartDurationElement);

        //usedPower
        Element usedPowerElement = new Element("usedPower");
        usedPowerElement.setText(getUsedPower() + "");
        root.addContent(usedPowerElement);

        //usedStorage
        Element usedStorageElement = new Element("usedStorage");
        usedStorageElement.setText(getUsedStorage() + "");
        root.addContent(usedStorageElement);

        //maintenanceDuration
        Element maintenanceDurationElement = new Element("maintenanceDuration");
        maintenanceDurationElement.setText(getMaintenanceDuration() + "");
        root.addContent(maintenanceDurationElement);

        //skillRateTests
        Element skillRateTestsElement = new Element("skillRateTests");
        skillRateTestsElement.setText(getSkillRateTests() + "");
        root.addContent(skillRateTestsElement);

        //skillRateDeployment
        Element skillRateDeploymentElement = new Element("skillRateDeployment");
        skillRateDeploymentElement.setText(getSkillRateDeployment() + "");
        root.addContent(skillRateDeploymentElement);

        //skillRateMaintenance
        Element skillRateMaintenanceElement = new Element("skillRateMaintenance");
        skillRateMaintenanceElement.setText(getSkillRateMaintenance() + "");
        root.addContent(skillRateMaintenanceElement);

        //Save the DOM element in file
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        output.output(document, new FileOutputStream(path));
    }

    /**
     * Function used to load the parameters from an xml file
     *
     * @param path the path where the xml file is stored
     * @throws Exception the exception
     */
    public void loadFromXMLFile(String path) throws Exception {
        FileInputStream file = new FileInputStream(path);
        SAXBuilder sxb = new SAXBuilder();
        Document document = sxb.build(file);
        Element root = document.getRootElement();

        //remediationCost
        Element remediationCostElement = root.getChild("remediationCost");
        if (remediationCostElement != null)
            setRemediationCost(Double.parseDouble(remediationCostElement.getText()));

        //businessApplicationsTestsDuration
        Element businessApplicationsTestsDurationElement = root.getChild("businessApplicationsTestsDuration");
        if (businessApplicationsTestsDurationElement != null)
            setBusinessApplicationsTestsDuration(Double.parseDouble(businessApplicationsTestsDurationElement.getText()));

        //workCost
        Element workCostElement = root.getChild("workCost");
        if (workCostElement != null)
            setWorkCost(Double.parseDouble(workCostElement.getText()));

        //computationPowerCost
        Element computationPowerCostElement = root.getChild("computationPowerCost");
        if (computationPowerCostElement != null)
            setComputationPowerCost(Double.parseDouble(computationPowerCostElement.getText()));

        //storageCost
        Element storageCostElement = root.getChild("storageCost");
        if (storageCostElement != null)
            setStorageCost(Double.parseDouble(storageCostElement.getText()));

        //deploymentDuration
        Element deploymentDurationElement = root.getChild("deploymentDuration");
        if (deploymentDurationElement != null)
            setDeploymentDuration(Double.parseDouble(deploymentDurationElement.getText()));

        //remediationUninstallDuration
        Element remediationUninstallDurationElement = root.getChild("remediationUninstallDuration");
        if (remediationUninstallDurationElement != null)
            setRemediationUninstallDuration(Double.parseDouble(remediationUninstallDurationElement.getText()));

        //serviceUnavailabilityDeploymentDuration
        Element serviceUnavailabilityDeploymentDurationElement = root.getChild("serviceUnavailabilityDeploymentDuration");
        if (serviceUnavailabilityDeploymentDurationElement != null)
            setServiceUnavailabilityDeploymentDuration(Double.parseDouble(serviceUnavailabilityDeploymentDurationElement.getText()));


        //restartCost
        Element restartCostElement = root.getChild("restartCost");
        if (restartCostElement != null)
            setRestartCost(Double.parseDouble(restartCostElement.getText()));

        //restartDuration
        Element restartDurationElement = root.getChild("restartDuration");
        if (restartDurationElement != null)
            setRestartDuration(Double.parseDouble(restartDurationElement.getText()));

        //usedPower
        Element usedPowerElement = root.getChild("usedPower");
        if (usedPowerElement != null)
            setUsedPower(Double.parseDouble(usedPowerElement.getText()));

        //usedStorage
        Element usedStorageElement = root.getChild("usedStorage");
        if (usedStorageElement != null)
            setUsedStorage(Double.parseDouble(usedStorageElement.getText()));

        //maintenanceDuration
        Element maintenanceDurationElement = root.getChild("maintenanceDuration");
        if (maintenanceDurationElement != null)
            setMaintenanceDuration(Double.parseDouble(maintenanceDurationElement.getText()));

        //skillRateTests
        Element skillRateTestsElement = root.getChild("skillRateTests");
        if (skillRateTestsElement != null)
            setSkillRateTests(Double.parseDouble(skillRateTestsElement.getText()));

        //skillRateDeployment
        Element skillRateDeploymentElement = root.getChild("skillRateDeployment");
        if (skillRateDeploymentElement != null)
            setSkillRateDeployment(Double.parseDouble(skillRateDeploymentElement.getText()));

        //skillRateMaintenance
        Element skillRateMaintenanceElement = root.getChild("skillRateMaintenance");
        if (skillRateMaintenanceElement != null)
            setSkillRateMaintenance(Double.parseDouble(skillRateMaintenanceElement.getText()));

    }
}
