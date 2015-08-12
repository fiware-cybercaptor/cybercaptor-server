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

package org.fiware.cybercaptor.server.attackgraph.fact;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class that represent a muval attack graph vertex containing a "RULE"
 * @author Francois-Xavier Aguessy
 */
public class Rule implements Cloneable{

	static Pattern pattern = Pattern.compile("^RULE (\\d+) \\((.*)\\)$");
	/**
	 * The text of the rule
	 */
	public String ruleText = "";
	/**
	 * The number of the rule
	 */
	int number = 0;
	
	/**
	 * Create a rule from a fact string
	 * @param fact the fact string
	 */
	public Rule(String fact) {
		Matcher matcherRule = pattern.matcher(fact);
		if(matcherRule.matches()) {
			this.number = Integer.parseInt(matcherRule.group(1));
			this.ruleText = matcherRule.group(2);
		}
	}
	
	/**
	 * Check if a fact string is a rule
	 * @param fact the fact string
	 * @return true if the fact string is a rule else false
	 */
	public static boolean isARule(String fact) {
		Matcher matcherRule = pattern.matcher(fact);
		return matcherRule.matches();
	}

	@Override
	public Rule clone() throws CloneNotSupportedException {
		Rule copie = (Rule)super.clone();

		return copie;
	}

	@Override
	public String toString() {
		return "Rule [number=" + number + ", ruleText=" + ruleText + "]";
	}
}
