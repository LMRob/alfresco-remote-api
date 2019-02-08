/*
 * #%L
 * Alfresco Repository WAR Community
 * %%
 * Copyright (C) 2005 - 2016 Alfresco Software Limited
 * %%
 * This file is part of the Alfresco software. 
 * If the software was purchased under a paid Alfresco license, the terms of 
 * the paid license agreement will prevail.  Otherwise, the software is 
 * provided under the following open source license terms:
 * 
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */
package org.apache.log4j;

import org.apache.log4j.PatternLayout;
import org.apache.log4j.spi.LoggingEvent;
import org.owasp.esapi.ESAPI;
/**
 * Custom Log Pattern Layout to neutralize logs
 * 
 * MNT-20199 Improper Output Neutralization for Logs CWE ID 117
 * Creator: aioobe (https://stackoverflow.com/questions/30912182/how-to-resolve-cwe-117-issue )
 * LM_2019-01-30
 * */

public class NewLinePatternLayout extends PatternLayout {

	public NewLinePatternLayout() { }

    public NewLinePatternLayout(String pattern) {
        super(pattern);
    }
    
    public String format(LoggingEvent event) {
        String original = super.format(event);

        // ensure no CRLF injection into logs for forging records
        String clean = original.replace('\n', '_').replace('\r', '_');
        if (ESAPI.securityConfiguration().getLogEncodingRequired()) {
        	//Encode data for use in HTML using HTML entity encoding
            clean = ESAPI.encoder().encodeForHTML(clean);
        }
        //insert new line for better readability of the logs
        StringBuilder sb = new StringBuilder(clean + "\n");

        return sb.toString();
    }
}
