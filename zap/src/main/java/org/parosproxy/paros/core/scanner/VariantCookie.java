/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.parosproxy.paros.core.scanner;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

import net.sf.json.JSONObject;

/**
 * A {@code Variant} for Cookie headers, allowing to attack the names and values of the cookies.
 *
 * @author andy
 * @see Variant
 */
public class VariantCookie implements Variant {

    private List<NameValuePair> params = Collections.emptyList();

    private boolean encodeCookieValues;

    private static final String SHORT_NAME = "cookie";

    public VariantCookie() {}

    public VariantCookie(boolean encodeCookieValues) {
        this.encodeCookieValues = encodeCookieValues;
    }

    @Override
    public String getShortName() {
        return SHORT_NAME;
    }

    /**
     * @throws IllegalArgumentException if {@code message} is {@code null}.
     */
    @Override
    public void setMessage(HttpMessage message) {
        if (message == null) {
            throw new IllegalArgumentException("Parameter message must not be null.");
        }

        List<String> cookieLines = message.getRequestHeader().getHeaderValues(HttpHeader.COOKIE);
        if (cookieLines.isEmpty()) {
            params = Collections.emptyList();
            return;
        }

        ArrayList<NameValuePair> extractedParameters = new ArrayList<>();
        for (String cookieLine : cookieLines) {
            if (cookieLine.trim().isEmpty()) {
                continue;
            }

            String[] cookieArray = cookieLine.split("; ?");
            for (String cookie : cookieArray) {
                String[] nameValuePair = cookie.split("=", 2);
                boolean hasNameValuePair = nameValuePair.length == 2;
                String name = hasNameValuePair ? nameValuePair[0] : null;
                String value =
                        getUnescapedValue(!hasNameValuePair ? nameValuePair[0] : nameValuePair[1]);
                String originalValue = value;

				String testValue = value;

                try {
					testValue = new String(Base64.getDecoder().decode(value));
				} catch (Exception e) {
					// Ignore - just means its not base64 encoded
				}

                // TODO
                try {
					JSONObject json = JSONObject.fromObject(testValue);
					System.out.println("SBSB got json from cookie " + name + 
							" " + json.toString()); // TODO
					
					// Its JSON structured data
					for (Object key : json.keySet()) {
						System.out.println("SBSB adding key " + name + 
								":" + key); // TODO
		                extractedParameters.add(
		                        new NameValuePair(
		                                NameValuePair.TYPE_COOKIE,
		                                name + ":" + key,
		                                originalValue,
		                                extractedParameters.size()));

					}
					
				} catch (Exception e) {
					System.out.println("SBSB not json in cookie " + name + " " + value); // TODO
					// Its not structured
	                extractedParameters.add(
	                        new NameValuePair(
	                                NameValuePair.TYPE_COOKIE,
	                                name,
	                                value,
	                                extractedParameters.size()));
				}
            }
        }

        if (extractedParameters.isEmpty()) {
            params = Collections.emptyList();
        } else {
            extractedParameters.trimToSize();
            params = Collections.unmodifiableList(extractedParameters);
        }
		System.out.println("SBSB num params " + params.size()); // TODO
    }

    /**
     * Encodes the given {@code value}.
     *
     * @param value the value that needs to be encoded, must not be {@code null}.
     * @return the encoded value
     */
    private String getEscapedValue(String value) {
        return encodeCookieValues ? AbstractPlugin.getURLEncode(value) : value;
    }

    /**
     * Decodes the given {@code value}.
     *
     * @param value the value that needs to be decoded, must not be {@code null}.
     * @return the decoded value
     */
    private String getUnescapedValue(String value) {
        return encodeCookieValues ? AbstractPlugin.getURLDecode(value) : value;
    }

    /**
     * Gets the list of parameters (that is, cookies) extracted from the request header of the
     * message.
     *
     * @return an unmodifiable {@code List} containing the extracted parameters, never {@code null}.
     */
    @Override
    public List<NameValuePair> getParamList() {
        return params;
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String name, String value) {
        return setParameter(msg, originalPair, name, value, false);
    }

    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String name, String value) {
        return setParameter(msg, originalPair, name, value, true);
    }

    private String setParameter(
            HttpMessage msg,
            NameValuePair originalPair,
            String name,
            String value,
            boolean escaped) {
		System.out.println("SBSB ------ " + name); // TODO
        String escapedValue = value == null ? null : escaped ? value : getEscapedValue(value);
        StringBuilder cookieString = new StringBuilder();
        
        Set<String> handledCookies = new HashSet<>();

        boolean isJson = false;
        String structName = null;
        
    	if (name != null && name.contains(":")) {
    		isJson = true;
    		structName = name.split(":")[0];
    		System.out.println("SBSB isJson " + isJson + " " + structName); // TODO
    	}
        
        
        for (int idx = 0; idx < params.size(); idx++) {
    		System.out.println("SBSB --- " + idx + " " + params.get(idx).getName() + "=" + params.get(idx).getValue()); // TODO
            NameValuePair param = params.get(idx);
        	String paramStructName = null;
            String cookieName = null;
            String cookieValue = null;
            
            if (param.getName() != null && param.getName().contains(":")) {
            	paramStructName = param.getName().split(":")[0];
        		System.out.println("SBSB paramStructName = " + paramStructName); // TODO
            	if (handledCookies.contains(paramStructName)) {
            		// Cookies with structured data will typically appear multiple times.
            		// We've already handled this one
            		System.out.println("SBSB ignoring - already handled");
            		continue;
            	}
            }
            
            
            /*
             * TODO - Problems
             * 		Can have multiple params per cookie - we only want one
             * 		If its the target then we must use the value being set
             * 		If its not the target then it doesnt matter
             */
            if (idx == originalPair.getPosition()) {
            	// TODO
            	if (isJson) {
            		// TODO
            		System.out.println("SBSB attacking " + name);
                    try {
                    	// TODO handle unencoded json
                    	String testValue = param.getValue();
                    	boolean b64enc = false;
    					try {
							testValue = new String(Base64.getDecoder().decode(testValue));
							b64enc = true;
						} catch (Exception e) {
							// Ignore, just means its not base64 encoded
						}
                		System.out.println("SBSB orig value " + testValue);
    					JSONObject json = JSONObject.fromObject(testValue);
                		System.out.println("SBSB orig str " + json.toString());
    					String [] keys = param.getName().split(":");
    					if (keys.length == 2) {
    						cookieName = keys[0];
	    					String key = keys[1];
	                		System.out.println("SBSB attacking " + cookieName + " / " + key);
	                		json.put(key, value); // TODO wrong - not (always) escapedValue
	                		System.out.println("SBSB json " + json.toString());
	                		if (b64enc) {
		                		cookieValue = Base64.getEncoder().encodeToString(json.toString().getBytes());
	                		} else {
		                		cookieValue = json.toString();
	                		}
	                		System.out.println("SBSB value " + cookieValue);
    					} else {
        					System.out.println("SBSB unsupported # keys " + keys.length); // TODO
    						
    					}
    					
    				} catch (Exception e) {
    					System.out.println("SBSB not json in cookie " + param.getName() + " " + param.getValue()); // TODO
    					e.printStackTrace(); // TODO
    					// Ignore
    				}

            		
            	} 
            	else
                if (!(name == null && escapedValue == null)) {
                    cookieName = name;
                    if (escapedValue != null) {
                        cookieValue = escapedValue;
                    }
                }
            } else if (isJson && structName.equals(paramStructName)) {
            	// Same cookie name as the one we are changing, ignore
        		System.out.println("SBSB ignoring - we're attacking this one");
            	continue;
            } else {
                cookieName = param.getName();
                cookieValue = param.getValue();
                if (cookieValue != null) {
                    cookieValue = getEscapedValue(cookieValue);
                }
            }

            if (cookieString.length() != 0
                    && !((cookieName == null || cookieName.isEmpty()) && cookieValue == null)) {
                cookieString.append("; ");
            }

            if (cookieName != null && !cookieName.isEmpty()) {
            	if (paramStructName != null) {
            		cookieString.append(paramStructName);
            		handledCookies.add(paramStructName);
            	} else {
            		cookieString.append(cookieName);
            	}
                cookieString.append('=');
            }

            if (cookieValue != null) {
                cookieString.append(cookieValue);
            }
    		System.out.println("SBSB CS " + cookieString.toString()); // TODO
        }

        msg.getRequestHeader().setHeader(HttpHeader.COOKIE, null);
        if (cookieString.length() != 0) {
            msg.getRequestHeader().setHeader(HttpHeader.COOKIE, cookieString.toString());
        }

        if (escapedValue == null) {
            if (name == null || name.isEmpty()) {
                return null;
            }
            return name + "=";
        }

        if (name == null) {
            return escapedValue;
        }

        return name + "=" + escapedValue;
    }
}
