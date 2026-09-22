/*
 * Copyright (c) 2019-2020 CSC- IT Center for Science, www.csc.fi
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fi.csc.shibboleth.plugin.oauth2.messaging.impl;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AbstractOptionallyIdentifiedRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

/**
 * Class implementing Device Access Token Request message as described in
 * https://tools.ietf.org/html/rfc8628#section-3.4.
 */
public class OAuth2DeviceTokenRequest extends AbstractOptionallyIdentifiedRequest {

    /** Grant Type value for Device Token Request. */
    public final static String grantTypeValue = "urn:ietf:params:oauth:grant-type:device_code";

    /**
     * REQUIRED. Value MUST be set to "urn:ietf:params:oauth:grant-type:device_code".
     */
    private final String grantType;

    /**
     * REQUIRED. The device verification code, "device_code" from the Device Authorization Response, defined in
     * https://tools.ietf.org/html/rfc8628#section-3.2
     */
    private final String deviceCode;

    /**
     * Constructor.
     * 
     * @param uri The URI of the endpoint (HTTP or HTTPS) for which the request is intended, {@code null} if not
     *            specified (if, for example, the {@link #toHTTPRequest()} method will not be used).
     * @param clientAuth The client authentication, {@code null} if none.
     * @param grantType Value MUST be set to "urn:ietf:params:oauth:grant-type:device_code"
     * @param deviceCode The device verification code
     */
    public OAuth2DeviceTokenRequest(final URI uri, ClientAuthentication clientAuth, String grantType,
            String deviceCode) {
        super(uri, clientAuth);
        if (!grantTypeValue.equals(grantType)) {
            throw new IllegalArgumentException("The grant type must be " + grantTypeValue);
        }
        if (deviceCode == null || deviceCode.isEmpty()) {
            throw new IllegalArgumentException("The device code must not be null or empty");
        }
        this.grantType = grantType;
        this.deviceCode = deviceCode;
    }

    /**
     * Constructor.
     * 
     * @param uri The URI of the endpoint (HTTP or HTTPS) for which the request is intended, {@code null} if not
     *            specified (if, for example, the {@link #toHTTPRequest()} method will not be used).
     * @param clientID The client identifier, {@code null} if not specified.
     * @param grantType Value MUST be set to "urn:ietf:params:oauth:grant-type:device_code"
     * @param deviceCode The device verification code
     */
    public OAuth2DeviceTokenRequest(final URI uri, ClientID clientID, String grantType, String deviceCode) {
        super(uri, clientID);
        if (!grantTypeValue.equals(grantType)) {
            throw new IllegalArgumentException("The grant type must be " + grantTypeValue);
        }
        if (deviceCode == null || deviceCode.isEmpty()) {
            throw new IllegalArgumentException("The device code must not be null or empty");
        }
        this.grantType = grantType;
        this.deviceCode = deviceCode;
    }

    /**
     * Get grant type value.
     * 
     * @return "urn:ietf:params:oauth:grant-type:device_code" or null.
     */
    @Nullable
    public String getGrantType() {
        return grantType;
    }

    /**
     * Get device verification code.
     * 
     * @return device verification code or null.
     */
    @Nullable
    public String getDeviceCode() {
        return deviceCode;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public HTTPRequest toHTTPRequest() {
        if (getEndpointURI() == null)
            throw new SerializeException("The endpoint URI is not specified");
        URL url;
        try {
            url = getEndpointURI().toURL();
        } catch (MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }
        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);
        httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
        Map<String, List<String>> params = new HashMap<>();
        if (getClientID() != null) {
            // public client
            params.put("client_id", Collections.singletonList(getClientID().getValue()));
        }
        params.put("grant_type", Collections.singletonList(grantType));
        params.put("device_code", Collections.singletonList(deviceCode));
        httpRequest.setQuery(URLUtils.serializeParameters(params));
        if (getClientAuthentication() != null) {
            getClientAuthentication().applyTo(httpRequest);
        }
        return httpRequest;
    }

    /**
     * Parses request from http request.
     * 
     * @param httpRequest request to parse.
     * @return parsed request.
     * @throws ParseException if parsing failed.
     */
    public static OAuth2DeviceTokenRequest parse(final HTTPRequest httpRequest) throws ParseException {
        httpRequest.ensureMethod(HTTPRequest.Method.POST);
        httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);
        ClientAuthentication clientAuth;
        try {
            clientAuth = ClientAuthentication.parse(httpRequest);
        } catch (ParseException e) {
            throw new ParseException(e.getMessage(),
                    OAuth2Error.INVALID_REQUEST.appendDescription(": " + e.getMessage()));
        }
        Map<String, List<String>> params = httpRequest.getQueryParameters();
        if (clientAuth instanceof ClientSecretBasic) {
            if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion"))
                    || StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {
                String msg = "Multiple conflicting client authentication methods found: Basic and JWT assertion";
                throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
            }
        }
        String grantType = MultivaluedMapUtils.getFirstValue(params, "grant_type");
        String deviceCode = MultivaluedMapUtils.getFirstValue(params, "device_code");
        URI uri;
        try {
            uri = httpRequest.getURL().toURI();
        } catch (URISyntaxException e) {
            throw new ParseException(e.getMessage(), e);
        }
        if (clientAuth != null) {
            return new OAuth2DeviceTokenRequest(uri, clientAuth, grantType, deviceCode);
        }
        final String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");
        if (StringUtils.isBlank(clientIDString)) {
            throw new ParseException(
                    "Invalid device flow token request: No client authentication or client_id parameter found");
        }
        return new OAuth2DeviceTokenRequest(uri, new ClientID(clientIDString), grantType, deviceCode);
    }

}
