/*
 * Copyright (c) 2019-2025 CSC- IT Center for Science, www.csc.fi
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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AbstractOptionallyIdentifiedRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import com.nimbusds.openid.connect.sdk.claims.ACR;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * Class implementing Authorization Request message as described in
 * https://tools.ietf.org/html/rfc8628#section-3.1.
 */
public class OAuth2DeviceAuthorizationRequest extends AbstractOptionallyIdentifiedRequest {

    /** OPTIONAL. The scope of the access request. */
    @Nullable
    private final Scope scope;

    /** OPTIONAL. The acr values of the access request. */
    @Nullable
    private final List<ACR> acrValues;

    /**
     * Constructor.
     * 
     * @param uri        The URI of the endpoint (HTTP or HTTPS) for which the
     *                   request is intended, {@code null} if not specified (if, for
     *                   example, the {@link #toHTTPRequest()} method will not be
     *                   used).
     * @param clientAuth The client authentication, {@code null} if none.
     * @param scope      The scope of the access request, {@code null} if none.
     */
    public OAuth2DeviceAuthorizationRequest(final URI uri, ClientAuthentication clientAuth, Scope scope,
            List<ACR> acrValues) {
        super(uri, clientAuth);
        this.scope = scope;
        this.acrValues = acrValues;
    }

    /**
     * Constructor.
     * 
     * @param uri      The URI of the endpoint (HTTP or HTTPS) for which the request
     *                 is intended, {@code null} if not specified (if, for example,
     *                 the {@link #toHTTPRequest()} method will not be used).
     * @param clientID The client identifier, {@code null} if not specified.
     * @param scope    The scope of the access request, {@code null} if none.
     */
    public OAuth2DeviceAuthorizationRequest(final URI uri, ClientID clientID, Scope scope, List<ACR> acrValues) {
        super(uri, clientID);
        this.scope = scope;
        this.acrValues = acrValues;
    }

    /**
     * Get the scope of the access request.
     * 
     * @return The scope of the access request
     */
    @Nullable
    public Scope getScope() {
        return scope;
    }

    /**
     * Get he acr values of the access request.
     * 
     * @return The acr values of the access request
     */
    @Nullable
    public List<ACR> getAcrValues() {
        return acrValues;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Nonnull
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
        if (acrValues != null) {
            StringBuilder sb = new StringBuilder();
            for (ACR acr: acrValues) {
                if (sb.length() > 0)
                    sb.append(' ');
                sb.append(acr.toString());
            }
            params.put("acr_values", Collections.singletonList(sb.toString()));
        }
        if (scope != null && !scope.isEmpty()) {
            params.put("scope", Collections.singletonList(scope.toString()));
        }
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
    public static OAuth2DeviceAuthorizationRequest parse(final HTTPRequest httpRequest) throws ParseException {
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
        String acrParameterValue = MultivaluedMapUtils.getFirstValue(params, "acr_values");

        List<ACR> acrValues = null;
        if (StringUtils.isNotBlank(acrParameterValue)) {
            acrValues = new LinkedList<>();
            StringTokenizer st = new StringTokenizer(acrParameterValue, " ");
            while (st.hasMoreTokens()) {
                acrValues.add(new ACR(st.nextToken()));
            }
        }

        String scopeValue = MultivaluedMapUtils.getFirstValue(params, "scope");
        Scope scope = null;
        if (scopeValue != null) {
            scope = Scope.parse(scopeValue);
        }
        URI uri;
        try {
            uri = httpRequest.getURL().toURI();
        } catch (URISyntaxException e) {
            throw new ParseException(e.getMessage(), e);
        }
        if (clientAuth != null) {
            return new OAuth2DeviceAuthorizationRequest(uri, clientAuth, scope, acrValues);
        }
        final String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");
        if (StringUtils.isBlank(clientIDString)) {
            throw new ParseException(
                    "Invalid device flow authorization request: No client authentication or client_id parameter found");
        }
        return new OAuth2DeviceAuthorizationRequest(uri, new ClientID(clientIDString), scope, acrValues);
    }

}
