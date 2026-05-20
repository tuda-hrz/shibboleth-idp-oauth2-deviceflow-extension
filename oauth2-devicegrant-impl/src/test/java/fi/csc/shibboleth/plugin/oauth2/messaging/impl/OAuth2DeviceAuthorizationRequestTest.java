/*
 * Copyright (c) 2019 CSC- IT Center for Science, www.csc.fi
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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.messaging.decoder.MessageDecodingException;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ACR;

import org.testng.Assert;

/**
 * Unit tests for {@link OAuth2DeviceAuthorizationRequest}.
 */
public class OAuth2DeviceAuthorizationRequestTest {

    private OAuth2DeviceAuthorizationRequest message;

    @BeforeMethod
    protected void setUp() throws Exception {
        ArrayList<ACR> acrs = new ArrayList<ACR>();
        acrs.add(new ACR("https://refeds"));
        message = new OAuth2DeviceAuthorizationRequest(new URI("http://example.com"), new ClientID("clientID"),
                new Scope("device"), acrs);
    }

    @Test
    public void testGetters() throws MessageDecodingException {
        Assert.assertEquals("clientID", message.getClientID().getValue());
        Assert.assertEquals("device", message.getScope().toString());
        Assert.assertNull(message.getClientAuthentication());
        Assert.assertEquals("example.com", message.getEndpointURI().getHost());
        Assert.assertEquals("http", message.getEndpointURI().getScheme());
    }

    @Test(expectedExceptions = SerializeException.class)
    public void testNullRequest() throws MessageDecodingException {
        message = new OAuth2DeviceAuthorizationRequest(null, (ClientID) null, null, null);
        Assert.assertNull(message.getClientID());
        Assert.assertNull(message.getScope());
        Assert.assertNull(message.getEndpointURI());
        message.toHTTPRequest();
    }

    @Test
    public void testHttpRequestAndParse() throws MessageDecodingException, ParseException {
        HTTPRequest req = message.toHTTPRequest();
        Assert.assertEquals(Method.POST, req.getMethod());
        Assert.assertEquals("http", req.getURL().getProtocol());
        Assert.assertEquals("example.com", req.getURL().getHost());
        Assert.assertTrue(req.getURL().getQuery().contains("client_id=clientID"));
        Assert.assertTrue(req.getURL().getQuery().contains("scope=device"));
        Assert.assertTrue(req.getURL().getQuery().contains("acr_values=https%3A%2F%2Frefeds"));
        OAuth2DeviceAuthorizationRequest messageParsed = OAuth2DeviceAuthorizationRequest.parse(req);
        Assert.assertEquals("clientID", messageParsed.getClientID().getValue());
        Assert.assertEquals("device", messageParsed.getScope().toString());
        Assert.assertEquals("example.com", messageParsed.getEndpointURI().getHost());
        Assert.assertEquals("http", messageParsed.getEndpointURI().getScheme());
        Assert.assertTrue("https://refeds".equals(messageParsed.getAcrValues().get(0).getValue()));
    }

    @Test
    public void testClientAuthnGetters() throws MessageDecodingException, ParseException, URISyntaxException {
        ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("clientID"), new Secret());
        message = new OAuth2DeviceAuthorizationRequest(new URI("http://example.com"), clientAuth, new Scope("device"),
                null);
        Assert.assertNull(message.getClientID());
        Assert.assertEquals("device", message.getScope().toString());
        Assert.assertEquals("clientID", message.getClientAuthentication().getClientID().getValue());
        Assert.assertEquals("example.com", message.getEndpointURI().getHost());
        Assert.assertEquals("http", message.getEndpointURI().getScheme());
    }

    @Test
    public void testClientAuthnHttpRequestAndParse()
            throws MessageDecodingException, ParseException, URISyntaxException {
        ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("clientID"), new Secret());
        message = new OAuth2DeviceAuthorizationRequest(new URI("http://example.com"), clientAuth, new Scope("device"),
                null);
        HTTPRequest req = message.toHTTPRequest();
        Assert.assertEquals(Method.POST, req.getMethod());
        Assert.assertEquals("http", req.getURL().getProtocol());
        Assert.assertEquals("example.com", req.getURL().getHost());
        Assert.assertFalse(req.getURL().getQuery().contains("client_id=clientID"));
        Assert.assertTrue(req.getURL().getQuery().contains("scope=device"));
        Assert.assertNotNull(req.getHeaderValue("Authorization"));
        OAuth2DeviceAuthorizationRequest messageParsed = OAuth2DeviceAuthorizationRequest.parse(req);
        Assert.assertNull(messageParsed.getClientID());
        Assert.assertEquals("device", messageParsed.getScope().toString());
        Assert.assertEquals("clientID", messageParsed.getClientAuthentication().getClientID().getValue());
        Assert.assertEquals("example.com", messageParsed.getEndpointURI().getHost());
        Assert.assertEquals("http", messageParsed.getEndpointURI().getScheme());
    }

}