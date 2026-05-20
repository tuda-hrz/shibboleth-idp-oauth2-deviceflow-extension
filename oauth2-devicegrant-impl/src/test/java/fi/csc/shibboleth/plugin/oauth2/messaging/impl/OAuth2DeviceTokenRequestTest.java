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
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.testng.Assert;

/**
 * Unit tests for {@link OAuth2DeviceTokenRequest}.
 */
public class OAuth2DeviceTokenRequestTest {

    private OAuth2DeviceTokenRequest message;

    @BeforeMethod
    protected void setUp() throws Exception {
        message = new OAuth2DeviceTokenRequest(new URI("http://example.com"), new ClientID("clientID"),
                OAuth2DeviceTokenRequest.grantTypeValue, "123456");
    }

    @Test
    public void testGetters() throws MessageDecodingException {
        Assert.assertEquals("clientID", message.getClientID().getValue());
        Assert.assertEquals("123456", message.getDeviceCode());
        Assert.assertEquals(OAuth2DeviceTokenRequest.grantTypeValue, message.getGrantType());
        Assert.assertNull(message.getClientAuthentication());
        Assert.assertEquals("example.com", message.getEndpointURI().getHost());
        Assert.assertEquals("http", message.getEndpointURI().getScheme());
    }

    @Test(expectedExceptions = SerializeException.class)
    public void testMinimalRequestInitialization() throws MessageDecodingException {
        message =
                new OAuth2DeviceTokenRequest(null, (ClientID) null, OAuth2DeviceTokenRequest.grantTypeValue, "123456");
        Assert.assertNull(message.getClientID());
        Assert.assertEquals("123456", message.getDeviceCode());
        Assert.assertEquals(OAuth2DeviceTokenRequest.grantTypeValue, message.getGrantType());
        Assert.assertNull(message.getEndpointURI());
        message.toHTTPRequest();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testInvalidGrantType() throws MessageDecodingException, URISyntaxException {
        message =
                new OAuth2DeviceTokenRequest(new URI("http://example.com"), new ClientID("clientID"), "none", "123456");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testMissingCode() throws MessageDecodingException, URISyntaxException {
        message = new OAuth2DeviceTokenRequest(new URI("http://example.com"), new ClientID("clientID"),
                OAuth2DeviceTokenRequest.grantTypeValue, null);
    }

    @Test
    public void testHttpRequestAndParse() throws MessageDecodingException, ParseException {
        HTTPRequest req = message.toHTTPRequest();
        Assert.assertEquals(Method.POST, req.getMethod());
        Assert.assertEquals("http", req.getURL().getProtocol());
        Assert.assertEquals("example.com", req.getURL().getHost());
        Assert.assertTrue(req.getURL().getQuery().contains("device_code=123456"));
        Assert.assertTrue(req.getURL().getQuery()
                .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code"));;
        OAuth2DeviceTokenRequest messageParsed = OAuth2DeviceTokenRequest.parse(req);
        Assert.assertEquals("clientID", messageParsed.getClientID().getValue());
        Assert.assertEquals("123456", messageParsed.getDeviceCode());
        Assert.assertEquals(OAuth2DeviceTokenRequest.grantTypeValue, messageParsed.getGrantType());
        Assert.assertEquals("example.com", messageParsed.getEndpointURI().getHost());
        Assert.assertEquals("http", messageParsed.getEndpointURI().getScheme());
    }

    @Test
    public void testClientAuthnGetters() throws MessageDecodingException, ParseException, URISyntaxException {
        ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("clientID"), new Secret());
        message = new OAuth2DeviceTokenRequest(new URI("http://example.com"), clientAuth,
                OAuth2DeviceTokenRequest.grantTypeValue, "123456");
        Assert.assertNull(message.getClientID());
        Assert.assertEquals("123456", message.getDeviceCode());
        Assert.assertEquals(OAuth2DeviceTokenRequest.grantTypeValue, message.getGrantType());
        Assert.assertEquals("clientID", message.getClientAuthentication().getClientID().getValue());
        Assert.assertEquals("example.com", message.getEndpointURI().getHost());
        Assert.assertEquals("http", message.getEndpointURI().getScheme());
    }

    @Test
    public void testClientAuthnHttpRequestAndParse()
            throws MessageDecodingException, ParseException, URISyntaxException {
        ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("clientID"), new Secret());
        message = new OAuth2DeviceTokenRequest(new URI("http://example.com"), clientAuth,
                OAuth2DeviceTokenRequest.grantTypeValue, "123456");
        HTTPRequest req = message.toHTTPRequest();
        Assert.assertEquals(Method.POST, req.getMethod());
        Assert.assertEquals("http", req.getURL().getProtocol());
        Assert.assertEquals("example.com", req.getURL().getHost());
        Assert.assertTrue(req.getURL().getQuery().contains("device_code=123456"));
        Assert.assertTrue(req.getURL().getQuery()
                .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code"));;
        Assert.assertNotNull(req.getHeaderValue("Authorization"));
        OAuth2DeviceTokenRequest messageParsed = OAuth2DeviceTokenRequest.parse(req);
        Assert.assertNull(messageParsed.getClientID());
        Assert.assertEquals("123456", messageParsed.getDeviceCode());
        Assert.assertEquals(OAuth2DeviceTokenRequest.grantTypeValue, messageParsed.getGrantType());
        Assert.assertEquals("clientID", messageParsed.getClientAuthentication().getClientID().getValue());
        Assert.assertEquals("example.com", messageParsed.getEndpointURI().getHost());
        Assert.assertEquals("http", messageParsed.getEndpointURI().getScheme());
    }

}