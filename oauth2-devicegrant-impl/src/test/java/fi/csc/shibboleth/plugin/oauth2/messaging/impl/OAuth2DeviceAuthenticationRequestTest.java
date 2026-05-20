/*
 * Copyright (c) 2019-2024 CSC- IT Center for Science, www.csc.fi
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

import org.opensaml.messaging.decoder.MessageDecodingException;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;

import org.testng.Assert;

/**
 * Unit tests for {@link OAuth2DeviceAuthenticationRequest}.
 */
public class OAuth2DeviceAuthenticationRequestTest {

    private OAuth2DeviceAuthenticationRequest message;

    @BeforeMethod
    protected void setUp() throws Exception {
        message = new OAuth2DeviceAuthenticationRequest(new URI("http://example.com"), "123456");
    }

    @Test
    public void testGetters() throws MessageDecodingException {
        Assert.assertEquals("123456", message.getUserCode());
        Assert.assertEquals("http://example.com", message.getEndpointURI().toString());
    }

    @Test(expectedExceptions = SerializeException.class)
    public void testNullRequest() throws MessageDecodingException {
        message = new OAuth2DeviceAuthenticationRequest(null, null);
        Assert.assertNull(message.getUserCode());
        Assert.assertNull(message.getEndpointURI());
        message.toHTTPRequest();
    }

    @Test
    public void testHttpRequestAndParse() throws MessageDecodingException, ParseException {
        HTTPRequest req = message.toHTTPRequest();
        Assert.assertEquals(Method.GET, req.getMethod());
        Assert.assertEquals("http", req.getURL().getProtocol());
        Assert.assertEquals("example.com", req.getURL().getHost());
        Assert.assertEquals("user_code=123456", req.getURL().getQuery());
        OAuth2DeviceAuthenticationRequest messageParsedParsed = OAuth2DeviceAuthenticationRequest.parse(req);
        Assert.assertEquals("123456", messageParsedParsed.getUserCode());
        Assert.assertEquals("example.com", messageParsedParsed.getEndpointURI().getHost());
        Assert.assertEquals("http", messageParsedParsed.getEndpointURI().getScheme());
    }

}