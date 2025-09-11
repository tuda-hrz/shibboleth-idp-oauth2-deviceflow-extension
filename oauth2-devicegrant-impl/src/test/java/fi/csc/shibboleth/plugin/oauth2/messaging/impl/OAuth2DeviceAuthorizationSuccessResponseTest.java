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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.minidev.json.JSONObject;
import org.testng.Assert;

/**
 * Unit tests for {@link OAuth2DeviceAuthorizationSuccessResponse}.
 */
public class OAuth2DeviceAuthorizationSuccessResponseTest {

    private OAuth2DeviceAuthorizationSuccessResponse message;

    @BeforeMethod
    protected void setUp() throws Exception {
        message = new OAuth2DeviceAuthorizationSuccessResponse("deviceCode", "userCode", new URI("http;//example.com"),
                new URI("http;//example.com/complete"), 60, 10);
    }

    @Test
    public void testGetters() throws MessageDecodingException {
        Assert.assertEquals("deviceCode", message.getDeviceCode());
        Assert.assertEquals("userCode", message.getUserCode());
        Assert.assertEquals("http;//example.com", message.getVerificationURI().toString());
        Assert.assertEquals("http;//example.com/complete", message.getVerificationURIComplete().toString());
        Assert.assertEquals(60, message.getExpiresIn().intValue());
        Assert.assertEquals(10, message.getInterval().intValue());
    }

    @Test
    public void testGettersMinimalConstructor() throws MessageDecodingException, URISyntaxException {
        message = new OAuth2DeviceAuthorizationSuccessResponse("deviceCode", "userCode", new URI("http;//example.com"),
                60);
        Assert.assertEquals("deviceCode", message.getDeviceCode());
        Assert.assertEquals("userCode", message.getUserCode());
        Assert.assertEquals("http;//example.com", message.getVerificationURI().toString());
        Assert.assertNull(message.getVerificationURIComplete());
        Assert.assertEquals((int) 60, message.getExpiresIn().intValue());
        Assert.assertNull(message.getInterval());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testIllegalExpiresIn() throws MessageDecodingException, URISyntaxException {
        message = new OAuth2DeviceAuthorizationSuccessResponse("deviceCode", "userCode", new URI("http;//example.com"),
                new URI("http;//example.com/complete"), 0, 10);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testIllegalInterval() throws MessageDecodingException, URISyntaxException {
        message = new OAuth2DeviceAuthorizationSuccessResponse("deviceCode", "userCode", new URI("http;//example.com"),
                new URI("http;//example.com/complete"), 60, -1);
    }

    @Test
    public void testJSONPresentation() throws MessageDecodingException {
        JSONObject response = message.toJSONObject();
        Assert.assertEquals("deviceCode", response.get("device_code"));
        Assert.assertEquals("userCode", response.get("user_code"));
        Assert.assertEquals("http;//example.com", response.get("verification_uri"));
        Assert.assertEquals("http;//example.com/complete", response.get("verification_uri_complete"));
        Assert.assertEquals(60, response.get("expires_in"));
        Assert.assertEquals(10, response.get("interval"));
    }

    @Test
    public void testHTTPResponsePresentation() throws MessageDecodingException, ParseException {
        HTTPResponse response = message.toHTTPResponse();
        Assert.assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        response.getContentAsJSONObject().equals(message.toJSONObject());
    }

}