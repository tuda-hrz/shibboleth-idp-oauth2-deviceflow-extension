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

package fi.csc.shibboleth.plugin.oauth2.decoding.impl;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;

/**
 * Unit tests for {@link OAuth2DeviceAuthorizationRequestDecoder}.
 */
public class OAuth2DeviceAuthorizationRequestDecoderTest {

    private MockHttpServletRequest httpRequest;

    private OAuth2DeviceAuthorizationRequestDecoder decoder;

    @BeforeMethod
    protected void setUp() throws Exception {

        decoder = new OAuth2DeviceAuthorizationRequestDecoder();
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod("POST");
        httpRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
        httpRequest.setQueryString("scope=value&client_id=123456");
        decoder.setHttpServletRequestSupplier(new NonnullSupplier<>() {
            public HttpServletRequest get() {
                return httpRequest;
            }
        });
        decoder.initialize();
    }

    @Test
    public void testRequestDecoding() throws MessageDecodingException {
        decoder.decode();
        MessageContext messageContext = decoder.getMessageContext();
        Assert.assertEquals(((OAuth2DeviceAuthorizationRequest) messageContext.getMessage()).getClientID().toString(),
                "123456");
        Assert.assertEquals("value",
                ((OAuth2DeviceAuthorizationRequest) messageContext.getMessage()).getScope().toString());

    }

    @Test(expectedExceptions = MessageDecodingException.class)
    public void testInvalidRequestDecoding() throws MessageDecodingException {
        httpRequest.setQueryString("scope=value");
        decoder.decode();
    }

    @Test
    public void testClientInHeaders() throws MessageDecodingException, ComponentInitializationException {
        httpRequest.addHeader("Authorization", "Basic dGVzdDp0ZXN0");
        httpRequest.setQueryString("scope=value");
        decoder = new OAuth2DeviceAuthorizationRequestDecoder();
        decoder.setHttpServletRequestSupplier(new NonnullSupplier<>() {
            public HttpServletRequest get() {
                return httpRequest;
            }
        });
        decoder.initialize();
        decoder.decode();
        MessageContext messageContext = decoder.getMessageContext();
        Assert.assertEquals("value",
                ((OAuth2DeviceAuthorizationRequest) messageContext.getMessage()).getScope().toString());
        Assert.assertEquals(((OAuth2DeviceAuthorizationRequest) messageContext.getMessage()).getClientAuthentication()
                .getClientID().getValue(), "test");
    }
}