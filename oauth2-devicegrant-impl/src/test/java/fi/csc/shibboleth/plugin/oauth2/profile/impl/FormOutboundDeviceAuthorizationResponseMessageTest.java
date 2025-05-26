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

package fi.csc.shibboleth.plugin.oauth2.profile.impl;

import java.io.IOException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.impl.MemoryStorageService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.config.impl.DefaultOAuth2DeviceGrantConfiguration;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationSuccessResponse;
import jakarta.servlet.http.HttpServletRequest;
import net.minidev.json.parser.ParseException;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseContext;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.testing.RequestContextBuilder;
import net.shibboleth.oidc.metadata.context.OIDCMetadataContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

/**
 * Unit tests for {@link FormOutboundDeviceAuthorizationResponseMessage}.
 */
public class FormOutboundDeviceAuthorizationResponseMessageTest {

    protected RequestContext requestCtx;

    protected ProfileRequestContext profileRequestCtx;

    private FormOutboundDeviceAuthorizationResponseMessage action;

    private MemoryStorageService storageService;

    private DeviceCodesCache deviceCodesCache;

    @BeforeMethod
    protected void setUp() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setInboundMessageContext(new MessageContext());
        profileRequestCtx.getInboundMessageContext()
                .setMessage(new OAuth2DeviceAuthorizationRequest(null, new ClientID("clientID"), new Scope("device"), null));
        profileRequestCtx.getInboundMessageContext().addSubcontext(new OIDCMetadataContext());
        profileRequestCtx.setOutboundMessageContext(new MessageContext());
        profileRequestCtx.getOutboundMessageContext().addSubcontext(new OIDCAuthenticationResponseContext());
        ((RelyingPartyContext) profileRequestCtx.addSubcontext(new RelyingPartyContext(), true))
                .setProfileConfig((new DefaultOAuth2DeviceGrantConfiguration()));
        ((RelyingPartyContext) profileRequestCtx.getSubcontext(RelyingPartyContext.class))
                .setRelyingPartyId("clientID");
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.initialize();
        deviceCodesCache = new DeviceCodesCache();
        deviceCodesCache.setStorage(storageService);
        deviceCodesCache.initialize();
        action = new FormOutboundDeviceAuthorizationResponseMessage();
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        action.setHttpServletRequestSupplier(new NonnullSupplier<>() {
            public HttpServletRequest get() {
                return httpRequest;
            }
        });
        action.setDeviceCodesCache(deviceCodesCache);
        action.initialize();
    }

    @AfterMethod
    protected void tearDown() {
        deviceCodesCache.destroy();
        deviceCodesCache = null;
        storageService.destroy();
        storageService = null;
    }

    @Test
    public void testSuccess() throws IOException, ParseException {
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        OAuth2DeviceAuthorizationSuccessResponse resp = (OAuth2DeviceAuthorizationSuccessResponse) profileRequestCtx
                .getOutboundMessageContext().getMessage();
        Assert.assertEquals("https://localhost/idp/profile/oauth2/devicegrant/authenticate",
                resp.getVerificationURI().toString());
        Assert.assertEquals("https://localhost/idp/profile/oauth2/devicegrant/authenticate?user_code=" + resp.getUserCode(),
                resp.getVerificationURIComplete().toString());
        Assert.assertNotNull(resp.getExpiresIn());
        Assert.assertNotNull(resp.getInterval());
        DeviceCodeObject object = deviceCodesCache.getDeviceCode(resp.getUserCode());
        Assert.assertEquals(resp.getDeviceCode(), object.getDeviceCode());
        Assert.assertEquals("clientID", object.getClientID().getValue());
        Assert.assertEquals("device", object.getScope().toString());
    }

    @Test
    public void testAlternatePath() throws IOException, ParseException, ComponentInitializationException {
        action = new FormOutboundDeviceAuthorizationResponseMessage();
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        action.setHttpServletRequestSupplier(new NonnullSupplier<>() {
            public HttpServletRequest get() {
                return httpRequest;
            }
        });
        action.setAuthenticationEndpoint("/endpoint");
        action.setDeviceCodesCache(deviceCodesCache);
        action.initialize();
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        OAuth2DeviceAuthorizationSuccessResponse resp = (OAuth2DeviceAuthorizationSuccessResponse) profileRequestCtx
                .getOutboundMessageContext().getMessage();
        Assert.assertEquals("https://localhost/endpoint", resp.getVerificationURI().toString());
        Assert.assertEquals("https://localhost/endpoint?user_code=" + resp.getUserCode(),
                resp.getVerificationURIComplete().toString());
    }

    @Test
    public void testNoHttpServletRequest() throws IOException, ParseException, ComponentInitializationException {
        action = new FormOutboundDeviceAuthorizationResponseMessage();
        action.setDeviceCodesCache(deviceCodesCache);
        action.initialize();
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_PROFILE_CTX);
    }

    @Test
    public void testNoRpCtx() {
        profileRequestCtx.removeSubcontext(RelyingPartyContext.class);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    @Test
    public void testFailNoProfileConfig() {
        profileRequestCtx.addSubcontext(new RelyingPartyContext(), true);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    @Test
    public void testFailNoInboudMessage() {
        profileRequestCtx.getInboundMessageContext().setMessage(null);
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MSG_CTX);
    }

}