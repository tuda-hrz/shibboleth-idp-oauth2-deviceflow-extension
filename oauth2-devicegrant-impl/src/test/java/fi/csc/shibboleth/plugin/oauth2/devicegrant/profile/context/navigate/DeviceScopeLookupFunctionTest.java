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

package fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthenticationRequest;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.ConstraintViolationException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.impl.MemoryStorageService;
import org.testng.Assert;

/**
 * Unit tests for {@link DeviceScopeLookupFunction}.
 */
public class DeviceScopeLookupFunctionTest {

    private DeviceScopeLookupFunction lookup;

    private MessageContext msgCtx;

    private DeviceCodesCache cache;

    private MemoryStorageService storage;

    private ProfileRequestContext prc;

    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DeviceScopeLookupFunction();
        cache = new DeviceCodesCache();
        storage = new MemoryStorageService();
        storage.setId("1");
        storage.initialize();
        cache.setStorage(storage);
        cache.initialize();
        cache.storeDeviceCode(new DeviceCodeObject("DC1234", new ClientID("clientID4"), new Scope("device1"), null), "UC1234",
                100);
        cache.storeDeviceCode(new DeviceCodeObject("DC12345", new ClientID("clientID5"), new Scope("device2"), null),
                "UC12345", 100);
        cache.storeDeviceCode(new DeviceCodeObject("DC123456", new ClientID("clientID6"), new Scope("device3"), null),
                "UC123456", 100);
        cache.storeDeviceCode(new DeviceCodeObject("DC1234567", new ClientID("clientID7"), new Scope("device4"), null),
                "UC1234567", 100);
        lookup.setDeviceCodesCache(cache);
        lookup.initialize();
        prc = new ProfileRequestContext();
        msgCtx = new MessageContext();
        prc.setInboundMessageContext(msgCtx);
        msgCtx.setMessage(new OAuth2DeviceAuthenticationRequest(null, "UC123456"));
    }

    @AfterMethod
    protected void tearDown() {
        cache.destroy();
        cache = null;
        storage.destroy();
        storage = null;
    }

    @Test
    public void lookupSuccess() {
        Assert.assertEquals(lookup.apply(prc), new Scope("device3"));
    }

    @Test
    public void lookupFailNoObjectForUserCode() {
        msgCtx.setMessage(new OAuth2DeviceAuthenticationRequest(null, "UC123456_NOTFOUND"));
        Assert.assertNull(lookup.apply(prc));
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void lookupFailNoCache() throws ComponentInitializationException {
        lookup = new DeviceScopeLookupFunction();
        lookup.initialize();
    }

    @Test
    public void lookupFailNoMessageContext() {
        Assert.assertNull(lookup.apply(null));
    }

}