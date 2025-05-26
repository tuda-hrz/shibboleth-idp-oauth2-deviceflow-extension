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

package fi.csc.shibboleth.plugin.oauth2.devicegrant.storage;

import java.io.IOException;
import org.opensaml.storage.impl.client.ClientStorageService;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

import net.minidev.json.parser.ParseException;
import net.shibboleth.shared.component.ComponentInitializationException;

import org.testng.annotations.BeforeMethod;
import org.testng.Assert;
import org.opensaml.storage.impl.MemoryStorageService;;

/**
 * Tests for {@link DeviceCodesCache}
 */
public class DeviceCodesCacheTest {

    private MemoryStorageService storageService;

    private DeviceCodesCache deviceCodesCache;

    private DeviceCodeObject deviceCodeObject;

    private String userCode = "user_code_XYZ";

    @BeforeMethod
    protected void setUp() throws Exception {

        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.initialize();

        deviceCodesCache = new DeviceCodesCache();
        deviceCodesCache.setStorage(storageService);
        deviceCodesCache.initialize();

        deviceCodeObject =
                new DeviceCodeObject("device_code_XYZ", new ClientID("client_id_XYZ"), new Scope("device_scope"), null);
    }

    @AfterMethod
    protected void tearDown() {
        deviceCodesCache.destroy();
        deviceCodesCache = null;

        storageService.destroy();
        storageService = null;
    }

    @Test
    public void testInit() {
        deviceCodesCache = new DeviceCodesCache();
        try {
            deviceCodesCache.setStorage(null);
            Assert.fail("Null StorageService should have caused constraint violation");
        } catch (Exception e) {
        }

        try {
            deviceCodesCache.setStorage(new ClientStorageService());

            Assert.fail("ClientStorageService should have caused constraint violation");
        } catch (Exception e) {
        }
    }

    @Test
    public void testStorageGetter() throws ComponentInitializationException {
        Assert.assertEquals(storageService, deviceCodesCache.getStorage());
    }

    @Test
    public void testStore() throws ComponentInitializationException, IOException, ParseException {
        Assert.assertTrue(deviceCodesCache.storeDeviceCode(deviceCodeObject, userCode, 200));
        DeviceCodeObject deviceCodeFromStore = deviceCodesCache.getDeviceCode(userCode);
        Assert.assertEquals(deviceCodeObject.toJSONObject().toJSONString(),
                deviceCodeFromStore.toJSONObject().toJSONString());
        Assert.assertEquals(deviceCodesCache.getDeviceState(deviceCodeObject.getDeviceCode()).getState(),
                DeviceStateObject.State.PENDING);
        Assert.assertFalse(deviceCodesCache.storeDeviceCode(deviceCodeObject, userCode, 200));
    }

    @Test
    public void testStaleObject()
            throws ComponentInitializationException, IOException, ParseException, InterruptedException {
        deviceCodesCache.storeDeviceCode(deviceCodeObject, userCode, 1);
        Thread.sleep(5);
        Assert.assertNull(deviceCodesCache.getDeviceCode(userCode));
        Assert.assertNull(deviceCodesCache.getDeviceState(deviceCodeObject.getDeviceCode()));
    }

    @Test
    public void testUpdate() throws ComponentInitializationException, IOException, ParseException {
        Assert.assertTrue(deviceCodesCache.storeDeviceCode(deviceCodeObject, userCode, 200));
        Assert.assertEquals(deviceCodesCache.getDeviceState(deviceCodeObject.getDeviceCode()).getState(),
                DeviceStateObject.State.PENDING);
        DeviceStateObject deviceStateObject =
                new DeviceStateObject(DeviceStateObject.State.APPROVED, "accessToken", 171717171L);
        Assert.assertTrue(deviceCodesCache.updateDeviceState(deviceCodeObject.getDeviceCode(), deviceStateObject, 200));
        Assert.assertEquals(deviceCodesCache.getDeviceState(deviceCodeObject.getDeviceCode()).getState(),
                DeviceStateObject.State.APPROVED);
        Assert.assertEquals(deviceCodesCache.getDeviceState(deviceCodeObject.getDeviceCode()).getAccessToken(),
                "accessToken");
    }

}