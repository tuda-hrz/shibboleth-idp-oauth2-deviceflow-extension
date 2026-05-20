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

import java.net.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.minidev.json.JSONObject;

/**
 * Class implementing Authorization Response message as described in
 * https://tools.ietf.org/html/rfc8628#section-3.2.
 */
public class OAuth2DeviceAuthorizationSuccessResponse implements SuccessResponse {

    /** REQUIRED. The device verification code. */
    private final String deviceCode;

    /** REQUIRED. The end-user verification code. */
    private final String userCode;

    /** REQUIRED. The end-user verification URI on the authorization server. */
    private final URI verificationURI;

    /**
     * OPTIONAL. A verification URI that includes the "user_code" (or other information with the same function as the
     * "user_code"), designed for non-textual transmission.
     */
    private final URI verificationURIComplete;

    /**
     * REQUIRED. The lifetime in seconds of the "device_code" and "user_code".
     */
    private final Integer expiresIn;

    /**
     * OPTIONAL. The minimum amount of time in seconds that the client SHOULD wait between polling requests to the token
     * endpoint.
     */
    private final Integer interval;

    /**
     * Constructor.
     * 
     * @param deviceCode The device verification code
     * @param userCode The end-user verification code
     * @param verificationURI The end-user verification URI on the authorization server
     * @param verificationURIComplete A verification URI that includes the "user_code"
     * @param expiresIn The lifetime in seconds of the "device_code" and "user_code"
     * @param interval The minimum amount of time in seconds that the client SHOULD wait between polling requests to the
     *            token endpoint
     */
    public OAuth2DeviceAuthorizationSuccessResponse(@Nonnull String deviceCode, @Nonnull String userCode,
            @Nonnull URI verificationURI, @Nullable URI verificationURIComplete, @Nonnull Integer expiresIn,
            @Nullable Integer interval) {
        if (deviceCode == null || userCode == null || verificationURI == null || expiresIn == null) {
            throw new IllegalArgumentException(
                    "device code, user code, verification uri and expiresIn must not be null");
        }
        if (expiresIn.intValue() < 1) {
            throw new IllegalArgumentException("expires_in value must be at least 1s");
        }
        if (interval != null && interval.intValue() < 0) {
            throw new IllegalArgumentException("interval value if set must be at least 0s");
        }
        this.deviceCode = deviceCode;
        this.userCode = userCode;
        this.verificationURI = verificationURI;
        this.verificationURIComplete = verificationURIComplete;
        this.expiresIn = expiresIn;
        this.interval = interval;
    }

    /**
     * Constructor.
     * 
     * @param deviceCode The device verification code
     * @param userCode The end-user verification code
     * @param verificationURI The end-user verification URI on the authorization server
     * @param expiresIn The lifetime in seconds of the "device_code" and "user_code"
     */
    public OAuth2DeviceAuthorizationSuccessResponse(@Nonnull String deviceCode, @Nonnull String userCode,
            @Nonnull URI verificationURI, int expiresIn) {
        this(deviceCode, userCode, verificationURI, null, expiresIn, null);
    }

    /**
     * Get the device verification code.
     * 
     * @return The device verification code
     */
    @Nonnull
    public String getDeviceCode() {
        return deviceCode;
    }

    /**
     * Get the end-user verification code
     * 
     * @return the end-user verification code
     */
    @Nonnull
    public String getUserCode() {
        return userCode;
    }

    /**
     * Get the end-user verification URI on the authorization server.
     * 
     * @return The end-user verification URI on the authorization server
     */
    @Nonnull
    public URI getVerificationURI() {
        return verificationURI;
    }

    /**
     * Get a verification URI that includes the "user_code".
     * 
     * @return A verification URI that includes the "user_code"
     */
    @Nullable
    public URI getVerificationURIComplete() {
        return verificationURIComplete;
    }

    /**
     * Get the lifetime in seconds of the "device_code" and "user_code".
     * 
     * @return The lifetime in seconds of the "device_code" and "user_code"
     */
    @Nonnull
    public Integer getExpiresIn() {
        return expiresIn;
    }

    /**
     * Get the minimum amount of time in seconds that the client SHOULD wait between polling requests to the token end
     * point.
     * 
     * @return The minimum amount of time in seconds that the client SHOULD wait between polling requests to the token
     *         end point.
     */
    @Nullable
    public Integer getInterval() {
        return interval;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean indicatesSuccess() {
        return true;
    }

    /**
     * Present the message contents as JSON Object.
     * 
     * @return the message contents as JSON Object
     */
    public JSONObject toJSONObject() {
        JSONObject content = new JSONObject();
        content.put("device_code", deviceCode);
        content.put("user_code", userCode);
        content.put("verification_uri", verificationURI.toString());
        if (verificationURIComplete != null) {
            content.put("verification_uri_complete", verificationURIComplete.toString());
        }
        content.put("expires_in", expiresIn);
        if (interval != null) {
            content.put("interval", interval);
        }
        return content;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public HTTPResponse toHTTPResponse() {
        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");
        httpResponse.setBody(toJSONObject().toString());
        return httpResponse;
    }

}
