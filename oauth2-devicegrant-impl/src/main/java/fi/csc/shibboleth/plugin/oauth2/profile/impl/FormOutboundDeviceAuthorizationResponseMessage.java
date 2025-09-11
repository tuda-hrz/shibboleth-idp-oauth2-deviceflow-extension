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
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.function.Function;

import javax.annotation.Nonnull;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationRequest;
import fi.csc.shibboleth.plugin.oauth2.messaging.impl.OAuth2DeviceAuthorizationSuccessResponse;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.profile.config.ProfileConfiguration;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.security.impl.SecureRandomIdentifierGenerationStrategy;

/**
 * Action forming device authorization response success message. Action
 * generates user and device codes, forms a {@link DeviceCodeObject} storing it
 * to {@link DeviceCodesCache} keyed with user code. Finally the action forms
 * {@link OAuth2DeviceAuthorizationSuccessResponse}
 */
public class FormOutboundDeviceAuthorizationResponseMessage extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundDeviceAuthorizationResponseMessage.class);

    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a
     * given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Length of the device code. */
    private long deviceCodeLength;

    /** Length of the user code. */
    private long userCodeLength;

    /** Expiration of device/user codes in milliseconds. */
    private Duration expiration;

    /** Relying party context. */
    private RelyingPartyContext rpCtx;

    /** Authentication endpoint not including server name and protocol. */
    private String authenticationEndpoint = "/idp/profile/oauth2/devicegrant/authenticate";

    /** Interval between polling requests. */
    private Duration interval;

    /**
     * Inbound request. Nonnull after pre-execute.
     */
    @NonnullAfterInit
    private OAuth2DeviceAuthorizationRequest request;

    public FormOutboundDeviceAuthorizationResponseMessage() {
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Set authentication endpoint not including server name and protocol.
     * 
     * @param endpoint authentication endpoint not including server name and
     *                 protocol
     */
    public void setAuthenticationEndpoint(String endpoint) {
        authenticationEndpoint = endpoint;
    }

    /**
     * Set the strategy used to locate the {@link IdentifierGenerationStrategy} to
     * use.
     * 
     * @param strategy lookup strategy
     */
    public void setIdentifierGeneratorLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, IdentifierGenerationStrategy> strategy) {
        checkSetterPreconditions();

        idGeneratorLookupStrategy = Constraint.isNotNull(strategy,
                "IdentifierGenerationStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated
     * with a given {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext}
     *                 associated with a given {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        checkSetterPreconditions();

        relyingPartyContextLookupStrategy = Constraint.isNotNull(strategy,
                "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set the device code cache instance to use.
     * 
     * @param cache The device code to set.
     */
    public void setDeviceCodesCache(@Nonnull final DeviceCodesCache cache) {
        checkSetterPreconditions();
        deviceCodesCache = Constraint.isNotNull(cache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(deviceCodesCache, "DeviceCodesCache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (getHttpServletRequest() == null) {
            log.error("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (idGeneratorLookupStrategy.apply(profileRequestContext) == null) {
            log.error("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.error("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        final ProfileConfiguration pc = rpCtx.getProfileConfig();
        if (pc instanceof OAuth2DeviceGrantConfiguration) {
            deviceCodeLength = ((OAuth2DeviceGrantConfiguration) pc).getDeviceCodeLength(profileRequestContext);
            userCodeLength = ((OAuth2DeviceGrantConfiguration) pc).getUserCodeLength(profileRequestContext);
            expiration = ((OAuth2DeviceGrantConfiguration) pc).getDeviceCodeLifetime(profileRequestContext);
            interval = ((OAuth2DeviceGrantConfiguration) pc).getPollingInterval(profileRequestContext);
        } else {
            log.error("{} No oauth2 device flow profile configuration associated with this profile request",
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }

        if (profileRequestContext.getInboundMessageContext() == null || !(profileRequestContext
                .getInboundMessageContext().getMessage() instanceof OAuth2DeviceAuthorizationRequest)) {
            log.error("{} No OAuth2DeviceAuthorizationRequest as inbound message", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        request = (OAuth2DeviceAuthorizationRequest) profileRequestContext.getInboundMessageContext().getMessage();
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        String deviceCode = idGeneratorLookupStrategy.apply(profileRequestContext).generateIdentifier();
        if (deviceCode.length() <= deviceCodeLength) {
            log.error("{} Generated device code length is {}, expected length by profile config is {}+1",
                    getLogPrefix(), deviceCode.length(), deviceCodeLength);
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        deviceCode = deviceCode.substring(1, (int) deviceCodeLength + 1);
        String userCode = idGeneratorLookupStrategy.apply(profileRequestContext).generateIdentifier();
        if (userCode.length() <= userCodeLength) {
            log.error("{} Generated user code length is {}, expected length by profile config is {}+1", getLogPrefix(),
                    userCode.length(), userCodeLength);
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_PROFILE_CONFIG);
            return;
        }
        userCode = userCode.substring(1, (int) userCodeLength + 1);
        String rpId = rpCtx.getRelyingPartyId();
        DeviceCodeObject deviceCodeObject = new DeviceCodeObject(deviceCode, new ClientID(rpId),
                new Scope(request.getScope()), request.getAcrValues());
        try {
            log.debug("Storing device flow device code object {} per user code {}",
                    deviceCodeObject.toJSONObject().toString(), userCode);
            if (!deviceCodesCache.storeDeviceCode(deviceCodeObject, userCode, expiration.toMillis())) {
                log.error("{} Failed to set device code to cache.", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
                return;
            }
        } catch (IOException e) {
            log.error("{} Failed to set device code to cache {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
        try {
            ((MessageContext) getOidcResponseContext().getParent())
                    .setMessage(new OAuth2DeviceAuthorizationSuccessResponse(deviceCode, userCode,
                            new URI("https://" + getHttpServletRequest().getServerName() + authenticationEndpoint),
                            new URI("https://" + getHttpServletRequest().getServerName() + authenticationEndpoint
                                    + "?user_code=" + userCode),
                            (int) expiration.toSeconds(), (int) interval.toSeconds()));
        } catch (URISyntaxException e) {
            log.error("{} URI malformed {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return;
        }
    }
}