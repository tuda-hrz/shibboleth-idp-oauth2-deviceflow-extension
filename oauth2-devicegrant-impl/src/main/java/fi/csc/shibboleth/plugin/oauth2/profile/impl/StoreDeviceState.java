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
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate.DeviceUserApprovalLookupFunction;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.profile.context.navigate.DeviceUserCodeLookupFunction;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodeObject;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceCodesCache;
import fi.csc.shibboleth.plugin.oauth2.devicegrant.storage.DeviceStateObject;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.ParseException;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseConsentContext;
import net.shibboleth.idp.plugin.oidc.op.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import net.shibboleth.idp.plugin.oidc.op.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import net.shibboleth.idp.plugin.oidc.op.token.support.AccessTokenClaimsSet;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.oidc.profile.config.logic.AttributeConsentFlowEnabledPredicate;
import net.shibboleth.oidc.profile.oauth2.config.OAuth2AccessTokenProducingProfileConfiguration;
import net.shibboleth.profile.config.ProfileConfiguration;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.profile.context.navigate.IssuerLookupFunction;
import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.security.DataSealer;
import net.shibboleth.shared.security.DataSealerException;
import net.shibboleth.shared.security.IdentifierGenerationStrategy;
import net.shibboleth.shared.security.impl.SecureRandomIdentifierGenerationStrategy;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;

/**
 * Action storing user approval action, approved or denied to
 * {@link DeviceCodesCache} as a {@link DeviceStateObject}. In the case user
 * approved the request the {@link DeviceStateObject} contains a access token
 * that may be queried by a trusted rp using Device Code.
 */
public class StoreDeviceState extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(StoreDeviceState.class);

    /** Expiration of device/user codes in milliseconds. */
    private Duration expiration;

    /** Device code matching the user code. */
    @Nullable
    String deviceCode;

    /** Cache for DeviceCodeObjects and DeviceStateObjects. */
    @NonnullAfterInit
    private DeviceCodesCache deviceCodesCache;

    /** Access Token lifetime. */
    private Duration accessTokenLifetime;

    /** Data sealer for handling access token. */
    @Nonnull
    private final DataSealer dataSealer;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a
     * given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Relying party information. */
    @Nullable
    RelyingPartyContext rpCtx;

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /**
     * Predicate used to check if consent is enabled with a given
     * {@link ProfileRequestContext}.
     */
    @Nonnull
    private Predicate<ProfileRequestContext> consentEnabledPredicate;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /** The generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /**
     * Strategy used to locate the
     * {@link OIDCAuthenticationResponseTokenClaimsContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> tokenClaimsContextLookupStrategy;

    /**
     * Strategy used to locate the {@link OIDCAuthenticationResponseConsentContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> consentContextLookupStrategy;

    /** Strategy to locate user code. */
    @Nonnull
    private Function<MessageContext, String> userCodeLookupStrategy;

    /** Strategy to locate user approval. */
    @Nonnull
    private Function<MessageContext, Boolean> userApprovalLookupStrategy;

    Set<String> audiences;

    /**
     * Constructor.
     * 
     * @param sealer sealer to encrypt/hmac access token.
     */
    public StoreDeviceState(@Nonnull @ParameterName(name = "sealer") final DataSealer sealer) {
        userCodeLookupStrategy = new DeviceUserCodeLookupFunction();
        userApprovalLookupStrategy = new DeviceUserApprovalLookupFunction();

        tokenClaimsContextLookupStrategy = new ChildContextLookup<>(OIDCAuthenticationResponseTokenClaimsContext.class)
                .compose(new OIDCAuthenticationResponseContextLookupFunction());
        consentContextLookupStrategy = new ChildContextLookup<>(OIDCAuthenticationResponseConsentContext.class)
                .compose(new OIDCAuthenticationResponseContextLookupFunction());
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        consentEnabledPredicate = new AttributeConsentFlowEnabledPredicate();
        dataSealer = Constraint.isNotNull(sealer, "DataSealer cannot be null");
        issuerLookupStrategy = (Function<ProfileRequestContext, String>) new IssuerLookupFunction();
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
    }

    /**
     * Set strategy to locate user code.
     * 
     * @param strategy Strategy to locate user code
     */
    public void setDeviceUserCodeLookupStrategy(@Nonnull final Function<MessageContext, String> strategy) {
        checkSetterPreconditions();
        userCodeLookupStrategy = Constraint.isNotNull(strategy,
                "DeviceUserCodeLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set strategy to locate user approval.
     * 
     * @param strategy Strategy to locate user approval
     */
    public void setDeviceUserApprovalLookupStrategy(@Nonnull final Function<MessageContext, Boolean> strategy) {
        checkSetterPreconditions();
        userApprovalLookupStrategy = Constraint.isNotNull(strategy,
                "DeviceUserApprovalLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the device code cache instance to use.
     * 
     * @param cache The device code cache to set.
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

    /**
     * Set the strategy used to locate the
     * {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseTokenClaimsContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> strategy) {
        checkSetterPreconditions();
        tokenClaimsContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseTokenClaimsContextt lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the
     * {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseConsentContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> strategy) {
        checkSetterPreconditions();
        consentContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseConsentContext lookup strategy cannot be null");
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
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        checkSetterPreconditions();
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the predicate used to check if consent is enabled with a given
     * {@link ProfileRequestContext}.
     * 
     * @param predicate predicate used to check if consent is enabled with a given
     *                  {@link ProfileRequestContext}.
     */
    public void setConsentEnabledPredicate(@Nonnull final Predicate<ProfileRequestContext> predicate) {
        checkSetterPreconditions();
        consentEnabledPredicate = Constraint.isNotNull(predicate,
                "predicate used to check if consent is enabled cannot be null");
    }

    // Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        String userCode = userCodeLookupStrategy.apply(profileRequestContext.getInboundMessageContext());
        if (userCode == null || userCode.isEmpty()) {
            log.error("{} No user code", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return false;
        }
        try {
            DeviceCodeObject deviceCodeObject = deviceCodesCache.getDeviceCode(userCode);
            if (deviceCodeObject == null || deviceCodeObject.getDeviceCode() == null) {
                log.error("{} No device code for user code", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return false;
            }
            deviceCode = deviceCodeObject.getDeviceCode();
        } catch (IOException | ParseException e) {
            log.error("{} Error accessing device code cache", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return false;
        }
        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.error("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        final ProfileConfiguration pc = rpCtx.getProfileConfig();
        if (pc != null && pc instanceof OAuth2DeviceGrantConfiguration) {
            accessTokenLifetime = ((OAuth2AccessTokenProducingProfileConfiguration) pc)
                    .getAccessTokenLifetime(profileRequestContext);
            expiration = ((OAuth2DeviceGrantConfiguration) pc).getDeviceCodeLifetime(profileRequestContext);
            audiences = ((OAuth2DeviceGrantConfiguration) pc)
                    .getAdditionalAudiencesForAccessToken(profileRequestContext);
        } else {
            log.error("{} No oidc profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class);
        if (subjectCtx == null) {
            log.error("{} No subject context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        idGenerator = idGeneratorLookupStrategy.apply(profileRequestContext);
        if (idGenerator == null) {
            log.error("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }
    // Checkstyle: CyclomaticComplexity ON

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        DeviceStateObject deviceStateObject = null;
        if (!userApprovalLookupStrategy.apply(profileRequestContext.getInboundMessageContext())) {
            deviceStateObject = new DeviceStateObject(DeviceStateObject.State.DENIED);
        } else {
            Instant dateExp = Instant.now().plus(accessTokenLifetime);
            ClaimsSet claims = null;
            ClaimsSet claimsUI = null;
            OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx = tokenClaimsContextLookupStrategy
                    .apply(profileRequestContext);
            if (tokenClaimsCtx != null) {
                claims = tokenClaimsCtx.getClaims();
                claimsUI = tokenClaimsCtx.getUserinfoClaims();
            }
            AccessTokenClaimsSet claimsSet;
            JSONArray consented = null;
            OIDCAuthenticationResponseConsentContext consentCtx = consentContextLookupStrategy
                    .apply(profileRequestContext);
            if (consentCtx != null) {
                consented = consentCtx.getConsentedAttributes();
            }
            try {
                claimsSet = new AccessTokenClaimsSet.Builder().setJWTID(idGenerator)
                        .setACR(getOidcResponseContext().getAcr()).setClientID(new ClientID(rpCtx.getRelyingPartyId()))
                        .setIssuer(issuerLookupStrategy.apply(profileRequestContext)).setAudience(audiences)
                        .setPrincipal(subjectCtx.getPrincipalName()).setSubject(getOidcResponseContext().getSubject())
                        .setIssuedAt(Instant.now()).setExpiresAt(dateExp).setACR(getOidcResponseContext().getAcr())
                        .setAuthenticationTime(getOidcResponseContext().getAuthTime())
                        .setScope(getOidcResponseContext().getScope()).setConsentedClaims(consented).setDlClaims(claims)
                        .setDlClaimsUI(claimsUI).setConsentEnabled(consentEnabledPredicate.test(profileRequestContext))
                        .build();
                deviceStateObject = new DeviceStateObject(DeviceStateObject.State.APPROVED,
                        claimsSet.serialize(dataSealer), System.currentTimeMillis() + accessTokenLifetime.toMillis());
                log.debug("{} Generated access token {} as {} expiring at {}", getLogPrefix(), claimsSet.serialize(),
                        deviceStateObject.getAccessToken(), deviceStateObject.getExpiresAt());
            } catch (DataSealerException e) {
                log.error("{} Access Token generation failed {}", getLogPrefix(), e);
                ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
                return;
            }
        }
        try {
            if (!deviceCodesCache.updateDeviceState(deviceCode, deviceStateObject, expiration.toMillis())) {
                log.error("{} Unable to update device state object to approved ", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
                return;
            }
            log.debug("{} Device {} state updated as {}", getLogPrefix(), deviceCode,
                    deviceStateObject.getState().toString());
        } catch (IOException | ParseException e) {
            log.error("{} Access Token generation failed {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
        }
    }
}