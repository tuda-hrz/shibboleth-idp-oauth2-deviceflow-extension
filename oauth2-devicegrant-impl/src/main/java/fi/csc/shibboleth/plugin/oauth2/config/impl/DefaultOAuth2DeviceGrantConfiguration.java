/*
 * Copyright (c) 2024 CSC- IT Center for Science, www.csc.fi
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

package fi.csc.shibboleth.plugin.oauth2.config.impl;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import fi.csc.shibboleth.plugin.oauth2.config.OAuth2DeviceGrantConfiguration;
import net.shibboleth.oidc.profile.oauth2.config.OAuth2AccessTokenProducingProfileConfiguration;
import net.shibboleth.oidc.profile.oauth2.config.impl.AbstractOAuth2ClientAuthenticableProfileConfiguration;
import net.shibboleth.profile.config.OverriddenIssuerProfileConfiguration;
import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Positive;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.FunctionSupport;
import net.shibboleth.shared.logic.PredicateSupport;
import net.shibboleth.shared.primitive.StringSupport;

public class DefaultOAuth2DeviceGrantConfiguration extends AbstractOAuth2ClientAuthenticableProfileConfiguration
        implements OAuth2DeviceGrantConfiguration, OAuth2AccessTokenProducingProfileConfiguration,
        OverriddenIssuerProfileConfiguration {

    /** Lookup function to override issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Lookup function to supply access token lifetime. */
    @Nonnull
    private Function<ProfileRequestContext, Duration> accessTokenLifetimeLookupStrategy;

    /** Lookup function to supply access token type. */
    @Nonnull
    private Function<ProfileRequestContext, String> accessTokenTypeLookupStrategy;

    /**
     * Lookup function to supply strategy bi-function for manipulating access token
     * claims set.
     */
    @Nonnull
    private Function<ProfileRequestContext, BiFunction<ProfileRequestContext, Map<String, Object>, Map<String, Object>>> accessTokenClaimsSetManipulationStrategyLookupStrategy;

    /** Lookup function to supply device code lifetime. */
    @Nonnull
    private Function<ProfileRequestContext, Duration> deviceCodeLifetimeLookupStrategy;

    /** Lookup function to supply device code length. */
    @Nonnull
    private Function<ProfileRequestContext, Integer> deviceCodeLengthLookupStrategy;

    /** Lookup function to supply user code length. */
    @Nonnull
    private Function<ProfileRequestContext, Integer> userCodeLengthLookupStrategy;

    /** Lookup function to supply polling interval. */
    @Nonnull
    private Function<ProfileRequestContext, Duration> pollingIntervalLookupStrategy;
    
    /** Lookup function to supply additional audiences for ID token. */
    @Nonnull private Function<ProfileRequestContext,Set<String>> assertionAudiencesLookupStrategy;

    /** Whether the access token to be issued is always a bearer access token. */
    @Nonnull
    private Predicate<ProfileRequestContext> alwaysIssueBearerAccessTokenPredicate;

    /**
     * Constructor.
     */
    public DefaultOAuth2DeviceGrantConfiguration() {
        super(OAuth2DeviceGrantConfiguration.PROFILE_ID);
        issuerLookupStrategy = FunctionSupport.constant(null);
        accessTokenLifetimeLookupStrategy = FunctionSupport.constant(Duration.ofMinutes(10));
        accessTokenTypeLookupStrategy = FunctionSupport.constant(null);
        accessTokenClaimsSetManipulationStrategyLookupStrategy = FunctionSupport.constant(null);
        deviceCodeLifetimeLookupStrategy = FunctionSupport.constant(Duration.ofMinutes(10));
        deviceCodeLengthLookupStrategy = FunctionSupport.constant(Integer.valueOf(16));
        userCodeLengthLookupStrategy = FunctionSupport.constant(Integer.valueOf(8));
        pollingIntervalLookupStrategy = FunctionSupport.constant(Duration.ofSeconds(5));
        assertionAudiencesLookupStrategy = FunctionSupport.constant(null);
        alwaysIssueBearerAccessTokenPredicate = PredicateSupport.alwaysFalse();
    }

    @Override
    @Positive
    @Nonnull
    public Duration getAccessTokenLifetime(@Nullable final ProfileRequestContext profileRequestContext) {
        final Duration lifetime = accessTokenLifetimeLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(lifetime != null && !lifetime.isZero() && !lifetime.isNegative(),
                "Access token lifetime must be greater than 0");
        return lifetime;
    }

    /**
     * Set the lifetime of an access token.
     * 
     * @param lifetime lifetime of an access token
     */
    public void setAccessTokenLifetime(@Positive @Nonnull final Duration lifetime) {
        Constraint.isTrue(lifetime != null && !lifetime.isZero() && !lifetime.isNegative(),
                "Access token lifetime must be greater than 0");

        accessTokenLifetimeLookupStrategy = FunctionSupport.constant(lifetime);
    }

    /**
     * Set a lookup strategy for the access token lifetime.
     *
     * @param strategy lookup strategy
     */
    public void setAccessTokenLifetimeLookupStrategy(
            @Nullable final Function<ProfileRequestContext, Duration> strategy) {
        accessTokenLifetimeLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Nullable
    @NotEmpty
    public String getAccessTokenType(@Nullable final ProfileRequestContext profileRequestContext) {
        return accessTokenTypeLookupStrategy.apply(profileRequestContext);
    }

    /**
     * Set access token type.
     * 
     * @param type token type, or null for unspecified/opaque
     * 
     */
    public void setAccessTokenType(@Nullable @NotEmpty final String type) {
        accessTokenTypeLookupStrategy = FunctionSupport.constant(StringSupport.trimOrNull(type));
    }

    /**
     * Set lookup strategy for access token type.
     * 
     * @param strategy lookup strategy
     * 
     */
    public void setAccessTokenTypeLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        accessTokenTypeLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Nonnull
    public BiFunction<ProfileRequestContext, Map<String, Object>, Map<String, Object>> getAccessTokenClaimsSetManipulationStrategy(
            @Nullable final ProfileRequestContext profileRequestContext) {
        return accessTokenClaimsSetManipulationStrategyLookupStrategy.apply(profileRequestContext);
    }

    /**
     * Set the bi-function for manipulating access token claims set.
     * 
     * @param strategy bi-function for manipulating access token claims set
     * 
     */
    public void setAccessTokenClaimsSetManipulationStrategy(
            @Nullable final BiFunction<ProfileRequestContext, Map<String, Object>, Map<String, Object>> strategy) {
        accessTokenClaimsSetManipulationStrategyLookupStrategy = FunctionSupport.constant(strategy);
    }

    /**
     * Set a lookup strategy for the bi-function for manipulating access token
     * claims set.
     *
     * @param strategy lookup strategy
     * 
     */
    public void setAccessTokenClaimsSetManipulationStrategyLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, BiFunction<ProfileRequestContext, Map<String, Object>, Map<String, Object>>> strategy) {
        accessTokenClaimsSetManipulationStrategyLookupStrategy = Constraint.isNotNull(strategy,
                "Lookup strategy cannot be null");
    }

    @Override
    @Positive
    @Nonnull
    public Duration getDeviceCodeLifetime(@Nullable final ProfileRequestContext profileRequestContext) {
        final Duration lifetime = deviceCodeLifetimeLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(lifetime != null && !lifetime.isZero() && !lifetime.isNegative(),
                "Access token lifetime must be greater than 0");
        return lifetime;
    }

    /**
     * Set the lifetime of an device code.
     * 
     * @param lifetime lifetime of an device code
     */
    public void setDeviceCodeLifetime(@Positive @Nonnull final Duration lifetime) {
        Constraint.isTrue(lifetime != null && !lifetime.isZero() && !lifetime.isNegative(),
                "Device code lifetime must be greater than 0");

        accessTokenLifetimeLookupStrategy = FunctionSupport.constant(lifetime);
    }

    /**
     * Set a lookup strategy for the device code lifetime.
     *
     * @param strategy lookup strategy
     */
    public void setDeviceCodeLifetimeLookupStrategy(
            @Nullable final Function<ProfileRequestContext, Duration> strategy) {
        accessTokenLifetimeLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Positive
    @Nonnull
    public Integer getDeviceCodeLength(@Nullable final ProfileRequestContext profileRequestContext) {
        final Integer codeLength = deviceCodeLengthLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(codeLength != null && codeLength > 9, "Device code length must be at least 10");
        return codeLength;
    }

    /**
     * Set the device code length.
     * 
     * @param codeLength length of the device code.
     */
    public void setDeviceCodeLength(@Positive @Nonnull final Integer codeLength) {
        Constraint.isTrue(codeLength != null && codeLength > 9, "Device code length must be at least 10");

        deviceCodeLengthLookupStrategy = FunctionSupport.constant(codeLength);
    }

    /**
     * Set a lookup strategy for the device code length.
     *
     * @param strategy lookup strategy
     */
    public void setDeviceCodeLengthLookupStrategy(@Nullable final Function<ProfileRequestContext, Integer> strategy) {
        deviceCodeLengthLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Positive
    @Nonnull
    public Integer getUserCodeLength(@Nullable final ProfileRequestContext profileRequestContext) {
        final Integer codeLength = userCodeLengthLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(codeLength != null && codeLength > 5, "Device code length must be at least 6");
        return codeLength;
    }

    /**
     * Set the user code length.
     * 
     * @param codeLength length of the user code.
     */
    public void setUserCodeLength(@Positive @Nonnull final Integer codeLength) {
        Constraint.isTrue(codeLength != null && codeLength > 5, "User code length must be at least 6");

        userCodeLengthLookupStrategy = FunctionSupport.constant(codeLength);
    }

    /**
     * Set a lookup strategy for the user code length.
     *
     * @param strategy lookup strategy
     */
    public void setUserCodeLengthLookupStrategy(@Nullable final Function<ProfileRequestContext, Integer> strategy) {
        deviceCodeLengthLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    @Override
    @Positive
    @Nonnull
    public Duration getPollingInterval(@Nullable final ProfileRequestContext profileRequestContext) {
        final Duration interval = pollingIntervalLookupStrategy.apply(profileRequestContext);

        Constraint.isTrue(interval != null && !interval.isZero() && !interval.isNegative(),
                "Polling interval must be greater than 0");
        return interval;
    }

    /**
     * Set the polling interval.
     * 
     * @param interval polling interval
     */
    public void setPollingInterval(@Positive @Nonnull final Duration interval) {
        Constraint.isTrue(interval != null && !interval.isZero() && !interval.isNegative(),
                "Polling interval must be greater than 0");

        pollingIntervalLookupStrategy = FunctionSupport.constant(interval);
    }

    /**
     * Set a lookup strategy for polling interval.
     *
     * @param strategy lookup strategy
     */
    public void setPollingIntervalLookupStrategy(@Nullable final Function<ProfileRequestContext, Duration> strategy) {
        pollingIntervalLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    @NotEmpty
    public String getIssuer(@Nullable final ProfileRequestContext profileRequestContext) {
        return issuerLookupStrategy.apply(profileRequestContext);
    }

    /**
     * Set overridden issuer value.
     * 
     * @param issuer issuer value
     */
    public void setIssuer(@Nullable @NotEmpty final String issuer) {
        issuerLookupStrategy = FunctionSupport.constant(issuer);
    }

    /**
     * Sets lookup strategy for overridden issuer value.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        issuerLookupStrategy = Constraint.isNotNull(strategy, "Issuer lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
   @Override
   @Nonnull @NonnullElements @NotLive public Set<String> getAdditionalAudiencesForAccessToken(
           @Nullable final ProfileRequestContext profileRequestContext) {
       
       final Set<String> audiences = assertionAudiencesLookupStrategy.apply(profileRequestContext);
       if (audiences != null) {
           return CollectionSupport.copyToSet(audiences);
       }
       return CollectionSupport.emptySet();
   }

   /**
    * Set the set of audiences, in addition to the relying party(ies) to which the IdP is issuing the ID Token, with
    * which the token may be shared.
    * 
    * @param audiences the additional audiences
    */
   public void setAdditionalAudiencesForAccessToken(@Nullable @NonnullElements final Collection<String> audiences) {

       if (audiences == null || audiences.isEmpty()) {
           assertionAudiencesLookupStrategy = FunctionSupport.constant(null);
       } else {
           assertionAudiencesLookupStrategy = FunctionSupport.constant(
                   Set.copyOf(StringSupport.normalizeStringCollection(audiences)));
       }
   }

   /**
    * Set a lookup strategy for the set of audiences, in addition to the relying party(ies) to which the IdP
    * is issuing the ID Token, with which the token may be shared.
    *
    * @param strategy  lookup strategy
    */
   public void setAdditionalAudiencesForIdTokenLookupStrategy(
           @Nonnull final Function<ProfileRequestContext,Set<String>> strategy) {
       assertionAudiencesLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
   }

   @Override
   public boolean isAlwaysIssueBearerAccessToken(@Nullable final ProfileRequestContext profileRequestContext) {
       return alwaysIssueBearerAccessTokenPredicate.test(profileRequestContext);
   }

   /**
    * Set whether the access token to be issued is always a bearer access token.
    *
    * @param flag flag to set
    *
    * @since 3.2.0
    */
   public void setAlwaysIssueBearerAccessToken(final boolean flag) {
       alwaysIssueBearerAccessTokenPredicate = flag ? PredicateSupport.alwaysTrue() : PredicateSupport.alwaysFalse();
   }

   /**
    * Set a condition to determine whether the access token to be issued is always
    * a bearer access token.
    *
    * @param condition condition to set
    *
    * @since 3.2.0
    */
   public void setAlwaysIssueBearerAccessTokenPredicate(@Nonnull final Predicate<ProfileRequestContext> condition) {
       alwaysIssueBearerAccessTokenPredicate = Constraint.isNotNull(condition,
               "Always issue bearer access token predicate cannot be null");
   }
}
