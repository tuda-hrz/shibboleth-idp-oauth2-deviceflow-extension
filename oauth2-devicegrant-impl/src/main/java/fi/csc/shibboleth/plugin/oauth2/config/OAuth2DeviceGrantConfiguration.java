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

package fi.csc.shibboleth.plugin.oauth2.config;

import java.time.Duration;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.profile.config.ConditionalProfileConfiguration;
import net.shibboleth.shared.annotation.ConfigurationSetting;
import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Positive;

/**
 * Profile configuration for the OAuth2 Device Grant.
 */
public interface OAuth2DeviceGrantConfiguration extends ConditionalProfileConfiguration {

    /** OAuth2 Device Grant URI. */
    @Nonnull
    @NotEmpty
    public static final String PROTOCOL_URI = "https://datatracker.ietf.org/doc/html/rfc8628";

    /** ID for this profile configuration. */
    @Nonnull
    @NotEmpty
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oauth.net/2/device-flow";

    /**
     * Get device code length.
     *
     * <p>
     * Defaults to 16.
     * </p>
     *
     * @param profileRequestContext profile request context
     *
     * @return device code length
     */
    @ConfigurationSetting(name = "deviceCodeLength")
    @Positive
    @Nonnull
    Integer getDeviceCodeLength(@Nullable final ProfileRequestContext profileRequestContext);

    /**
     * Get user code length.
     *
     * <p>
     * Defaults to 8.
     * </p>
     *
     * @param profileRequestContext profile request context
     *
     * @return device code length
     */
    @ConfigurationSetting(name = "userCodeLength")
    @Positive
    @Nonnull
    Integer getUserCodeLength(@Nullable final ProfileRequestContext profileRequestContext);

    /**
     * Get polling interval.
     *
     * <p>
     * Defaults to 5 seconds.
     * </p>
     *
     * @param profileRequestContext profile request context
     *
     * @return polling interval
     */
    @ConfigurationSetting(name = "pollingInterval")
    @Positive
    @Nonnull
    Duration getPollingInterval(@Nullable final ProfileRequestContext profileRequestContext);

    /**
     * Get device code lifetime.
     *
     * <p>
     * Defaults to 5 minutes.
     * </p>
     *
     * @param profileRequestContext profile request context
     *
     * @return device code lifetime
     */
    @ConfigurationSetting(name = "deviceCodeLifetime")
    @Positive
    @Nonnull
    Duration getDeviceCodeLifetime(@Nullable final ProfileRequestContext profileRequestContext);
    
    /**
     * 
     * @param profileRequestContext
     * @return
     */
    @Nonnull @NonnullElements @NotLive public Set<String> getAdditionalAudiencesForAccessToken(
            @Nullable final ProfileRequestContext profileRequestContext);
}
