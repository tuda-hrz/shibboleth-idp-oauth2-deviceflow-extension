/*
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

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.annotation.Nullable;

import com.google.common.base.MoreObjects;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/** Request logging helper class. */
public final class RequestUtil {
    
    /** Private constructor. */
    private RequestUtil() {
        
    }

    /**
     * Helper method to print request to string for logging.
     * 
     * @param httpReq request to be printed
     * @return request as formatted string.
     */
    @Nullable public static String toString(@Nullable final HTTPRequest httpReq) {
        if (httpReq == null) {
            return null;
        }
        final String nl = System.lineSeparator();
        String ret = httpReq.getMethod().toString() + nl;
        final Map<String, List<String>> headers = httpReq.getHeaderMap();
        if (headers != null) {
            ret += "Headers:" + nl;
            for (final Entry<String, List<String>> entry : headers.entrySet()) {
                ret += "\t" + entry.getKey() + ":" + entry.getValue() + nl;
            }
        }
        final Map<String, List<String>> parameters = httpReq.getQueryParameters();
        if (parameters != null) {
            ret += "Parameters:" + nl;
            for (final Entry<String, List<String>> entry : parameters.entrySet()) {
                ret += "\t" + entry.getKey() + ":" + entry.getValue().get(0) + nl;
            }
        }
        return ret;
    }

    /**
     * Helper method for getting protocol log message for client authentication object.
     * 
     * @param authentication The client authentication object
     * @return The log message
     */
    @Nullable public static String getClientAuthenticationLog(@Nullable final ClientAuthentication authentication) {
        return authentication == null ? null : MoreObjects.toStringHelper("ClientAuthentication").omitNullValues()
                .add("clientId", authentication.getClientID())
                .add("method", authentication.getMethod())
                .toString();
    }

    /**
     * Helper method for getting protocol log message for access token object.
     * 
     * @param accessToken The access token object
     * @return The log message
     */
    @Nullable public static String getAccessTokenLog(@Nullable final AccessToken accessToken) {
        return accessToken == null ? null : MoreObjects.toStringHelper("AccessToken").omitNullValues()
                .add("lifetime", accessToken.getLifetime())
                .add("issuedTokenType", accessToken.getIssuedTokenType())
                .add("parameterNames", accessToken.getParameterNames())
                .add("scope", accessToken.getScope())
                .add("value", accessToken.getValue())
                .add("type", accessToken.getType())
                .toString();
    }

    /**
     * Helper method for getting protocol log message for authorization grant object.
     * 
     * @param grant The authorization grant object
     * @return The log message
     */
    @Nullable public static String getAuthorizationGrantLog(@Nullable final AuthorizationGrant grant) {
        if (grant == null) {
            return null;
        }
        if (grant instanceof AuthorizationCodeGrant) {
            final AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant) grant;
            return MoreObjects.toStringHelper(codeGrant).omitNullValues()
                    .add("authorizationCode", codeGrant.getAuthorizationCode())
                    .add("codeVerifier", codeGrant.getCodeVerifier())
                    .add("redirectionURI", codeGrant.getRedirectionURI())
                    .add("type", codeGrant.getType())
                    .toString();
        } else if (grant instanceof RefreshTokenGrant) {
            final RefreshTokenGrant refreshGrant = (RefreshTokenGrant) grant;
            return MoreObjects.toStringHelper(refreshGrant).omitNullValues()
                    .add("refreshToken", getRefreshTokenLog(refreshGrant.getRefreshToken()))
                    .add("type", refreshGrant.getType())
                    .toString();
        } else if (grant instanceof ClientCredentialsGrant) {
            final ClientCredentialsGrant credentialsGrant = (ClientCredentialsGrant) grant;
            return MoreObjects.toStringHelper(credentialsGrant).omitNullValues()
                    .add("type", credentialsGrant.getType())
                    .toString();

        }
        return MoreObjects.toStringHelper(grant).omitNullValues()
                .add("type", grant.getType())
                .toString();
    }

    /**
     * Helper method for getting protocol log message for refresh token object.
     * 
     * @param refreshToken The refresh token object
     * @return The log message
     */
    @Nullable public static String getRefreshTokenLog(@Nullable final RefreshToken refreshToken) {
        return refreshToken == null ? null : MoreObjects.toStringHelper("RefreshToken").omitNullValues()
                .add("parameterNames", refreshToken.getParameterNames())
                .add("value", refreshToken.getValue())
                .toString();
    }

}
