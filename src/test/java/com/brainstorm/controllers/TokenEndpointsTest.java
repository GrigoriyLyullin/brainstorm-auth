package com.brainstorm.controllers;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.NestedServletException;

import java.io.UnsupportedEncodingException;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Unit tests for provided endpoints. The URL paths provided by the framework are following:
 * <ul>
 * <li>/oauth/authorize (the authorization endpoint)</li>
 * <li>/oauth/token (the token endpoint)</li>
 * <li>/oauth/confirm_access (user posts approval for grants here)</li>
 * <li>/oauth/error (used to render errors in the authorization server)</li>
 * <li>/oauth/check_token (used by Resource Servers to decode access tokens)</li>
 * <li>/oauth/token_key (exposes public key for token verification if using JWT tokens)</li>
 * </ul>
 * <p>
 * The custom URL paths:
 * <ul>
 * <li>/oauth/revoke_token (used for token revocation)</li>
 * </ul>
 * See also: <a href="https://projects.spring.io/spring-security-oauth/docs/oauth2.html">OAuth 2 Developers Guide</a>
 *
 * @author Grigorii Liullin
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
class TokenEndpointsTest {

    private static final Logger LOG = LoggerFactory.getLogger(TokenEndpointsTest.class);

    /**
     * The authorization endpoint.
     */
    private static final String OAUTH_AUTHORIZE = "/oauth/authorize";

    /**
     * Exposes public key for token verification if using JWT tokens.
     */
    private static final String OAUTH_TOKEN_KEY = "/oauth/token_key";

    /**
     * User posts approval for grants here.
     */
    private static final String OAUTH_CONFIRM_ACCESS = "/oauth/confirm_access";

    /**
     * OAuth 2.0 client_id.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-2.3.1">The OAuth 2.0 Authorization Framework:
     * 2.3.1. Client Password</a>
     */
    private static final String OAUTH2_JWT_CLIENT_ID = "brainstorm-jwt-client";

    /**
     * OAuth 2.0 client_secret. See 'V2__init_data.sql' for the test value.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-2.3.1">The OAuth 2.0 Authorization Framework:
     * 2.3.1. Client Password</a>
     */
    private static final String OAUTH2_JWT_CLIENT_PASSWORD = "admin";

    /**
     * OAuth 2.0 grant_type='password'.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.3.2">The OAuth 2.0 Authorization Framework:
     * 4.3.2. Access Token Request</a>
     */
    private static final String GRANT_TYPE_PASSWORD = "password";

    /**
     * OAuth 2.0 grant_type='refresh_token'.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-6">The OAuth 2.0 Authorization Framework:
     * 6. Refreshing an Access Token</a>
     */
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    /**
     * This URL uses for access token check.
     */
    private static final String OAUTH_CHECK_TOKEN_URL = "/oauth/check_token";

    /**
     * This URL uses for token revocation.
     */
    private static final String OAUTH_REVOKE_TOKEN_URL = "/oauth/revoke_token";

    /**
     * This URL uses for receiving new tokens via password or refresh_token.
     */
    private static final String OAUTH_TOKEN_URL = "/oauth/token";

    /**
     * Username of actual user.
     */
    private static final String TEST_USERNAME = "admin";

    /**
     * Password of actual user.
     */
    private static final String TEST_PASSWORD = "admin";

    /**
     * Used to render errors in the authorization server.
     */
    private static final String OAUTH_ERROR = "/oauth/error";

    // see V2__init_data.sql
    private static final long REFRESH_TOKEN_VALIDITY = 86400L;

    // see V2__init_data.sql
    private static final long ACCESS_TOKEN_VALIDITY = 10800L;

    // It is needed to compare value with some period (target - delta < value < target).
    private static final int DELTA = 60;

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = OAUTH2_JWT_CLIENT_ID, password = OAUTH2_JWT_CLIENT_PASSWORD)
    void checkThatTokenAndCheckTokenURLsAreAvailableForAuthenticatedUsers() throws Exception {
        String payload = String.format("grant_type=%s&username=%s&password=%s", GRANT_TYPE_PASSWORD, TEST_USERNAME,
                TEST_PASSWORD);
        MockHttpServletRequestBuilder request = prepareGetTokenRequest(payload);

        // it is possible to receive token
        MockHttpServletResponse response = mockMvc.perform(request).andExpect(status().isOk()).andReturn().getResponse();
        String accessToken = new JSONObject(response.getContentAsString())
                .getString("access_token");

        // it is possible to check token for authenticated clients
        checkThatAccessTokenIsValid(accessToken);
    }

    @Test
    @WithMockUser(username = OAUTH2_JWT_CLIENT_ID, password = OAUTH2_JWT_CLIENT_PASSWORD)
    void checkThatTokenKeyIsNotAvailableEvenForAuthenticatedUsers() throws Exception {
        // it is NOT possible to receive secret key that has been used for JWT token signing even for authenticated
        // clients
        mockMvc.perform(get(OAUTH_TOKEN_KEY)).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = OAUTH2_JWT_CLIENT_ID, password = OAUTH2_JWT_CLIENT_PASSWORD)
    void checkThatAuthorizeURLIsAvailableForAuthenticatedUsers() throws Exception {
        // this URL forwarded user to error URL if parameters for authorization are missing
        mockMvc.perform(post(OAUTH_AUTHORIZE)).andExpect(status().isUnauthorized()).andExpect(forwardedUrl(OAUTH_ERROR));
    }

    @Test
    @WithMockUser(username = OAUTH2_JWT_CLIENT_ID, password = OAUTH2_JWT_CLIENT_PASSWORD)
    void checkThatConfirmAccessURLIsAvailableForAuthenticatedUsers() {
        // currently this URL is not working, but it is not needed for now
        assertThrows(NestedServletException.class, () ->
                mockMvc.perform(post(OAUTH_CONFIRM_ACCESS))
                        .andDo(print())
                        .andExpect(status().is5xxServerError()));
    }

    @Test
    void checkThatTokenURLsAreNotAvailableForNonAuthenticatedUsers() throws Exception {
        // requests to the following URLs without filled Basic Authentication header (with client_id:client_secret)
        // should lead to response with code 401
        mockMvc.perform(post(OAUTH_TOKEN_URL)).andExpect(status().isUnauthorized());
        mockMvc.perform(post(OAUTH_CHECK_TOKEN_URL)).andExpect(status().isUnauthorized());
        mockMvc.perform(post(OAUTH_AUTHORIZE)).andExpect(status().isUnauthorized());
        mockMvc.perform(get(OAUTH_TOKEN_KEY)).andExpect(status().isUnauthorized());
    }

    @Test
    void checkThatErrorUrlAccessibleForAll() throws Exception {
        // this URL should be available for all (even non-authenticated) users
        mockMvc.perform(post(OAUTH_ERROR)).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = OAUTH2_JWT_CLIENT_ID, password = OAUTH2_JWT_CLIENT_PASSWORD)
    void receiveNewTokenUsingRefreshToken() throws Exception {
        String payload = String.format("grant_type=%s&username=%s&password=%s", GRANT_TYPE_PASSWORD, TEST_USERNAME,
                TEST_PASSWORD);
        MockHttpServletRequestBuilder requestNewTokenUsingPassword = prepareGetTokenRequest(payload);
        MockHttpServletResponse responseWithNewTokensUsingPassword = mockMvc.perform(requestNewTokenUsingPassword)
                .andExpect(status().isOk()).andReturn().getResponse();

        String accessTokenUsingPassword = retrieveDataFromResponseJSON(responseWithNewTokensUsingPassword, "access_token");
        checkThatAccessTokenIsValid(accessTokenUsingPassword);

        String refreshToken = retrieveDataFromResponseJSON(responseWithNewTokensUsingPassword, "refresh_token");

        String refreshTokenPayload = String.format("grant_type=%s&refresh_token=%s", GRANT_TYPE_REFRESH_TOKEN, refreshToken);
        MockHttpServletRequestBuilder requestNewTokenUsingRefreshToken = prepareGetTokenRequest(refreshTokenPayload);

        MockHttpServletResponse responseWithNewTokensUsingRefreshToken = mockMvc
                .perform(requestNewTokenUsingRefreshToken)
                .andExpect(status().isOk())
                .andReturn().getResponse();

        String accessTokenUsingRefreshToken = retrieveDataFromResponseJSON(responseWithNewTokensUsingRefreshToken, "access_token");
        checkThatAccessTokenIsValid(accessTokenUsingRefreshToken);

        assertNotEquals(accessTokenUsingPassword, accessTokenUsingRefreshToken);
    }

    @Test
    @WithMockUser(username = OAUTH2_JWT_CLIENT_ID, password = OAUTH2_JWT_CLIENT_PASSWORD)
    void tokensAreInJWTFormatAndHasValidExpiration() throws Exception {
        String payload = String.format("grant_type=%s&username=%s&password=%s", GRANT_TYPE_PASSWORD, TEST_USERNAME,
                TEST_PASSWORD);
        MockHttpServletRequestBuilder requestNewTokenUsingPassword = prepareGetTokenRequest(payload);
        MockHttpServletResponse responseWithNewTokensUsingPassword = mockMvc.perform(requestNewTokenUsingPassword)
                .andExpect(status().isOk()).andReturn().getResponse();

        long expiresIn = Long.parseLong(retrieveDataFromResponseJSON(responseWithNewTokensUsingPassword,
                "expires_in"));
        LOG.debug("expires_in: " + expiresIn);

        assertEquals(ACCESS_TOKEN_VALIDITY, expiresIn, DELTA);

        String accessToken = retrieveDataFromResponseJSON(responseWithNewTokensUsingPassword, "access_token");
        String decodedAccessToken = JwtHelper.decode(accessToken).getClaims();
        LOG.debug("decodedAccessToken: " + decodedAccessToken);

        assertEquals(TEST_USERNAME, retrieveDataFromJSON(decodedAccessToken, "user_name"));
        assertEquals(OAUTH2_JWT_CLIENT_ID, retrieveDataFromJSON(decodedAccessToken, "client_id"));

        long currentTime = System.currentTimeMillis() / 1000L;
        LOG.debug(String.format("currentTime: %s", currentTime));
        long accessTokenExp = Long.parseLong(retrieveDataFromJSON(decodedAccessToken, "exp"));

        assertEquals(accessTokenExp, currentTime + ACCESS_TOKEN_VALIDITY, DELTA);

        String refreshToken = retrieveDataFromResponseJSON(responseWithNewTokensUsingPassword, "refresh_token");
        String decodedRefreshToken = JwtHelper.decode(refreshToken).getClaims();
        LOG.debug("decodedRefreshToken: " + decodedRefreshToken);

        assertEquals(TEST_USERNAME, retrieveDataFromJSON(decodedRefreshToken, "user_name"));
        assertEquals(OAUTH2_JWT_CLIENT_ID, retrieveDataFromJSON(decodedRefreshToken, "client_id"));

        currentTime = System.currentTimeMillis() / 1000L;
        LOG.debug(String.format("currentTime: %s", currentTime));
        long refreshTokenExp = Long.valueOf(retrieveDataFromJSON(decodedRefreshToken, "exp"));
        assertEquals(refreshTokenExp, currentTime + REFRESH_TOKEN_VALIDITY, DELTA);
    }

    /**
     * Prepares get token request for /oauth/token endpoint.
     *
     * @param payload request parameters
     * @return prepared request
     */
    private MockHttpServletRequestBuilder prepareGetTokenRequest(String payload) {
        return post(OAUTH_TOKEN_URL).contentType(MediaType.APPLICATION_FORM_URLENCODED).content(payload);
    }

    /**
     * Returns JSON value for specified key from the HTTP Response.
     *
     * @param response response
     * @param key      JSON key
     * @return JSON value if any
     * @throws JSONException                if it is not a valid JSON
     * @throws UnsupportedEncodingException if content is in unsupported encoding
     */
    private String retrieveDataFromResponseJSON(MockHttpServletResponse response, String key) throws JSONException,
            UnsupportedEncodingException {
        return retrieveDataFromJSON(response.getContentAsString(), key);
    }

    /**
     * Returns JSON value for specified key from JSON string.
     *
     * @param json string with JSON
     * @param key  JSON key
     * @return JSON value if any
     */
    private String retrieveDataFromJSON(String json, String key) throws JSONException {
        return new JSONObject(json).getString(key);
    }

    /**
     * Checks that access_token is valid.
     *
     * @param accessToken access token to check
     * @throws Exception exception
     */
    private void checkThatAccessTokenIsValid(String accessToken) throws Exception {
        mockMvc.perform(post(OAUTH_CHECK_TOKEN_URL).param("token", accessToken)).andExpect(status().isOk());
    }

    /**
     * Checks that access_token is invalid.
     *
     * @param accessToken access token to check
     * @throws Exception exception
     */
    private void checkThatAccessTokenIsInvalid(String accessToken) throws Exception {
        mockMvc.perform(post(OAUTH_CHECK_TOKEN_URL).param("token", accessToken)).andExpect(status().isBadRequest());
    }
}
