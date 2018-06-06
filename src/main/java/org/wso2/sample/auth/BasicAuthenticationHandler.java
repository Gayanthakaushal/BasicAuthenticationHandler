/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.sample.auth;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.axis2.Constants;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.rest.RESTConstants;
import org.apache.ws.security.util.Base64;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APIKeyValidator;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.gateway.handlers.security.ResourceNotFoundException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;

import javax.cache.Cache;
import javax.cache.CacheConfiguration;
import javax.cache.Caching;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BasicAuthenticationHandler extends AbstractHandler {
    static Logger log = Logger.getLogger(BasicAuthenticationHandler.class.getName());
    private static final String UTF_8 = "UTF-8";
    private static final String SINGLE_NODE = "ALL_IN_ONE";
    private static final String BASIC_AUTH_JWT_CACHE = "BASIC_AUTH_JWT_CACHE";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
    private String deploymentPattern;
    private String clientKey;
    private String clientSecret;
    private  static boolean isBasicAuthJWTCacheInitialized = false;

    public String getClientKey() {
        return clientKey;
    }

    public void setClientKey(String clientKey) {
        this.clientKey = clientKey;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getDeploymentPattern() {
        return deploymentPattern;
    }

    public void setDeploymentPattern(String deploymentPattern) {
        this.deploymentPattern = deploymentPattern;
    }


    protected Cache getBasicAuthJWTCache() {
        String basicAuthJWTCacheExpiry = getAPIManagerConfiguration().getFirstProperty(APIConstants.TOKEN_CACHE_EXPIRY);
        if(!isBasicAuthJWTCacheInitialized && basicAuthJWTCacheExpiry != null ) {
            isBasicAuthJWTCacheInitialized = true;
            return Caching.getCacheManager(
                    APIConstants.API_MANAGER_CACHE_MANAGER).createCacheBuilder(BASIC_AUTH_JWT_CACHE).
                    setExpiry(CacheConfiguration.ExpiryType.MODIFIED, new CacheConfiguration.Duration(TimeUnit.SECONDS,
                            Long.parseLong(basicAuthJWTCacheExpiry))).
                    setExpiry(CacheConfiguration.ExpiryType.ACCESSED, new CacheConfiguration.Duration(TimeUnit.SECONDS,
                            Long.parseLong(basicAuthJWTCacheExpiry))).setStoreByValue(false).build();
        } else {
            return Caching.getCacheManager(
                    APIConstants.API_MANAGER_CACHE_MANAGER).getCache(BASIC_AUTH_JWT_CACHE);
        }
    }

    public boolean handleRequest(MessageContext messageContext) {

        if (log.isDebugEnabled()) {
            log.debug("BasicAuthenticationHandler engaged.");
        }
        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        String username = null;
        String password = null;
        try {
            if (headers != null && headers instanceof Map) {
                Map headersMap = (Map) headers;
                String authHeader = (String) headersMap.get("Authorization");
                if (authHeader == null) {
                    headersMap.clear();
                    sendUnauthorizedResponse(axis2MessageContext, messageContext, "401");
                    return false;
                } else {
                    if (authHeader.contains("Basic")) {
                        String credentials[] =
                                new String(Base64.decode(authHeader.substring(6).trim()))
                                        .split(":");
                        username = credentials[0];
                        password = credentials[1];
                    } else {
                        sendUnauthorizedResponse(axis2MessageContext, messageContext, "401");
                        return false;
                    }
                }
            }
            return authenticateUser(axis2MessageContext, messageContext, username,
                    password);
        } catch (Exception e) {
            log.error("Unable to execute the authorization process : ", e);
            return false;
        }
    }

    public boolean authenticateUser(org.apache.axis2.context.MessageContext axis2MessageContext,
                                    MessageContext messageContext, String username,
                                    String password) throws IOException, NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        String userInfo = username + ":" + password;
        messageDigest.update(userInfo.getBytes());
        String hashedCredentials = new String(messageDigest.digest());
        String jwtToken = (String) getBasicAuthJWTCache().get(hashedCredentials);

        if (jwtToken != null) {
            // TODO: Validate whether the token is expired or not by checking the timestamp of the JWT token and the
            // current time. You can implement your own logic here to check if the token is valid or not.
        } else {
            if (SINGLE_NODE.equals(deploymentPattern)) { //Single node
                OAuth2Service oAuth2Service = (OAuth2Service) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getOSGiService(OAuth2Service.class, null);
                String[] scope = {"openid"};
                OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
                oAuth2AccessTokenReqDTO.setGrantType("password");
                oAuth2AccessTokenReqDTO.setScope(scope);
                oAuth2AccessTokenReqDTO.setClientId(clientKey);
                oAuth2AccessTokenReqDTO.setClientSecret(clientSecret);
                oAuth2AccessTokenReqDTO.setResourceOwnerUsername(username);
                oAuth2AccessTokenReqDTO.setResourceOwnerPassword(password);

                OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO = oAuth2Service.issueAccessToken(oAuth2AccessTokenReqDTO);
                jwtToken = oAuth2AccessTokenRespDTO.getIDToken();
            } else {
                // If the gateway token cache manager is null, create a new cache
                try {
                    jwtToken = generateJWTToken(axis2MessageContext, messageContext, username, password);
                } catch (APISecurityException e) {
                    log.error("User authentication failed!", e);
                    return false;
                }
            }
            getBasicAuthJWTCache().put(hashedCredentials, jwtToken);
        }

        String jwtHeader = getAPIManagerConfiguration().getFirstProperty(APIConstants.JWT_HEADER);
        ((TreeMap) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
                .put(jwtHeader, jwtToken);
        setAuthenticateInfo(messageContext, username);
        setAPIParametersToMessageContext(messageContext);
        return true;
    }

    private String generateJWTToken(org.apache.axis2.context.MessageContext axis2MessageContext,
                                    MessageContext messageContext, String username, String password)
            throws APISecurityException {
        Gson gson = new Gson();
        JsonElement element;
        JsonObject jsonObj = null;

        String revokeUrl = getAPIManagerConfiguration().getFirstProperty(APIConstants.REVOKE_API_URL);
        String tokenUrl = revokeUrl != null ? revokeUrl.replace("revoke", "token") : null;
        tokenUrl = tokenUrl != null ? tokenUrl.replace("'", "") : null;

        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            HttpPost postRequest = new HttpPost(tokenUrl);
            String credentials = Base64.encode((clientKey + ":" + clientSecret).getBytes());
            postRequest.setHeader(CONTENT_TYPE_HEADER, APPLICATION_X_WWW_FORM_URLENCODED);
            postRequest.setHeader(AUTHORIZATION_HEADER, "Basic " + credentials);
            String query = String.format("grant_type=password&username=%s&password=%s&scope=openid",
                    URLEncoder.encode(username, UTF_8), URLEncoder.encode(password, UTF_8));
            StringEntity input = new StringEntity(query);
            postRequest.setEntity(input);

            HttpResponse response = httpClient.execute(postRequest);

            if (response.getStatusLine().getStatusCode() != 200) {
                sendUnauthorizedResponse(axis2MessageContext, messageContext, "401");
                throw new APISecurityException(401, "User is unauthorized.");
            } else {
                BufferedReader br = new BufferedReader(
                        new InputStreamReader((response.getEntity().getContent())));

                String output;
                while ((output = br.readLine()) != null) {
                    System.out.println(output);
                    element = gson.fromJson(output, JsonElement.class);
                    jsonObj = element.getAsJsonObject();
                }
                return String.valueOf(jsonObj.get("id_token"));
            }
        } catch (IOException ex) {
            throw new APISecurityException(500, "User authentication failed!");
        } finally {
            try {
                httpClient.close();
            } catch (IOException e) {
                //ignore
            }
        }
    }


    private void setAuthenticateInfo(MessageContext messageContext, String userName) {
        String clientIP = null;

        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        TreeMap<String, String> transportHeaderMap = (TreeMap<String, String>) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        if (transportHeaderMap != null) {
            clientIP = transportHeaderMap.get(APIMgtGatewayConstants.X_FORWARDED_FOR);
        }

        //Setting IP of the client
        if (clientIP != null && !clientIP.isEmpty()) {
            if (clientIP.indexOf(",") > 0) {
                clientIP = clientIP.substring(0, clientIP.indexOf(","));
            }
        } else {
            clientIP = (String) axis2MessageContext
                    .getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        }

        AuthenticationContext authContext = new AuthenticationContext();
        authContext.setAuthenticated(true);
        authContext.setTier(APIConstants.UNAUTHENTICATED_TIER);
        authContext.setStopOnQuotaReach(true);
        authContext.setApiKey(clientIP);
        authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
        authContext.setUsername(userName);
        authContext.setCallerToken(null);
        authContext.setApplicationName(null);
        authContext.setApplicationId(clientIP);
        authContext.setConsumerKey(null);
        APISecurityUtils.setAuthenticationContext(messageContext, authContext, null);
    }

    private void setAPIParametersToMessageContext(MessageContext messageContext) {

        AuthenticationContext authContext =
                APISecurityUtils.getAuthenticationContext(messageContext);
        org.apache.axis2.context.MessageContext axis2MsgContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        String username = "";
        if (authContext != null) {
            username = authContext.getUsername();
        }

        String context = (String) messageContext.getProperty(RESTConstants.REST_API_CONTEXT);
        String apiVersion = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API);

        String apiPublisher =
                (String) messageContext.getProperty(APIMgtGatewayConstants.API_PUBLISHER);
        //if publisher is null,extract the publisher from the api_version
        if (apiPublisher == null) {
            int ind = apiVersion.indexOf("--");
            apiPublisher = apiVersion.substring(0, ind);
            if (apiPublisher.contains(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT)) {
                apiPublisher = apiPublisher.replace(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT,
                        APIConstants.EMAIL_DOMAIN_SEPARATOR);
            }
        }
        int index = apiVersion.indexOf("--");

        if (index != -1) {
            apiVersion = apiVersion.substring(index + 2);
        }

        String api = apiVersion.split(":")[0];
        String version =
                (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
        String resource = extractResource(messageContext);
        String method = (String) (axis2MsgContext.getProperty(Constants.Configuration.HTTP_METHOD));
        String hostName = APIUtil.getHostAddress();

        messageContext.setProperty(APIMgtGatewayConstants.USER_ID, username);
        messageContext.setProperty(APIMgtGatewayConstants.CONTEXT, context);
        messageContext.setProperty(APIMgtGatewayConstants.API_VERSION, apiVersion);
        messageContext.setProperty(APIMgtGatewayConstants.API, api);
        messageContext.setProperty(APIMgtGatewayConstants.VERSION, version);
        messageContext.setProperty(APIMgtGatewayConstants.RESOURCE, resource);
        messageContext.setProperty(APIMgtGatewayConstants.HTTP_METHOD, method);
        messageContext.setProperty(APIMgtGatewayConstants.HOST_NAME, hostName);
        messageContext.setProperty(APIMgtGatewayConstants.API_PUBLISHER, apiPublisher);

        APIKeyValidator validator = new APIKeyValidator(null);
        try {
            VerbInfoDTO verb = validator.findMatchingVerb(messageContext);
            if (verb != null) {
                messageContext.setProperty(APIConstants.VERB_INFO_DTO, verb);
            }
        } catch (ResourceNotFoundException e) {
            log.error("Could not find matching resource for request", e);
        } catch (APISecurityException e) {
            log.error("APISecurityException for request:", e);
        }
    }

    private String extractResource(MessageContext mc) {
        String resource = "/";
        Pattern pattern = Pattern.compile("^/.+?/.+?([/?].+)$");
        Matcher matcher =
                pattern.matcher((String) mc.getProperty(RESTConstants.REST_FULL_REQUEST_PATH));
        if (matcher.find()) {
            resource = matcher.group(1);
        }
        return resource;
    }

    private void sendUnauthorizedResponse(org.apache.axis2.context.MessageContext axis2MessageContext,
                                          MessageContext messageContext, String status) {
        axis2MessageContext.setProperty("HTTP_SC", status);
        axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
        messageContext.setProperty("RESPONSE", "true");
        messageContext.setTo(null);
        Axis2Sender.sendBack(messageContext);
    }

    public Map getProperties() {
        log.info("getProperties");
        return null;
    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    private APIManagerConfiguration getAPIManagerConfiguration () {
        return BasicAuthServiceComponent.getAmConfigService().getAPIManagerConfiguration();
    }
}