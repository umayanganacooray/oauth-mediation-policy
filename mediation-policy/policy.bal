import ballerina/http;
import choreo/mediation;
import ballerina/time;
import ballerina/log;
import ballerina/lang.runtime;

final TokenCacheManager tokenCacheManager = new TokenCacheManager();
http:Client tokenClient = check new("https://example.com/token");

@mediation:RequestFlow
public function oauthIn(mediation:Context ctx, http:Request req,
                        string tokenEndpointUrl, string clientId, string clientSecret, string headerName)
                        returns http:Response|false|error? {

    OAuthEndpoint oauthEndpoint = {
        tokenApiUrl: tokenEndpointUrl,
        clientId: clientId,
        clientSecret: clientSecret
    };
    
    http:Client|error tokenClientResult = new(tokenEndpointUrl);
    if (tokenClientResult is error) {
        log:printError("Failed to initialize token client", 'error = tokenClientResult);
        return error("Failed to initialize token client");
    }
    tokenClient = tokenClientResult;

    TokenResponse token = check getValidToken(oauthEndpoint);
    tokenCacheManager.putToken(oauthEndpoint.clientId, token);
    string authorizationHeader = headerName == "Authorization" ? "Bearer " + token.accessToken : token.accessToken;
    req.setHeader(headerName, authorizationHeader);
    
    return;
}

@mediation:ResponseFlow
public function oauthOut(mediation:Context ctx, http:Request req, http:Response response,
                         string tokenEndpointUrl, string clientId, string clientSecret, string headerName)
                         returns http:Response|false|error? {

    if (response.statusCode == http:STATUS_UNAUTHORIZED) {
        log:printError("Received 401 Unauthorized response");
        return error("Unauthorized response from backend");
    }
    return;
}

@mediation:FaultFlow
public function oauthFault(mediation:Context ctx, http:Request req, http:Response? res, http:Response errFlowRes, error e,
                           string tokenEndpointUrl, string clientId, string clientSecret, string headerName)
                           returns http:Response|false|error? {

    log:printError("OAuth mediation fault occurred", 'error = e);
    return errFlowRes;
}

function getValidToken(OAuthEndpoint oauthEndpoint) returns TokenResponse|error {
    TokenResponse? cachedToken = tokenCacheManager.getToken(oauthEndpoint.clientId);

    if (cachedToken is TokenResponse) {
        int currentTimeInSeconds = time:utcNow()[0];
        int tokenExpiryBuffer = 300; 

        if (cachedToken.validTill - currentTimeInSeconds > tokenExpiryBuffer) {
            return cachedToken;
        }

        if (cachedToken.refreshToken is string) {
            TokenResponse|error refreshResult = refreshToken(oauthEndpoint, <string>cachedToken.refreshToken);
            if (refreshResult is TokenResponse) {
                return refreshResult;
            }
            log:printError("Token refresh failed. Generating a new token.", 'error = refreshResult);
        }
    }
    
    return generateNewToken(oauthEndpoint);
}

function generateNewToken(OAuthEndpoint endpoint) returns TokenResponse|error {
    http:Request tokenReq = new;
    tokenReq.setHeader("Content-Type", "application/x-www-form-urlencoded");
    
    string payload = string `grant_type=client_credentials&client_id=${endpoint.clientId}&client_secret=${endpoint.clientSecret}`;
    tokenReq.setTextPayload(payload);
    
    TokenResponse token = check requestAndParseToken(tokenReq);
    return token;
}

function refreshToken(OAuthEndpoint endpoint, string refreshToken) returns TokenResponse|error {
    if (refreshToken == "") {
        return error("Refresh token is empty");
    }

    http:Request tokenReq = new;
    tokenReq.setHeader("Content-Type", "application/x-www-form-urlencoded");

    string payload = string `grant_type=refresh_token&refresh_token=${refreshToken}&client_id=${endpoint.clientId}&client_secret=${endpoint.clientSecret}`;
    tokenReq.setTextPayload(payload);
    
    TokenResponse token = check requestAndParseToken(tokenReq);
    return token;
}

function requestAndParseToken(http:Request tokenReq) returns TokenResponse|error {

    int maxRetries = 3;
    int retryCount = 0;
    decimal initialBackoff = 5; 
    
    http:Response? tokenResp = ();
    error? lastError = ();
   
    while retryCount < maxRetries {
        http:Response|error tokenRespResult = tokenClient->post("", tokenReq);
        
        if tokenRespResult is http:Response {
            tokenResp = tokenRespResult;
            break;
        } else {
            string errorMsg = tokenRespResult.message();
            if errorMsg.includes("timed out") || errorMsg.includes("Connection refused") {
                lastError = tokenRespResult;
                retryCount += 1;
                
                if retryCount < maxRetries {
                    decimal backoffTime = initialBackoff * (2 ^ retryCount);
                    log:printWarn(string `Token request failed (${errorMsg}). Retrying (${retryCount}/${maxRetries}) after ${backoffTime}s`);
                    
                    runtime:sleep(backoffTime);
                } else {
                    log:printError(string `Maximum retries (${maxRetries}) exceeded for token request`);
                    return error("Error calling token endpoint after maximum retries: " + errorMsg);
                }
            } else {
                return error("Error calling token endpoint: " + errorMsg);
            }
        }
    }
    
    if tokenResp is () {
        return error("Failed to get token response after retries", lastError);
    }
    
    json|error respJson = tokenResp.getJsonPayload();
    if (respJson is error) {
        return error("Failed to parse token response: " + respJson.message());
    }

    int currentTime = time:utcNow()[0];
    int expiresIn = check respJson.expires_in;

    TokenResponse token = {
        accessToken: check respJson.access_token,
        tokenType: check respJson.token_type,
        expiresIn: expiresIn,
        validTill: currentTime + expiresIn
    };

    if (respJson.refresh_token is string && respJson.refresh_token != "") {
        token.refreshToken = check respJson.refresh_token;
    } else {
        log:printDebug("No refresh_token in response");
    }

    return token;
}