import ballerina/http;
import choreo/mediation;
import ballerina/time;
import ballerina/log;
import ballerina/lang.runtime;
import ballerina/mime;
import ballerina/lang.regexp;

TokenResponse? oauthAccessToken = ();
http:Client? tokenClient = ();

function getTokenClient(string tokenEndpointUrl) returns http:Client|error {
    if (tokenClient is http:Client) {
        return <http:Client>tokenClient;
    }

    lock {
        if (tokenClient is http:Client) {
            return <http:Client>tokenClient;
        }

        http:Client|error tokenClientResult = new (tokenEndpointUrl);

        if (tokenClientResult is error) {
            return error("Failed to initialize token client");
        } else {
            tokenClient = tokenClientResult;
            return tokenClientResult;
        }
    }
}

@mediation:RequestFlow
public function oauthIn(mediation:Context ctx,
        http:Request req,
        string tokenEndpointUrl,
        string clientId,
        string clientSecret,
        string headerName)
                        returns http:Response|false|error? {

    OauthEndpointConfig oauthEndpointConfig = {
        tokenApiUrl: tokenEndpointUrl,
        clientId: clientId,
        clientSecret: clientSecret
    };

    http:Client|error tokenClientResult = getTokenClient(tokenEndpointUrl);
    if (tokenClientResult is error) {
        return error("Failed to initialize token client");
    }

    // check what happens when 500. check for incorrect endpoint url
    TokenResponse|error token = check getValidToken(oauthEndpointConfig);
    if (token is error) {
        return error("Failed to get a valid token");
    }
    //oauthAccessToken = token;

    if token.accessToken is string && token.accessToken.length() > 0 {
        string headerValue = string `Bearer ${token.accessToken}`;
        req.setHeader(headerName, headerValue);
    } else {
        return error("Invalid access token");
    }

    return;
}

function isValidToken() returns boolean {
    TokenResponse? cachedToken = oauthAccessToken;

    if (cachedToken is TokenResponse) {
        int currentTimeInSeconds = time:utcNow()[0];
        int tokenExpiryBuffer = 300;

        if (cachedToken.validTill - currentTimeInSeconds > tokenExpiryBuffer) {
            return true;
        }
    }
    return false;
}

function getValidToken(OauthEndpointConfig oauthEndpointConfig) returns TokenResponse|error {
    TokenResponse? cachedToken = oauthAccessToken;
    if (cachedToken is TokenResponse) {
        if (isValidToken()) {
            return cachedToken;
        }
    }

    lock {
        if (cachedToken is TokenResponse) {
            if (isValidToken()) {
                return cachedToken;
            }
        }

        if (cachedToken is TokenResponse && cachedToken.refreshToken is string && cachedToken.refreshToken != "") {
            TokenResponse|error refreshResult = refreshToken(oauthEndpointConfig, <string>cachedToken.refreshToken);
            if (refreshResult is TokenResponse) {
                return refreshResult;
            }
            log:printError("Token refresh failed. Generating a new token.", 'error = refreshResult);
        }

        TokenResponse newToken = check generateNewToken(oauthEndpointConfig);
        oauthAccessToken = newToken;
        return newToken;
    }

}

function generateNewToken(OauthEndpointConfig oauthEndpointConfig) returns TokenResponse|error {
    http:Request tokenReq = new;
    tokenReq.setHeader("Content-Type", "application/x-www-form-urlencoded");

    string authString = oauthEndpointConfig.clientId + ":" + oauthEndpointConfig.clientSecret;
    string encodedCredentials = (check mime:base64Encode(authString)).toString();
    string encodedCreds = regexp:replaceAll(re `\s+`, encodedCredentials, "");
    string authHeader = string `Basic ${encodedCreds}`;
    tokenReq.setHeader("Authorization", authHeader);

    string payload = "grant_type=client_credentials";
    tokenReq.setTextPayload(payload);

    TokenResponse|error token = check requestAndParseToken(tokenReq, oauthEndpointConfig.tokenApiUrl);
    return token;
}

function refreshToken(OauthEndpointConfig oauthEndpointConfig, string refreshToken) returns TokenResponse|error {
    if (refreshToken == "") {
        return error("Refresh token is empty");
    }

    http:Request tokenReq = new;
    tokenReq.setHeader("Content-Type", "application/x-www-form-urlencoded");

    string authString = oauthEndpointConfig.clientId + ":" + oauthEndpointConfig.clientSecret;
    string encodedCredentials = (check mime:base64Encode(authString)).toString();
    string encodedCreds = regexp:replaceAll(re `\s+`, encodedCredentials, "");
    string authHeader = string `Basic ${encodedCreds}`;
    tokenReq.setHeader("Authorization", authHeader);

    string payload = string `grant_type=refresh_token&refresh_token=${refreshToken}`;
    tokenReq.setTextPayload(payload);

    TokenResponse|error token = check requestAndParseToken(tokenReq, oauthEndpointConfig.tokenApiUrl);
    return token;
}

// function generateNewToken(OauthEndpointConfig oauthEndpointConfig) returns TokenResponse|error {
//     http:Request tokenReq = new;
//     tokenReq.setHeader("Content-Type", "application/x-www-form-urlencoded");

//     string payload = string `grant_type=client_credentials&client_id=${oauthEndpointConfig.clientId}&client_secret=${oauthEndpointConfig.clientSecret}`;
//     tokenReq.setTextPayload(payload);

//     TokenResponse token = check requestAndParseToken(tokenReq, oauthEndpointConfig.tokenApiUrl);
//     return token;
// }

// function refreshToken(OauthEndpointConfig oauthEndpointConfig, string refreshToken) returns TokenResponse|error {
//     if (refreshToken == "") {
//         return error("Refresh token is empty");
//     }

//     http:Request tokenReq = new;
//     tokenReq.setHeader("Content-Type", "application/x-www-form-urlencoded");

//     string payload = string `grant_type=refresh_token&refresh_token=${refreshToken}&client_id=${oauthEndpointConfig.clientId}&client_secret=${oauthEndpointConfig.clientSecret}`;
//     tokenReq.setTextPayload(payload);

//     TokenResponse token = check requestAndParseToken(tokenReq, oauthEndpointConfig.tokenApiUrl);
//     return token;
// }

function requestAndParseToken(http:Request tokenReq, string tokenEndpointUrl) returns TokenResponse|error {
    // Think about the concurrent request. Wait until one request get a token. 
    int maxRetries = 3;
    int retryCount = 0;
    decimal initialBackoff = 5;
    http:Response? tokenResp = ();
    error? lastError = ();

    while retryCount < maxRetries {
        http:Response|http:ClientError tokenRespResult = (check getTokenClient(tokenEndpointUrl))->post("", tokenReq);

        if tokenRespResult is http:Response {
            tokenResp = tokenRespResult;
            break;
        } else {
            if (tokenRespResult is http:IdleTimeoutError || tokenRespResult is http:RemoteServerError) {
                lastError = tokenRespResult;
                retryCount += 1;
                log:printWarn(string `Token request failed (${tokenRespResult.message()}). Retrying ${retryCount}`);

                if retryCount < maxRetries {
                    decimal backoffTime = initialBackoff * (2 ^ (retryCount - 1));
                    runtime:sleep(backoffTime);
                } else {
                    return error("Error calling token endpoint after maximum retries");
                }
            } else {
                return error("Unexpected error calling token endpoint");
            }
        }
    }
    if tokenResp is () {
        return error("Failed to receive a token response after retries");
    }

    if tokenResp.statusCode == http:STATUS_OK {
        json|error respJson = tokenResp.getJsonPayload();
        if (respJson is error) {
            return error("Failed to parse token response: " + respJson.message());
        } else {
            var accessTokenJson = respJson.access_token;
            var tokenTypeJson = respJson.token_type;
            var expiresInJson = respJson.expires_in;

            if (accessTokenJson is ()) {
                return error("Missing required field: access_token");
            }
            if (tokenTypeJson is ()) {
                return error("Missing required field: token_type");
            }
            if (expiresInJson is ()) {
                return error("Missing required field: expires_in");
            }

            int currentTime = time:utcNow()[0];
            int expiresIn = check respJson.expires_in;

            TokenResponse token = {
                accessToken: check respJson.access_token,
                tokenType: check respJson.token_type,
                expiresIn: expiresIn,
                validTill: currentTime + expiresIn
            };

            json|error refreshTokenJson = check respJson.refresh_token;
            if (refreshTokenJson is json && refreshTokenJson != "") {
                token.refreshToken = check refreshTokenJson;
            } else {
                log:printDebug("No valid refresh_token in response");
            }

            return token;
        }
    } else {
        log:printInfo("Token endpoint returned non-200 status.", 'error = lastError);
        return error("Token endpoint returned non-200 status.");
    }

}
