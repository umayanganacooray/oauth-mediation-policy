import ballerina/cache;
import ballerina/log;

public class TokenCacheManager {
    private cache:Cache tokenCache;

    public function init() {
        self.tokenCache = new (capacity = 100, evictionFactor = 0.2);
    }

     public function getToken(string id) returns TokenResponse? {
        any|error cachedItem = self.tokenCache.get(id);
        if (cachedItem is error) {
            log:printDebug("No token in cache for ID: " + id);
            return ();
        }
        return <TokenResponse>cachedItem;
    }
    
    public function putToken(string id, TokenResponse token) {
        error? result = self.tokenCache.put(id, token);
        if result is error {
            log:printError("Failed to cache token", 'error = result);
        }
    }

    public function removeToken(string id) {
        error? result = self.tokenCache.invalidate(id);
        if (result is error) {
            log:printError("Failed to remove token from cache", 'error = result);
        }
    }
}