module anonymos.net.https;

import anonymos.net.types;
import anonymos.net.tcp;
import anonymos.net.tls;
import anonymos.net.dns;
import anonymos.net.http;
import anonymos.net.stack;

/// HTTPS request
struct HTTPSRequest {
    HTTPMethod method;
    char[256] host;
    ushort port;
    char[512] path;
    char[1024] headers;
    ubyte* body;
    size_t bodyLen;
    bool verifyPeer;
}

private __gshared HTTPResponse g_httpsResponse;
private __gshared bool g_httpsResponseReady = false;
private __gshared int g_httpsTlsCtx = -1;

/// Send HTTPS request
export extern(C) bool httpsSendRequest(const ref HTTPSRequest request) @nogc nothrow {
    // Reset response
    g_httpsResponse.statusCode = 0;
    g_httpsResponse.bodyLen = 0;
    g_httpsResponse.complete = false;
    g_httpsResponseReady = false;
    
    // Resolve hostname
    IPv4Address serverIP;
    if (!dnsResolve(request.host.ptr, &serverIP, 5000)) {
        return false;
    }
    
    // Create TLS connection
    g_httpsTlsCtx = tlsSimpleConnect(serverIP, request.port, request.verifyPeer);
    if (g_httpsTlsCtx < 0) {
        return false;
    }
    
    // Build HTTP request
    char[2048] requestBuffer;
    size_t reqLen = 0;
    
    // Method and path
    const(char)* methodStr;
    switch (request.method) {
        case HTTPMethod.GET:    methodStr = "GET "; break;
        case HTTPMethod.POST:   methodStr = "POST "; break;
        case HTTPMethod.PUT:    methodStr = "PUT "; break;
        case HTTPMethod.DELETE: methodStr = "DELETE "; break;
        default:                methodStr = "GET "; break;
    }
    
    // Copy method
    for (size_t i = 0; methodStr[i] != '\0' && reqLen < requestBuffer.length; i++) {
        requestBuffer[reqLen++] = methodStr[i];
    }
    
    // Copy path
    for (size_t i = 0; request.path[i] != '\0' && reqLen < requestBuffer.length; i++) {
        requestBuffer[reqLen++] = request.path[i];
    }
    
    // HTTP version
    const(char)* httpVer = " HTTP/1.1\r\n";
    for (size_t i = 0; httpVer[i] != '\0' && reqLen < requestBuffer.length; i++) {
        requestBuffer[reqLen++] = httpVer[i];
    }
    
    // Host header
    const(char)* hostHeader = "Host: ";
    for (size_t i = 0; hostHeader[i] != '\0' && reqLen < requestBuffer.length; i++) {
        requestBuffer[reqLen++] = hostHeader[i];
    }
    for (size_t i = 0; request.host[i] != '\0' && reqLen < requestBuffer.length; i++) {
        requestBuffer[reqLen++] = request.host[i];
    }
    requestBuffer[reqLen++] = '\r';
    requestBuffer[reqLen++] = '\n';
    
    // Additional headers
    for (size_t i = 0; request.headers[i] != '\0' && reqLen < requestBuffer.length; i++) {
        requestBuffer[reqLen++] = request.headers[i];
    }
    
    // Content-Length if POST
    if (request.method == HTTPMethod.POST && request.bodyLen > 0) {
        const(char)* contentLen = "Content-Length: ";
        for (size_t i = 0; contentLen[i] != '\0' && reqLen < requestBuffer.length; i++) {
            requestBuffer[reqLen++] = contentLen[i];
        }
        
        // Convert body length to string
        char[16] lenStr;
        size_t lenStrLen = 0;
        size_t temp = request.bodyLen;
        do {
            lenStr[lenStrLen++] = cast(char)('0' + (temp % 10));
            temp /= 10;
        } while (temp > 0);
        
        // Reverse
        for (size_t i = 0; i < lenStrLen && reqLen < requestBuffer.length; i++) {
            requestBuffer[reqLen++] = lenStr[lenStrLen - 1 - i];
        }
        requestBuffer[reqLen++] = '\r';
        requestBuffer[reqLen++] = '\n';
    }
    
    // End of headers
    requestBuffer[reqLen++] = '\r';
    requestBuffer[reqLen++] = '\n';
    
    // Send request via TLS
    if (tlsWrite(g_httpsTlsCtx, cast(ubyte*)requestBuffer.ptr, reqLen) < 0) {
        tlsClose(g_httpsTlsCtx);
        return false;
    }
    
    // Send body if POST
    if (request.method == HTTPMethod.POST && request.body !is null && request.bodyLen > 0) {
        if (tlsWrite(g_httpsTlsCtx, request.body, request.bodyLen) < 0) {
            tlsClose(g_httpsTlsCtx);
            return false;
        }
    }
    
    return true;
}

/// Wait for HTTPS response
export extern(C) bool httpsWaitResponse(HTTPResponse* outResponse, uint timeoutMs) @nogc nothrow {
    if (outResponse is null) return false;
    
    ubyte[8192] responseBuffer;
    size_t totalReceived = 0;
    bool headersComplete = false;
    size_t bodyStart = 0;
    
    uint attempts = timeoutMs / 10;
    for (uint i = 0; i < attempts; i++) {
        networkStackPoll();
        
        // Try to read data
        int received = tlsRead(g_httpsTlsCtx, responseBuffer.ptr + totalReceived,
                               responseBuffer.length - totalReceived);
        
        if (received > 0) {
            totalReceived += received;
            
            // Parse status code if not done yet
            if (g_httpsResponse.statusCode == 0 && totalReceived > 12) {
                if (responseBuffer[9] >= '0' && responseBuffer[9] <= '9') {
                    g_httpsResponse.statusCode = (responseBuffer[9] - '0') * 100 +
                                                  (responseBuffer[10] - '0') * 10 +
                                                  (responseBuffer[11] - '0');
                }
            }
            
            // Look for end of headers
            if (!headersComplete) {
                for (size_t j = 0; j < totalReceived - 3; j++) {
                    if (responseBuffer[j] == '\r' && responseBuffer[j+1] == '\n' &&
                        responseBuffer[j+2] == '\r' && responseBuffer[j+3] == '\n') {
                        headersComplete = true;
                        bodyStart = j + 4;
                        break;
                    }
                }
            }
            
            // If headers complete, copy body
            if (headersComplete && bodyStart < totalReceived) {
                size_t bodyLen = totalReceived - bodyStart;
                size_t copyLen = bodyLen;
                if (copyLen > g_httpsResponse.body.length) {
                    copyLen = g_httpsResponse.body.length;
                }
                
                for (size_t j = 0; j < copyLen; j++) {
                    g_httpsResponse.body[j] = responseBuffer[bodyStart + j];
                }
                g_httpsResponse.bodyLen = copyLen;
                g_httpsResponse.complete = true;
                
                *outResponse = g_httpsResponse;
                tlsClose(g_httpsTlsCtx);
                return true;
            }
        }
        
        // Wait ~10ms
        for (uint j = 0; j < 1000000; j++) {
            asm { nop; }
        }
    }
    
    tlsClose(g_httpsTlsCtx);
    return false;
}

/// Simple HTTPS GET request
export extern(C) bool httpsGet(const(char)* host, ushort port, const(char)* path,
                                HTTPResponse* outResponse, bool verifyPeer) @nogc nothrow {
    HTTPSRequest request;
    request.method = HTTPMethod.GET;
    request.port = port;
    request.bodyLen = 0;
    request.verifyPeer = verifyPeer;
    
    // Copy host
    size_t i = 0;
    while (host[i] != '\0' && i < request.host.length - 1) {
        request.host[i] = host[i];
        i++;
    }
    request.host[i] = '\0';
    
    // Copy path
    i = 0;
    while (path[i] != '\0' && i < request.path.length - 1) {
        request.path[i] = path[i];
        i++;
    }
    request.path[i] = '\0';
    
    // No additional headers
    request.headers[0] = '\0';
    
    if (!httpsSendRequest(request)) {
        return false;
    }
    
    return httpsWaitResponse(outResponse, 10000);
}

/// Simple HTTPS POST request
export extern(C) bool httpsPost(const(char)* host, ushort port, const(char)* path,
                                 const(ubyte)* body, size_t bodyLen,
                                 HTTPResponse* outResponse, bool verifyPeer) @nogc nothrow {
    HTTPSRequest request;
    request.method = HTTPMethod.POST;
    request.port = port;
    request.body = cast(ubyte*)body;
    request.bodyLen = bodyLen;
    request.verifyPeer = verifyPeer;
    
    // Copy host
    size_t i = 0;
    while (host[i] != '\0' && i < request.host.length - 1) {
        request.host[i] = host[i];
        i++;
    }
    request.host[i] = '\0';
    
    // Copy path
    i = 0;
    while (path[i] != '\0' && i < request.path.length - 1) {
        request.path[i] = path[i];
        i++;
    }
    request.path[i] = '\0';
    
    // Set Content-Type header
    const(char)* contentType = "Content-Type: application/json\r\n";
    i = 0;
    while (contentType[i] != '\0' && i < request.headers.length - 1) {
        request.headers[i] = contentType[i];
        i++;
    }
    request.headers[i] = '\0';
    
    if (!httpsSendRequest(request)) {
        return false;
    }
    
    return httpsWaitResponse(outResponse, 10000);
}

/// HTTPS request to hostname (with DNS resolution)
export extern(C) bool httpsGetHostname(const(char)* hostname, const(char)* path,
                                        HTTPResponse* outResponse) @nogc nothrow {
    return httpsGet(hostname, 443, path, outResponse, true);
}

/// HTTPS POST to hostname (with DNS resolution)
export extern(C) bool httpsPostHostname(const(char)* hostname, const(char)* path,
                                         const(ubyte)* body, size_t bodyLen,
                                         HTTPResponse* outResponse) @nogc nothrow {
    return httpsPost(hostname, 443, path, body, bodyLen, outResponse, true);
}
