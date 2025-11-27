module anonymos.net.http;

import anonymos.net.types;
import anonymos.net.tcp;
import anonymos.net.stack;

/// HTTP method
enum HTTPMethod {
    GET,
    POST,
    PUT,
    DELETE,
}

/// HTTP request
struct HTTPRequest {
    HTTPMethod method;
    char[256] host;
    ushort port;
    char[512] path;
    char[1024] headers;
    ubyte* body;
    size_t bodyLen;
}

/// HTTP response
struct HTTPResponse {
    int statusCode;
    char[2048] headers;
    ubyte[8192] body;
    size_t bodyLen;
    bool complete;
}

private __gshared HTTPResponse g_currentResponse;
private __gshared bool g_responseReady = false;
private __gshared int g_httpSock = -1;

/// HTTP data callback
private void httpDataCallback(int sockfd, const(ubyte)* data, size_t len) @nogc nothrow {
    if (len == 0) return;
    
    // Simple HTTP response parser
    // Look for status code
    if (g_currentResponse.statusCode == 0) {
        // Parse status line: "HTTP/1.1 200 OK\r\n"
        if (len > 12) {
            // Extract status code (simplified)
            if (data[9] >= '0' && data[9] <= '9') {
                g_currentResponse.statusCode = (data[9] - '0') * 100 +
                                                (data[10] - '0') * 10 +
                                                (data[11] - '0');
            }
        }
    }
    
    // Look for end of headers (\r\n\r\n)
    bool foundBodyStart = false;
    size_t bodyStart = 0;
    
    for (size_t i = 0; i < len - 3; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' &&
            data[i+2] == '\r' && data[i+3] == '\n') {
            foundBodyStart = true;
            bodyStart = i + 4;
            break;
        }
    }
    
    if (foundBodyStart && bodyStart < len) {
        // Copy body
        size_t bodyLen = len - bodyStart;
        size_t copyLen = bodyLen;
        if (g_currentResponse.bodyLen + copyLen > g_currentResponse.body.length) {
            copyLen = g_currentResponse.body.length - g_currentResponse.bodyLen;
        }
        
        for (size_t i = 0; i < copyLen; i++) {
            g_currentResponse.body[g_currentResponse.bodyLen++] = data[bodyStart + i];
        }
        
        g_currentResponse.complete = true;
        g_responseReady = true;
    }
}

/// HTTP connect callback
private void httpConnectCallback(int sockfd) @nogc nothrow {
    // Connection established
}

/// HTTP close callback
private void httpCloseCallback(int sockfd) @nogc nothrow {
    g_responseReady = true;
}

/// Send HTTP request
export extern(C) bool httpSendRequest(const ref HTTPRequest request) @nogc nothrow {
    // Reset response
    g_currentResponse.statusCode = 0;
    g_currentResponse.bodyLen = 0;
    g_currentResponse.complete = false;
    g_responseReady = false;
    
    // Parse host IP (simplified - assumes dotted decimal)
    ubyte[4] ipBytes;
    size_t byteIdx = 0;
    size_t numStart = 0;
    
    for (size_t i = 0; i < 256 && request.host[i] != '\0'; i++) {
        if (request.host[i] == '.' || request.host[i] == '\0') {
            // Parse number
            uint num = 0;
            for (size_t j = numStart; j < i; j++) {
                if (request.host[j] >= '0' && request.host[j] <= '9') {
                    num = num * 10 + (request.host[j] - '0');
                }
            }
            ipBytes[byteIdx++] = cast(ubyte)num;
            numStart = i + 1;
            
            if (byteIdx >= 4 || request.host[i] == '\0') break;
        }
    }
    
    // Create TCP connection
    g_httpSock = tcpConnectTo(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], request.port);
    if (g_httpSock < 0) return false;
    
    // Set callbacks
    tcpSetCallbacks(g_httpSock, &httpConnectCallback, &httpDataCallback, &httpCloseCallback);
    
    // Wait for connection (simplified - should be async)
    for (int i = 0; i < 100; i++) {
        networkStackPoll();
        for (int j = 0; j < 100000; j++) {
            asm { nop; }
        }
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
    
    // Send request
    if (tcpSend(g_httpSock, cast(ubyte*)requestBuffer.ptr, reqLen) < 0) {
        tcpClose(g_httpSock);
        return false;
    }
    
    // Send body if POST
    if (request.method == HTTPMethod.POST && request.body !is null && request.bodyLen > 0) {
        if (tcpSend(g_httpSock, request.body, request.bodyLen) < 0) {
            tcpClose(g_httpSock);
            return false;
        }
    }
    
    return true;
}

/// Wait for HTTP response
export extern(C) bool httpWaitResponse(HTTPResponse* outResponse, uint timeoutMs) @nogc nothrow {
    if (outResponse is null) return false;
    
    uint attempts = timeoutMs / 10;
    for (uint i = 0; i < attempts; i++) {
        networkStackPoll();
        
        if (g_responseReady) {
            *outResponse = g_currentResponse;
            tcpClose(g_httpSock);
            return true;
        }
        
        // Wait ~10ms
        for (uint j = 0; j < 1000000; j++) {
            asm { nop; }
        }
    }
    
    tcpClose(g_httpSock);
    return false;
}

/// Simple HTTP GET request
export extern(C) bool httpGet(const(char)* host, ushort port, const(char)* path,
                               HTTPResponse* outResponse) @nogc nothrow {
    HTTPRequest request;
    request.method = HTTPMethod.GET;
    request.port = port;
    request.bodyLen = 0;
    
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
    
    if (!httpSendRequest(request)) {
        return false;
    }
    
    return httpWaitResponse(outResponse, 5000);
}

/// Simple HTTP POST request
export extern(C) bool httpPost(const(char)* host, ushort port, const(char)* path,
                                const(ubyte)* body, size_t bodyLen,
                                HTTPResponse* outResponse) @nogc nothrow {
    HTTPRequest request;
    request.method = HTTPMethod.POST;
    request.port = port;
    request.body = cast(ubyte*)body;
    request.bodyLen = bodyLen;
    
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
    
    if (!httpSendRequest(request)) {
        return false;
    }
    
    return httpWaitResponse(outResponse, 5000);
}
