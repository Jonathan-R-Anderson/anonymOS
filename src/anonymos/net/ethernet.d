module anonymos.net.ethernet;

import anonymos.net.types;
import anonymos.drivers.network : sendEthFrame, receiveEthFrame, getMacAddress;

/// Ethernet frame header
struct EthernetHeader {
    MACAddress destMac;
    MACAddress srcMac;
    ushort etherType;  // Network byte order
}

/// Ethernet frame
struct EthernetFrame {
    EthernetHeader header;
    ubyte* payload;
    size_t payloadLength;
}

private __gshared MACAddress g_localMac;
private __gshared bool g_macInitialized = false;

/// Initialize Ethernet layer
export extern(C) void initEthernet() @nogc nothrow {
    if (!g_macInitialized) {
        getMacAddress(g_localMac.bytes.ptr);
        g_macInitialized = true;
    }
}

/// Get local MAC address
export extern(C) void getLocalMac(MACAddress* outMac) @nogc nothrow {
    if (outMac is null) return;
    *outMac = g_localMac;
}

/// Send Ethernet frame
export extern(C) bool sendEthernetFrame(const ref MACAddress destMac, 
                                         ushort etherType,
                                         const(ubyte)* payload, 
                                         size_t payloadLen) @nogc nothrow {
    if (payload is null || payloadLen == 0) return false;
    
    // Allocate buffer for frame
    enum MAX_FRAME_SIZE = 1518;
    ubyte[MAX_FRAME_SIZE] frameBuffer;
    
    size_t frameSize = EthernetHeader.sizeof + payloadLen;
    if (frameSize > MAX_FRAME_SIZE) return false;
    
    // Build Ethernet header
    EthernetHeader* header = cast(EthernetHeader*)frameBuffer.ptr;
    header.destMac = destMac;
    header.srcMac = g_localMac;
    header.etherType = htons(etherType);
    
    // Copy payload
    ubyte* payloadPtr = frameBuffer.ptr + EthernetHeader.sizeof;
    for (size_t i = 0; i < payloadLen; i++) {
        payloadPtr[i] = payload[i];
    }
    
    // Send frame
    return sendEthFrame(frameBuffer.ptr, frameSize);
}

/// Receive Ethernet frame
export extern(C) int receiveEthernetFrame(EthernetFrame* outFrame, 
                                           ubyte* buffer, 
                                           size_t bufferSize) @nogc nothrow {
    if (outFrame is null || buffer is null) return -1;
    
    // Receive raw frame
    int received = receiveEthFrame(buffer, bufferSize);
    if (received <= 0) return received;
    
    // Parse header
    if (received < EthernetHeader.sizeof) return -1;
    
    EthernetHeader* header = cast(EthernetHeader*)buffer;
    outFrame.header = *header;
    outFrame.header.etherType = ntohs(header.etherType);
    
    // Set payload
    outFrame.payload = buffer + EthernetHeader.sizeof;
    outFrame.payloadLength = received - EthernetHeader.sizeof;
    
    return cast(int)outFrame.payloadLength;
}

/// Check if frame is for us
export extern(C) bool isFrameForUs(const ref EthernetFrame frame) @nogc nothrow {
    return frame.header.destMac.isEqual(g_localMac) || 
           frame.header.destMac.isBroadcast();
}
