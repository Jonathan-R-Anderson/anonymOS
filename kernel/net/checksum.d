module kernel.net.checksum;

pragma(LDC_no_moduleinfo);

import kernel.types : memset;

public:

// Compute Internet checksum (ones complement sum)
extern(C) ushort checksum16(const(ubyte)* data, size_t len)
{
    uint sum = 0;
    size_t i;

    // Sum 16-bit words
    for(i = 0; i + 1 < len; i += 2)
    {
        ushort word = cast(ushort)((data[i] << 8) | data[i+1]);
        sum += word;
    }

    // Handle odd byte
    if(i < len)
    {
        ushort word = cast(ushort)(data[i] << 8);
        sum += word;
    }

    // Fold carries
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return ones complement
    return cast(ushort)(~sum & 0xFFFF);
}
