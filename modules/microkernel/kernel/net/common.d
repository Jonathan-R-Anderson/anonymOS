module kernel.net.common;

pragma(LDC_no_moduleinfo);

public:

// Switch endian for 16-bit
extern(C) ushort swap16(ushort val)
{
    return cast(ushort)((val >> 8) | (val << 8));
}

// Switch endian for 32-bit
extern(C) uint swap32(uint val)
{
    return ((val >> 24) & 0xFF) |
           ((val >> 8)  & 0xFF00) |
           ((val << 8)  & 0xFF0000) |
           ((val << 24) & 0xFF000000);
}
