module anonymos.userland.peer_info;

import core.stdc.string : strlen, strcmp;
import core.stdc.stdlib : malloc;

extern (C):

struct PeerInfo
{
    char* service_id;
    ubyte[32] code_hash;
    char** roles; // null-terminated array
}

@nogc nothrow:

int peer_has_role(const PeerInfo* p, const char* role)
{
    if (p is null || role is null || p.roles is null) return 0;
    size_t idx = 0;
    while (p.roles[idx] !is null)
    {
        if (strcmp(p.roles[idx], role) == 0)
            return 1;
        ++idx;
    }
    return 0;
}
