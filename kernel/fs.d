module kernel.fs;

pragma(LDC_no_moduleinfo);

import kernel.lib.stdc.stdio : FILE, fopen, fclose, fgets, fwrite, fread;
import kernel.types : strlen, memcpy, strchr;
import kernel.lib.stdc.stdlib : malloc, realloc, free;
import kernel.logger : log_message;

public:

enum NodeType { Directory, File }

struct Node {
    char*      name;
    NodeType   kind;
    Node*      parent;
    Node*      child;
    Node*      sibling;
    ubyte*     data;
    size_t     size;
    size_t     capacity;
}

__gshared Node* fsRoot;

struct FileDesc {
    Node* node;
    size_t pos;
}

enum MAX_FDS = 16;
__gshared FileDesc[MAX_FDS] g_fdtable;

extern(C) void fs_fdtable_init()
{
    foreach(ref f; g_fdtable)
    {
        f.node = null;
        f.pos = 0;
    }
}

extern(C) int fs_open_file(const(char)* path, int mode)
{
    auto n = fs_lookup(path);
    if(n is null || n.kind != NodeType.File)
        return -1;
    foreach(i, ref f; g_fdtable)
    {
        if(f.node is null)
        {
            f.node = n;
            f.pos = 0;
            return cast(int)i;
        }
    }
    return -1;
}

extern(C) int fs_close_file(int fd)
{
    if(fd < 0 || fd >= g_fdtable.length)
        return -1;
    if(g_fdtable[fd].node is null)
        return -1;
    g_fdtable[fd].node = null;
    g_fdtable[fd].pos = 0;
    return 0;
}

extern(C) int fs_create_file_desc(const(char)* path, int mode, int perm)
{
    auto n = createFile(path);
    if(n is null) return -1;
    n.size = 0;
    foreach(i, ref f; g_fdtable)
    {
        if(f.node is null)
        {
            f.node = n;
            f.pos = 0;
            return cast(int)i;
        }
    }
    return -1;
}

extern(C) long fs_pread_file(int fd, void* buf, size_t count, size_t offset)
{
    if(fd < 0 || fd >= g_fdtable.length) return -1;
    auto n = g_fdtable[fd].node;
    if(n is null || n.kind != NodeType.File) return -1;
    if(offset >= n.size) return 0;
    size_t toRead = count;
    if(offset + toRead > n.size)
        toRead = n.size - offset;
    memcpy(buf, n.data + offset, toRead);
    return cast(long)toRead;
}

extern(C) long fs_pwrite_file(int fd, const(void)* buf, size_t count, size_t offset)
{
    if(fd < 0 || fd >= g_fdtable.length) return -1;
    auto n = g_fdtable[fd].node;
    if(n is null || n.kind != NodeType.File) return -1;
    size_t end = offset + count;
    if(end > n.capacity)
    {
        size_t newCap = end;
        n.data = cast(ubyte*)realloc(n.data, newCap);
        if(n.data is null) return -1;
        n.capacity = newCap;
    }
    memcpy(n.data + offset, buf, count);
    if(end > n.size)
        n.size = end;
    return cast(long)count;
}

extern(C) long fs_seek_file(int fd, long offset, int whence)
{
    if(fd < 0 || fd >= g_fdtable.length) return -1;
    auto desc = &g_fdtable[fd];
    if(desc.node is null || desc.node.kind != NodeType.File) return -1;
    size_t newPos = 0;
    final switch(whence)
    {
        case 0: // SEEK_SET
            newPos = cast(size_t)offset;
            break;
        case 1: // SEEK_CUR
            newPos = desc.pos + cast(size_t)offset;
            break;
        case 2: // SEEK_END
            newPos = desc.node.size + cast(size_t)offset;
            break;
        default:
            return -1;
    }
    desc.pos = newPos;
    return cast(long)newPos;
}

private Node* createNode(const(char)* name, NodeType kind)
{
    auto n = cast(Node*)malloc(Node.sizeof);
    if(n is null) return null;
    size_t len = strlen(name);
    n.name = cast(char*)malloc(len + 1);
    if(n.name !is null)
    {
        memcpy(n.name, name, len);
        n.name[len] = 0;
    }
    n.kind = kind;
    n.parent = null;
    n.child = null;
    n.sibling = null;
    n.data = null;
    n.size = 0;
    n.capacity = 0;
    return n;
}

private Node* findChild(Node* parent, const(char)* name)
{
    auto c = parent.child;
    while(c !is null)
    {
        size_t i = 0;
        while(c.name[i] == name[i] && c.name[i] != 0) ++i;
        if(c.name[i] == 0 && name[i] == 0)
            return c;
        c = c.sibling;
    }
    return null;
}

private void addChild(Node* parent, Node* child)
{
    if(parent.child is null)
        parent.child = child;
    else
    {
        auto c = parent.child;
        while(c.sibling !is null) c = c.sibling;
        c.sibling = child;
    }
    child.parent = parent;
}

private Node* mkdirInternal(const(char)* path)
{
    if(path[0] != '/') return null;
    auto cur = fsRoot;
    size_t i = 1;
    while(path[i])
    {
        char[64] nameBuf;
        size_t j = 0;
        while(path[i] && path[i] != '/' && j < nameBuf.length-1)
            nameBuf[j++] = path[i++];
        nameBuf[j] = 0;
        auto next = findChild(cur, nameBuf.ptr);
        if(next is null)
        {
            next = createNode(nameBuf.ptr, NodeType.Directory);
            addChild(cur, next);
        }
        cur = next;
        if(path[i] == '/') ++i;
    }
    return cur;
}

private Node* createFile(const(char)* path)
{
    if(path[0] != '/') return null;
    // split path; last segment is file name
    size_t len = strlen(path);
    size_t end = len;
    while(end > 1 && path[end-1] != '/') --end;
    char[128] dirBuf;
    if(end == 1)
    {
        dirBuf[0] = '/';
        dirBuf[1] = 0;
    }
    else
    {
        memcpy(dirBuf.ptr, path, end);
        dirBuf[end] = 0;
    }
    auto dir = mkdirInternal(dirBuf.ptr);
    if(dir is null) return null;
    auto fname = path + end;
    auto node = findChild(dir, fname);
    if(node is null)
    {
        node = createNode(fname, NodeType.File);
        addChild(dir, node);
    }
    return node;
}

extern(C) Node* fs_lookup(const(char)* path)
{
    if(path[0] != '/') return null;
    if(path[1] == 0) return fsRoot;
    auto cur = fsRoot;
    size_t i = 1;
    while(cur !is null && path[i])
    {
        char[64] nameBuf;
        size_t j = 0;
        while(path[i] && path[i] != '/' && j < nameBuf.length-1)
            nameBuf[j++] = path[i++];
        nameBuf[j] = 0;
        cur = findChild(cur, nameBuf.ptr);
        if(cur is null) return null;
        if(path[i] == '/') ++i;
    }
    return cur;
}

private void saveNode(FILE* f, Node* n, char* prefix, size_t len)
{
    char[256] pathBuf;
    size_t plen = len;
    if(plen == 0)
    {
        pathBuf[0] = '/';
        pathBuf[1] = 0;
        plen = 1;
    }
    else
    {
        memcpy(pathBuf.ptr, prefix, plen);
    }
    if(n !is fsRoot)
    {
        if(plen > 1 && pathBuf[plen-1] != '/')
            pathBuf[plen++] = '/';
        size_t nameLen = strlen(n.name);
        memcpy(pathBuf.ptr + plen, n.name, nameLen);
        plen += nameLen;
        pathBuf[plen] = 0;
    }
    char[300] line;
    line[0] = (n.kind == NodeType.Directory) ? 'D' : 'F';
    line[1] = ' ';
    memcpy(line.ptr + 2, pathBuf.ptr, plen);
    line[2 + plen] = '\n';
    fwrite(line.ptr, 1, plen + 3, f);
    auto c = n.child;
    while(c !is null)
    {
        saveNode(f, c, pathBuf.ptr, plen);
        c = c.sibling;
    }
}

/// Default directory tree for the in-memory filesystem.
__gshared immutable(char*)[] defaultDirs = [
    "/sys",
    "/sys/boot",
    "/sys/kernel",
    "/sys/drivers",
    "/sys/init",
    "/sys/profiles",
    "/apps",
    "/apps/coreutils",
    "/apps/coreutils/v1.2.3",
    "/apps/browser",
    "/apps/browser/v105.0",
    "/apps/editor",
    "/apps/editor/v3.1",
    "/users",
    "/users/alice",
    "/users/alice/bin",
    "/users/alice/cfg",
    "/users/alice/doc",
    "/users/alice/media",
    "/users/alice/projects",
    "/users/alice/vault",
    "/users/bob",
    "/users/bob/bin",
    "/users/bob/cfg",
    "/users/bob/doc",
    "/users/bob/media",
    "/users/bob/projects",
    "/users/bob/vault",
    "/srv",
    "/srv/sshd",
    "/srv/web",
    "/srv/dns",
    "/srv/db",
    "/cfg",
    "/cfg/users",
    "/cfg/network",
    "/cfg/system",
    "/vol",
    "/vol/usb0",
    "/vol/backup_drive",
    "/vol/encrypted_partition",
    "/log",
    "/run",
    "/tmp",
    "/dev",
    "/net",
    "/net/ip",
    "/net/tcp",
    "/net/dns",
];

/// Default set of configuration files created on first boot.
__gshared immutable(char*)[] defaultFiles = [
    "/cfg/hostname",
    "/cfg/users/alice.json",
    "/cfg/users/bob.json",
    "/cfg/network/interfaces.json",
    "/cfg/system/packages.json",
];

private void createDefaultTree()
{
    fsRoot = createNode("/", NodeType.Directory);
    foreach(dir; defaultDirs)
        mkdirInternal(dir);
    foreach(f; defaultFiles)
        createFile(f);
}

private void loadFilesystem()
{
    auto f = fopen("fs.img", "rb");
    if(f is null)
    {
        createDefaultTree();
        auto outFile = fopen("fs.img", "wb");
        if(outFile !is null)
        {
            saveNode(outFile, fsRoot, null, 0);
            fclose(outFile);
        }
        return;
    }
    fsRoot = createNode("/", NodeType.Directory);
    char[256] line;
    while(fgets(line.ptr, line.length, f) !is null)
    {
        if(line[0] != 'D' && line[0] != 'F') continue;
        auto p = line.ptr + 2;
        auto nl = strchr(p, '\n');
        if(nl !is null) *nl = 0;
        if(line[0] == 'D')
            mkdirInternal(p);
        else
            createFile(p);
    }
    fclose(f);
}

extern(C) void save_filesystem()
{
    auto f = fopen("fs.img", "wb");
    if(f is null) return;
    saveNode(f, fsRoot, null, 0);
    fclose(f);
}

extern(C) void init_filesystem(void* info)
{
    loadFilesystem();
    fs_fdtable_init();
    log_message("Filesystem initialized\n");
}

extern(C) void fs_create_user(const(char)* name)
{
    char[128] path;
    size_t len;
    // /users/<name>
    path[0] = '/'; path[1] = 'u'; path[2] = 's'; path[3] = 'e'; path[4] = 'r'; path[5]='s'; path[6]='/';
    len = 7;
    size_t nlen = strlen(name);
    memcpy(path.ptr + len, name, nlen);
    len += nlen; path[len]=0;
    mkdirInternal(path.ptr);
    const(char*)[6] subdirs = ["bin","cfg","doc","media","projects","vault"];
    foreach(i, sub; subdirs)
    {
        char[160] sp;
        size_t sl = len;
        memcpy(sp.ptr, path.ptr, len);
        sp[sl++] = '/';
        memcpy(sp.ptr+sl, sub, strlen(sub));
        sl += strlen(sub);
        sp[sl] = 0;
        mkdirInternal(sp.ptr);
    }
    // config file
    char[160] cfgPath;
    auto prefix = "/cfg/users/";
    memcpy(cfgPath.ptr, prefix.ptr, strlen(prefix.ptr));
    size_t pl = strlen(prefix.ptr);
    memcpy(cfgPath.ptr + pl, name, nlen);
    pl += nlen;
    cfgPath[pl++] = '.'; cfgPath[pl++] = 'j'; cfgPath[pl++] = 's'; cfgPath[pl++] = 'o'; cfgPath[pl++] = 'n';
    cfgPath[pl] = 0;
    createFile(cfgPath.ptr);
    save_filesystem();
}

