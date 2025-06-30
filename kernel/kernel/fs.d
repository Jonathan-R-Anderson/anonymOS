module kernel.fs;

pragma(LDC_no_moduleinfo);

import kernel.lib.stdc.stdio : FILE, fopen, fclose, fgets, fwrite, fread, fseek;
import kernel.types : strlen, memcpy, strchr;
import kernel.lib.stdc.stdlib : malloc, realloc, free;
import kernel.logger : log_message;

public:

enum NodeType { Directory, File, Pipe }

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
__gshared Node* fsCurrentDir;

struct Pipe {
    ubyte[1024] buffer;
    size_t readPos;
    size_t writePos;
    size_t count;
}

struct FileDesc {
    Node* node;
    size_t pos;
    bool pipeRead;
    bool pipeWrite;
}

struct Stat {
    NodeType kind;
    size_t   size;
}

enum MAX_FDS = 16;
__gshared FileDesc[MAX_FDS] g_fdtable;

extern(C) void fs_fdtable_init()
{
    foreach(ref f; g_fdtable)
    {
        f.node = null;
        f.pos = 0;
        f.pipeRead = false;
        f.pipeWrite = false;
    }
}

extern(C) Node* fs_create_pipe()
{
    auto n = cast(Node*)malloc(Node.sizeof);
    if(n is null) return null;
    n.name = null;
    n.kind = NodeType.Pipe;
    n.parent = null;
    n.child = null;
    n.sibling = null;
    auto p = cast(Pipe*)malloc(Pipe.sizeof);
    if(p is null)
    {
        free(n);
        return null;
    }
    p.readPos = 0;
    p.writePos = 0;
    p.count = 0;
    n.data = cast(ubyte*)p;
    n.size = 0;
    n.capacity = Pipe.sizeof;
    return n;
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
    auto n = g_fdtable[fd].node;
    g_fdtable[fd].node = null;
    g_fdtable[fd].pos = 0;
    g_fdtable[fd].pipeRead = false;
    g_fdtable[fd].pipeWrite = false;
    if(n.kind == NodeType.Pipe)
    {
        bool stillUsed = false;
        foreach(ref f; g_fdtable)
        {
            if(f.node is n)
            {
                stillUsed = true;
                break;
            }
        }
        if(!stillUsed)
        {
            auto p = cast(Pipe*)n.data;
            free(p);
            free(n);
        }
    }
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
            save_filesystem();
            return cast(int)i;
        }
    }
    return -1;
}

extern(C) long fs_pread_file(int fd, void* buf, size_t count, size_t offset)
{
    if(fd < 0 || fd >= g_fdtable.length) return -1;
    auto n = g_fdtable[fd].node;
    if(n is null) return -1;
    if(n.kind == NodeType.Pipe)
    {
        auto p = cast(Pipe*)n.data;
        size_t read = 0;
        auto b = cast(ubyte*)buf;
        while(read < count && p.count > 0)
        {
            b[read++] = p.buffer[p.readPos];
            p.readPos = (p.readPos + 1) % p.buffer.length;
            p.count--;
        }
        return cast(long)read;
    }
    if(n.kind != NodeType.File) return -1;
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
    if(n is null) return -1;
    if(n.kind == NodeType.Pipe)
    {
        auto p = cast(Pipe*)n.data;
        size_t written = 0;
        auto b = cast(const ubyte*)buf;
        while(written < count && p.count < p.buffer.length)
        {
            p.buffer[p.writePos] = b[written++];
            p.writePos = (p.writePos + 1) % p.buffer.length;
            p.count++;
        }
        return cast(long)written;
    }
    if(n.kind != NodeType.File) return -1;
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
    save_filesystem();
    return cast(long)count;
}

extern(C) long fs_seek_file(int fd, long offset, int whence)
{
    if(fd < 0 || fd >= g_fdtable.length) return -1;
    auto desc = &g_fdtable[fd];
    if(desc.node is null) return -1;
    if(desc.node.kind == NodeType.Pipe) return -1;
    if(desc.node.kind != NodeType.File) return -1;
    size_t newPos = 0;
    switch(whence)
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

extern(C) int fs_dup_fd(int oldfd, int newfd)
{
    if(oldfd < 0 || oldfd >= g_fdtable.length) return -1;
    if(g_fdtable[oldfd].node is null) return -1;
    if(newfd >= 0)
    {
        if(newfd >= g_fdtable.length) return -1;
        g_fdtable[newfd] = g_fdtable[oldfd];
        return newfd;
    }
    foreach(i, ref f; g_fdtable)
    {
        if(f.node is null)
        {
            f = g_fdtable[oldfd];
            return cast(int)i;
        }
    }
    return -1;
}

private size_t buildPath(Node* n, char* buf, size_t buflen)
{
    if(n is fsRoot)
    {
        if(buflen < 2) return 0;
        buf[0] = '/';
        buf[1] = 0;
        return 1;
    }
    char*[32] segs;
    size_t count = 0;
    auto cur = n;
    while(cur !is fsRoot && cur !is null && count < segs.length)
    {
        segs[count++] = cur.name;
        cur = cur.parent;
    }
    size_t pos = 0;
    if(pos < buflen) buf[pos++] = '/';
    foreach(i; 0 .. count)
    {
        auto name = segs[count - i - 1];
        size_t l = strlen(name);
        if(pos + l >= buflen) l = buflen - pos - 1;
        memcpy(buf + pos, name, l);
        pos += l;
        if(i < count - 1 && pos < buflen)
            buf[pos++] = '/';
    }
    if(pos < buflen) buf[pos] = 0; else buf[buflen-1] = 0;
    return pos;
}

extern(C) const(char)* fs_fd2path(int fd)
{
    if(fd < 0 || fd >= g_fdtable.length) return null;
    auto n = g_fdtable[fd].node;
    if(n is null) return null;
    __gshared static char[256] pathBuf;
    buildPath(n, pathBuf.ptr, pathBuf.length);
    return pathBuf.ptr;
}

extern(C) int fs_stat(const(char)* path, Stat* st)
{
    auto n = fs_lookup(path);
    if(n is null) return -1;
    st.kind = n.kind;
    st.size = n.size;
    return 0;
}

extern(C) int fs_fstat(int fd, Stat* st)
{
    if(fd < 0 || fd >= g_fdtable.length) return -1;
    auto n = g_fdtable[fd].node;
    if(n is null) return -1;
    st.kind = n.kind;
    st.size = n.size;
    return 0;
}

extern(C) int fs_wstat(const(char)* path, const Stat* st)
{
    auto n = fs_lookup(path);
    if(n is null || n.kind != NodeType.File) return -1;
    if(st.size > n.capacity)
    {
        n.data = cast(ubyte*)realloc(n.data, st.size);
        if(st.size != 0 && n.data is null) return -1;
        n.capacity = st.size;
    }
    n.size = st.size;
    return 0;
}

extern(C) int fs_fwstat(int fd, const Stat* st)
{
    if(fd < 0 || fd >= g_fdtable.length) return -1;
    auto n = g_fdtable[fd].node;
    if(n is null || n.kind != NodeType.File) return -1;
    if(st.size > n.capacity)
    {
        n.data = cast(ubyte*)realloc(n.data, st.size);
        if(st.size != 0 && n.data is null) return -1;
        n.capacity = st.size;
    }
    n.size = st.size;
    return 0;
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

private void freeNodeTree(Node* n)
{
    if(n is null) return;
    auto c = n.child;
    while(c !is null)
    {
        auto next = c.sibling;
        freeNodeTree(c);
        c = next;
    }
    if(n.data !is null) free(n.data);
    if(n.name !is null) free(n.name);
    free(n);
}

private Node* cloneSubtree(Node* src)
{
    if(src is null) return null;
    auto n = createNode(src.name, src.kind);
    if(n is null) return null;
    if(src.kind == NodeType.File && src.size > 0)
    {
        n.data = cast(ubyte*)malloc(src.size);
        if(src.size != 0 && n.data is null)
        {
            free(n.name);
            free(n);
            return null;
        }
        memcpy(n.data, src.data, src.size);
        n.size = src.size;
        n.capacity = src.size;
    }
    auto child = src.child;
    Node* prev = null;
    while(child !is null)
    {
        auto c = cloneSubtree(child);
        if(c is null)
        {
            // free previously cloned
            freeNodeTree(n);
            return null;
        }
        if(n.child is null)
            n.child = c;
        else
            prev.sibling = c;
        c.parent = n;
        prev = c;
        child = child.sibling;
    }
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
    if(n.kind == NodeType.Directory) {
        char[300] line;
        line[0] = 'D'; line[1] = ' ';
        memcpy(line.ptr + 2, pathBuf.ptr, plen);
        line[2 + plen] = '\n';
        fwrite(line.ptr, 1, plen + 3, f);
    } else {
        // File header: F <path> <size>\n
        char[300] line;
        auto szStr = cast(char[32])"";
        size_t szLen = 0;
        size_t tmp = n.size;
        if(tmp == 0) { szStr[0]='0'; szLen=1; }
        else {
            char[32] rev; size_t r=0;
            while(tmp>0) { rev[r++] = '0'+ (tmp%10); tmp/=10; }
            for(size_t i=0;i<r;i++) szStr[i]=rev[r-1-i];
            szLen=r;
        }
        line[0]='F'; line[1]=' ';
        memcpy(line.ptr+2, pathBuf.ptr, plen); size_t pos=2+plen;
        line[pos++]=' ';
        memcpy(line.ptr+pos, szStr.ptr, szLen); pos+=szLen;
        line[pos++]='\n';
        fwrite(line.ptr,1,pos,f);
        if(n.size>0 && n.data !is null)
            fwrite(n.data,1,n.size,f);
    }
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
    "/bin",
    "/third_party",
    "/third_party/sh",
    "/third_party/dmd",
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
        if(line[0] == 'D') {
            mkdirInternal(p);
            continue;
        }

        // File line: "F <path> <size>"
        // Split path and size
        size_t pathLen = 0;
        while(p[pathLen] && p[pathLen] != ' ') ++pathLen;
        size_t sz = 0;
        if(p[pathLen] == ' ') {
            char* szStr = p + pathLen + 1;
            while(*szStr) { sz = sz*10 + (*szStr - '0'); ++szStr; }
            p[pathLen] = 0;
        }
        auto node = createFile(p);
        if(node is null) {
            // skip bytes
            fseek(f, sz, 1);
            continue;
        }
        if(sz>0) {
            node.data = cast(ubyte*)malloc(sz);
            node.size = sz; node.capacity = sz;
            fread(node.data,1,sz,f);
        }
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
    fsCurrentDir = fsRoot;
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

extern(C) int fs_remove(const(char)* path)
{
    auto n = fs_lookup(path);
    if(n is null || n is fsRoot) return -1;
    auto parent = n.parent;
    if(parent is null) return -1;
    if(parent.child is n)
        parent.child = n.sibling;
    else
    {
        auto c = parent.child;
        while(c !is null && c.sibling !is n)
            c = c.sibling;
        if(c is null) return -1;
        c.sibling = n.sibling;
    }
    freeNodeTree(n);
    save_filesystem();
    return 0;
}

extern(C) int fs_chdir(const(char)* path)
{
    auto n = fs_lookup(path);
    if(n is null || n.kind != NodeType.Directory) return -1;
    fsCurrentDir = n;
    return 0;
}

extern(C) const(char)* fs_getcwd()
{
    __gshared static char[256] cwdBuf;
    buildPath(fsCurrentDir, cwdBuf.ptr, cwdBuf.length);
    return cwdBuf.ptr;
}


extern(C) int fs_mount(const(char)* spec, const(char)* target, int flags, const(char)* fs, const(char)* aname)
{
    auto src = fs_lookup(spec);
    if(src is null) return -1;
    auto copy = cloneSubtree(src);
    if(copy is null) return -1;

    size_t len = strlen(target);
    size_t end = len;
    while(end > 1 && target[end-1] != '/') --end;
    char[128] dirBuf;
    if(end == 1)
    {
        dirBuf[0] = '/'; dirBuf[1] = 0;
    }
    else
    {
        memcpy(dirBuf.ptr, target, end);
        dirBuf[end] = 0;
    }
    auto parent = mkdirInternal(dirBuf.ptr);
    if(parent is null)
    {
        freeNodeTree(copy);
        return -1;
    }
    const(char)* fname = target + end;
    if(copy.name !is null) { free(copy.name); }
    size_t nl = strlen(fname);
    copy.name = cast(char*)malloc(nl+1);
    memcpy(copy.name, fname, nl);
    copy.name[nl] = 0;
    addChild(parent, copy);
    save_filesystem();
    return 0;
}

extern(C) int fs_bind(const(char)* oldp, const(char)* newp, int flags)
{
    // bind implemented as mount of a cloned subtree
    return fs_mount(oldp, newp, flags, null, null);
}

extern(C) int fs_unmount(const(char)* target)
{
    return fs_remove(target);
}

