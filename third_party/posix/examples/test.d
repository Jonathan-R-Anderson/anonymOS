module app;

import posix;
import core.stdc.stdio : printf;

extern(C) void main()
{
    printf("pid=%d\n", posix_getpid());
    int fd = posix_open("README.md", O_RDONLY, 0);
    if(fd < 0)
    {
        printf("open failed\n");
        posix_exit(1);
    }
    char[64] buf;
    auto n = posix_read(fd, buf.ptr, buf.length);
    if(n > 0)
    {
        printf("%.*s", cast(int)n, buf.ptr);
    }
    posix_close(fd);
    posix_exit(0);
}
