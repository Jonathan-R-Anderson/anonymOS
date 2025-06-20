import kernel.memory.virtmem;

void main()
{
    virtmem_init();
    auto p1 = cast(ubyte*)virtmem_alloc(1, 4);
    foreach(i; 0 .. 4) p1[i] = cast(ubyte)(i+1);
    assert(virtmem_size(1) == 4);
    auto p2 = cast(ubyte*)virtmem_alloc(1, 2);
    p2[0] = 5; p2[1] = 6;
    assert(virtmem_size(1) == 6);
    auto q = cast(ubyte*)virtmem_alloc(2, 3);
    q[0] = 7;
    assert(virtmem_size(2) == 3);
    assert(virtmem_size(1) == 6);
    virtmem_free(1);
    assert(virtmem_size(1) == 0);
}
