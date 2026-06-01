module memory.physmem;

import memory.mm : alloc_phys_page;

@nogc nothrow:

size_t allocFrame()
{
    return cast(size_t)alloc_phys_page();
}

void freeFrame(size_t frame)
{
    // Bump allocator currently has no reclamation support.
    cast(void)frame;
}
