module kernel.sync;

public:

struct Semaphore {
    int count;
}

enum MAX_SEMAPHORES = 16;
__gshared Semaphore[MAX_SEMAPHORES] g_semaphores;

extern(C) void semaphore_init()
{
    foreach(ref s; g_semaphores)
        s.count = 1;
}

extern(C) int sem_acquire(size_t id)
{
    if(id >= g_semaphores.length)
        return -1;
    while(g_semaphores[id].count <= 0)
        asm { "hlt"; }
    g_semaphores[id].count--;
    return 0;
}

extern(C) int sem_release(size_t id)
{
    if(id >= g_semaphores.length)
        return -1;
    g_semaphores[id].count++;
    return 0;
}

struct RendezSlot {
    ulong tag;
    long value;
    bool used;
    bool waiting;
}

enum MAX_RENDEZ = 16;
__gshared RendezSlot[MAX_RENDEZ] g_rendez;

extern(C) long rendezvous(ulong tag, long val)
{
    foreach(ref slot; g_rendez)
    {
        if(slot.used && slot.tag == tag && slot.waiting)
        {
            long rv = slot.value;
            slot.value = val;
            slot.waiting = false;
            return rv;
        }
    }
    foreach(ref slot; g_rendez)
    {
        if(!slot.used)
        {
            slot.used = true;
            slot.tag = tag;
            slot.value = val;
            slot.waiting = true;
            while(slot.waiting)
                asm { "hlt"; }
            long rv = slot.value;
            slot.used = false;
            return rv;
        }
    }
    return -1;
}
