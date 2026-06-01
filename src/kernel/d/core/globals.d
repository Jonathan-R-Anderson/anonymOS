module core.globals;

extern (C):

// HHDM Offset provided by Limine
__gshared ulong hhdm_offset;

ulong x64_get_hhdm_offset() {
    return hhdm_offset;
}

void x64_poke_pte(ulong* mapping, int i, ulong val) {
    mapping[i] = val;
}

ulong x64_peek_pte(ulong* mapping, int i) {
    return mapping[i];
}

void x64_poke_u64(void* ptr, ulong val) {
    *cast(ulong*)ptr = val;
}

// Kernel Physical Base (from Limine kernel address response)
__gshared ulong kernel_phys_base;
__gshared ulong kernel_virt_base;

// Init module physical base
__gshared ulong init_module_phys_base;
