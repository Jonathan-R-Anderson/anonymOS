module kernel.container_service;

pragma(LDC_no_moduleinfo);

import kernel.logger : log_message, log_hex;
import kernel.hypervisor : vmm_create_vm, vmm_run_vm, vmm_destroy_vm;

struct ContainerConfig {
    char[64] baseImage;
    char[64] cmd;
}

extern(C) void init_container_service()
{
    log_message("Kernel container service initialized.\n");
}

extern(C) void start_container(ContainerConfig* cfg)
{
    log_message("[container] start_container called with cfg=");
    log_hex(cast(ulong)cfg);
    log_message("\n");
    
    if(cfg is null) {
        log_message("[container] ERROR: null config pointer\n");
        return;
    }
    
    log_message("[container] starting container\n");
    log_message("image: ");
    log_message(cfg.baseImage.ptr);
    log_message("\ncmd: ");
    log_message(cfg.cmd.ptr);
    log_message("\n");
    int id = vmm_create_vm();
    vmm_run_vm(id);
    vmm_destroy_vm(id);
}
