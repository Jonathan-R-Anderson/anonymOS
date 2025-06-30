module kernel.sanity;

pragma(LDC_no_moduleinfo);

import kernel.logger : log_message, log_hex;
import kernel.object_namespace : rootObject;
import kernel.object_validator : validate_object_graph;
import kernel.fs : fsRoot;
import kernel.process_manager : g_process_count;
import kernel.user_manager : userCount;

extern(C) void run_sanity_checks()
{
    log_message("Running OS sanity checks...\n");

    if(rootObject is null)
        log_message("[FAIL] Object tree not initialized\n");
    else
    {
        if(validate_object_graph())
            log_message("[OK] Object tree valid\n");
        else
            log_message("[FAIL] Object tree invalid\n");
    }

    if(fsRoot is null)
        log_message("[FAIL] Filesystem not initialized\n");
    else
        log_message("[OK] Filesystem present\n");

    log_message("Process count: ");
    log_hex(g_process_count);
    log_message("\n");

    log_message("User count: ");
    log_hex(userCount);
    log_message("\n");
}
