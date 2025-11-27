module main;
import runtime;

void run()
{
    print("Installer started.\n");
    
    char[512] buf;
    
    // Create a pattern
    print("Writing pattern to sector 0...\n");
    for(int i=0; i<512; i++)
    {
        buf[i] = cast(char)('A' + (i % 26));
    }
    buf[511] = '\n'; // End with newline for viewing
    
    long ret = sys_block_write(0, 1, buf.ptr);
    if (ret != 0)
    {
        print("Write failed!\n");
        return;
    }
    print("Write success.\n");
    
    // Clear buffer
    for(int i=0; i<512; i++) buf[i] = 0;
    
    // Read back
    print("Reading back sector 0...\n");
    ret = sys_block_read(0, 1, buf.ptr);
    if (ret != 0)
    {
        print("Read failed!\n");
        return;
    }
    
    if (buf[0] == 'A' && buf[1] == 'B')
    {
        print("Verification success: Data matches.\n");
    }
    else
    {
        print("Verification failed: Data mismatch.\n");
    }
    
    print("Installer finished.\n");
}
