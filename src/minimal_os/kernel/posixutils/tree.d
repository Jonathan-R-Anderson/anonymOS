module minimal_os.kernel.posixutils.tree;

import minimal_os.kernel.posixutils.context;

extern(C) int main(int argc, const(char)** argv)
{
    import minimal_os.objects : getRootObject, getObject, ObjectType, ObjectID, ChannelState, SocketType;
    import minimal_os.console : print, printLine, printUnsigned;
    
    void printTree(ObjectID dirId, int depth)
    {
        auto slot = getObject(dirId);
        if (slot is null || slot.type != ObjectType.Directory) return;
        
        for (size_t i = 0; i < slot.directory.count; ++i)
        {
            auto entry = &slot.directory.entries[i];
            
            // Indent
            for (int k = 0; k < depth; ++k) print("  ");
            
            print("|-- ");
            
            // Print name
            size_t len = 0;
            while (entry.name[len] != 0) len++;
            print(cast(const(char)[])entry.name[0 .. len]);
            
            print(" (");
            // Print type
            auto childSlot = getObject(entry.cap.oid);
            if (childSlot !is null)
            {
                if (childSlot.type == ObjectType.Directory) 
                    print("DIR");
                else if (childSlot.type == ObjectType.Blob) 
                {
                    print("BLOB, ");
                    printUnsigned(childSlot.blob.size);
                    print(" bytes");
                }
                else if (childSlot.type == ObjectType.VMO)
                {
                    print("VMO, ");
                    printUnsigned(childSlot.vmo.dataLen);
                    print(" bytes");
                    if (childSlot.vmo.immutable_) print(", immutable");
                }
                else if (childSlot.type == ObjectType.Process) 
                {
                    print("PROCESS, PID=");
                    printUnsigned(childSlot.process.pid);
                }
                else if (childSlot.type == ObjectType.BlockDevice)
                {
                    print("BLOCKDEV, ");
                    printUnsigned(childSlot.blockDevice.blockCount);
                    print(" blocks");
                }
                else if (childSlot.type == ObjectType.Channel)
                {
                    print("CHANNEL");
                    if (childSlot.channel.state == ChannelState.Open) print(", open");
                    else if (childSlot.channel.state == ChannelState.Shutdown) print(", shutdown");
                    else print(", closed");
                }
                else if (childSlot.type == ObjectType.Socket)
                {
                    print("SOCKET");
                    if (childSlot.socket.type == SocketType.Stream) print(", stream");
                    else if (childSlot.socket.type == SocketType.Datagram) print(", dgram");
                }
                else if (childSlot.type == ObjectType.Window)
                    print("WINDOW");
                else if (childSlot.type == ObjectType.Device)
                    print("DEVICE");
                else 
                    print("OBJ");
            }
            else print("???");
            
            printLine(")");
            
            if (childSlot !is null && childSlot.type == ObjectType.Directory)
            {
                printTree(entry.cap.oid, depth + 1);
            }
        }
    }
    
    printLine(".");
    printTree(getRootObject(), 0);
    
    return 0;
}
