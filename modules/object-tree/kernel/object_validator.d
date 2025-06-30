module kernel.object_validator;

pragma(LDC_no_moduleinfo);

import kernel.object_namespace : Object, rootObject;
import kernel.logger : log_message;

private enum MAX_NODES = 1024;

struct VisitedSet {
    Object*[MAX_NODES] nodes;
    size_t count;

    bool contains(Object* o) const
    {
        foreach(i; 0 .. count)
        {
            if(nodes[i] is o)
                return true;
        }
        return false;
    }

    void add(Object* o)
    {
        if(count < MAX_NODES)
            nodes[count++] = o;
    }
}

private bool detectCycle(Object* node, ref VisitedSet visited)
{
    if(node is null)
        return false;
    if(visited.contains(node))
        return true; // encountered a node twice => cycle
    visited.add(node);

    auto c = node.child;
    while(c !is null)
    {
        if(detectCycle(c, visited))
            return true;
        c = c.sibling;
    }
    return false;
}

extern(C) bool validate_object_graph()
{
    if(rootObject is null)
        return true;
    VisitedSet visited;
    bool cycle = detectCycle(rootObject, visited);
    if(cycle)
        log_message("Object graph cycle detected\n");
    return !cycle;
}

