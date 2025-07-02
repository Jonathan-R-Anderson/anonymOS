module kernel.object_validator;

pragma(LDC_no_moduleinfo);

import kernel.object_namespace : Object, rootObject;
import kernel.logger : log_message;

private enum MAX_NODES = 1024;

struct PQEntry {
    Object* obj;
    size_t g;
    size_t f;
}

struct PriorityQueue {
    PQEntry[MAX_NODES] data;
    size_t count;

    bool empty() const { return count == 0; }

    void push(PQEntry e)
    {
        if(count < MAX_NODES)
        {
            data[count++] = e;
        }
    }

    PQEntry popMin()
    {
        size_t best = 0;
        foreach(i; 1 .. count)
        {
            if(data[i].f < data[best].f)
                best = i;
        }
        auto e = data[best];
        if(count > 0)
        {
            data[best] = data[count - 1];
            count--;
        }
        return e;
    }
}

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

static size_t heuristic(Object* /*node*/, Object* /*goal*/)
{
    // Simple zero heuristic suitable for generic graphs
    return 0;
}

private void enqueueNeighbor(Object* neighbor, size_t g, Object* goal, ref PriorityQueue open)
{
    if(neighbor is null) return;
    auto h = heuristic(neighbor, goal);
    PQEntry e;
    e.obj = neighbor;
    e.g = g + 1;
    e.f = e.g + h;
    open.push(e);
}

private bool aStarCycleSearch(Object* start)
{
    if(start is null) return false;
    PriorityQueue open;
    VisitedSet closed;

    // Start search from neighbors of start to avoid zero-length path
    enqueueNeighbor(start.child, 0, start, open);
    enqueueNeighbor(start.sibling, 0, start, open);

    while(!open.empty())
    {
        auto current = open.popMin();
        if(current.obj is start)
            return true; // Found a path back to start => cycle
        if(closed.contains(current.obj))
            continue;
        closed.add(current.obj);

        auto c = current.obj.child;
        while(c !is null)
        {
            enqueueNeighbor(c, current.g, start, open);
            c = c.sibling;
        }
        enqueueNeighbor(current.obj.sibling, current.g, start, open);
    }
    return false;
}

extern(C) bool validate_object_graph()
{
    if(rootObject is null)
        return true;
    bool cycle = aStarCycleSearch(rootObject);
    if(cycle)
        log_message("Object graph cycle detected\n");
    return !cycle;
}

