module minimal_os.kernel.numa;

/// Identifies a logical NUMA node. The minimal OS treats these as abstract
/// placement domains that callers can use to hint where a mapping should
/// reside.
enum NumaNode : ubyte
{
    node0,
    node1,
    node2,
    node3,
}

/// Hint provided when mapping a VMO into an address space. Callers can
/// optionally express an affinity for a particular NUMA node and whether the
/// kernel should replicate read-only pages for that node.
struct NumaPlacementHint
{
    bool hasPreference;
    NumaNode preferred;
    bool replicateReadOnly;

    static NumaPlacementHint automatic()
    {
        NumaPlacementHint hint;
        hint.hasPreference = false;
        hint.preferred = NumaNode.node0;
        hint.replicateReadOnly = false;
        return hint;
    }

    static NumaPlacementHint prefer(NumaNode node)
    {
        NumaPlacementHint hint;
        hint.hasPreference = true;
        hint.preferred = node;
        hint.replicateReadOnly = false;
        return hint;
    }

    static NumaPlacementHint replicate(NumaNode node)
    {
        auto hint = prefer(node);
        hint.replicateReadOnly = true;
        return hint;
    }

    NumaNode resolvedNode() const
    {
        return hasPreference ? preferred : NumaNode.node0;
    }
}
