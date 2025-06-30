# anonymos-object-tree

This repository hosts an object-based namespace for a custom operating system. The
layout mirrors the design used in the Norost project but is intended to integrate
with the [internetcomputer](https://github.com/Jonathan-R-Anderson/internetcomputer)
codebase.

Kernel services are exposed as nodes in a single tree. Each node can store methods
and properties that are accessible through the object path. Recent updates add
recursive cleanup and helpers like `obj_remove`, `obj_create_path` and
`obj_destroy_path` so that nodes may be dynamically created or destroyed at
runtime.

The main logic resides in `kernel/object_namespace.d` while
`kernel/object_validator.d` performs A\* search to verify the tree is acyclic.
The code is written in D and compiles with `ldc2` when the required kernel
headers are available.


