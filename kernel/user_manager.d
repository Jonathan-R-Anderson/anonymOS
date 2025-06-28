module kernel.user_manager;

pragma(LDC_no_moduleinfo);

import kernel.fs : fs_create_user;
import kernel.object_namespace : Object;
public:
struct User {
    char[16] name;
}

__gshared User[8] users;
__gshared size_t userCount;
__gshared char[16] currentUser;

extern(C) void init_user_manager() {
    userCount = 1;
    users[0].name[0..5] = "setup";
    users[0].name[5] = 0;
    // Default current user to 'setup' until login occurs
    currentUser[0..5] = "setup";
    currentUser[5] = 0;
}

extern(C) bool create_user(const(char)* name) {
    if (userCount >= users.length) return false;
    size_t idx = userCount;
    size_t i = 0;
    while (i < users[idx].name.length - 1 && name[i] != 0) {
        users[idx].name[i] = cast(char)name[i];
        ++i;
    }
    users[idx].name[i] = 0;
    ++userCount;
    fs_create_user(name);
    return true;
}

extern(C) void set_current_user(const(char)* name) {
    size_t i = 0;
    while(i < currentUser.length - 1 && name[i] != 0) {
        currentUser[i] = cast(char)name[i];
        ++i;
    }
    currentUser[i] = 0;
}

extern(C) const(char)* get_current_user() {
    return currentUser.ptr;
}

extern(C) long obj_um_create_user(Object* obj, void** args, size_t nargs)
{
    if(nargs < 1 || args[0] is null) return -1;
    auto name = cast(const(char)*)args[0];
    return create_user(name) ? 0 : -1;
}

extern(C) long obj_um_set_current_user(Object* obj, void** args, size_t nargs)
{
    if(nargs < 1 || args[0] is null) return -1;
    auto name = cast(const(char)*)args[0];
    set_current_user(name);
    return 0;
}

extern(C) long obj_um_get_current_user(Object* obj, void** args, size_t nargs)
{
    if(nargs >= 1 && args[0] !is null)
    {
        auto dest = cast(char**)args[0];
        *dest = cast(char*)get_current_user();
    }
    return 0;
}
