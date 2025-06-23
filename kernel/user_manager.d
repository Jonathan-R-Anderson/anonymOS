module kernel.user_manager;

pragma(LDC_no_moduleinfo);

import kernel.fs : fs_create_user;
public:
struct User {
    char[16] name;
}

__gshared User[8] users;
__gshared size_t userCount;

extern(C) void init_user_manager() {
    userCount = 1;
    users[0].name[0..5] = "setup";
    users[0].name[5] = 0;
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
