// logname.d — D translation of the provided C logname
module logname_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import core.stdc.stdlib  : EXIT_FAILURE, EXIT_SUCCESS;
import core.stdc.stdio   : printf, perror;
import core.sys.posix.unistd : getlogin;

extern(C) int main(int argc, char** argv)
{
    // No options / args to parse (kept identical to the C version)
    auto s = getlogin();
    if (s is null) {
        // perror(_("getlogin(3)")) equivalent without gettext
        perror("getlogin(3)");
        return 1;
    }

    // Match C’s return check on printf
    return (printf("%s\n", s) < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
