// rm.d — D translation of the given rm(1) implementation
module rm;

version (OSX) {} // parity with DARWIN guards

import core.stdc.stdio : printf, fprintf, perror, stderr, getchar, EOF, fflush;
import core.stdc.stdlib : exit;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import core.sys.posix.sys.stat : stat, lstat, fstat, S_ISDIR;
import core.sys.posix.unistd : unlink, rmdir, isatty, fchdir, open as c_open, close,
                               STDIN_FILENO, geteuid, getegid;
import core.sys.posix.dirent : DIR, fdopendir, readdir, closedir, dirent;
import core.sys.posix.fcntl : O_RDONLY, O_DIRECTORY;
import core.sys.posix.sys.types : uid_t, gid_t;
import std.string : toStringz, lastIndexOf;
import std.algorithm : max;

// ----- constants / flags -----
enum PFX = "rm: ";

__gshared int opt_force       = 0;
__gshared int opt_recurse     = 0;
__gshared int opt_interactive = 0;

// ----- small helpers equivalent to libpu pieces -----
bool have_dots(string s) @safe @nogc nothrow { return s == "." || s == ".."; }

struct PathElem { string dirn; string basen; }

PathElem path_split(string path) {
    auto p = path;
    // strip trailing slashes (except root)
    while (p.length > 1 && p[$-1] == '/') p = p[0 .. $-1];
    if (p == "/") return PathElem("/", "/");

    auto idx = cast(ptrdiff_t) p.lastIndexOf('/');
    if (idx < 0) return PathElem(".", p);

    auto d = p[0 .. idx];
    if (d.length == 0) d = "/";
    auto b = p[idx + 1 .. $];
    return PathElem(d, b);
}

string strpathcat(string dirn, string basen) {
    if (dirn == "/") return "/" ~ basen;
    if (dirn.length == 0) return basen;
    if (dirn[$-1] == '/') return dirn ~ basen;
    return dirn ~ "/" ~ basen;
}

// simple y/N prompt (true only for y/Y)
bool ask_question(string prefix, const(char)* fmt, const(char)* name) {
    printf("%s", prefix.toStringz);
    printf(fmt, "".toStringz, name);
    fflush(stdout);

    int ch = getchar();
    bool yes = (ch == 'y' || ch == 'Y');
    while (ch != '\n' && ch != EOF) ch = getchar();
    return yes;
}

// ----- permissions (matches original simplified logic) -----
int can_write(ref const(stat) st) {
    enum S_IWOTH = 0o002;
    enum S_IWGRP = 0o020;
    enum S_IWUSR = 0o200;

    if ((st.st_mode & S_IWOTH) != 0) return 1;

    uid_t uid = geteuid();
    if (uid == st.st_uid && (st.st_mode & S_IWUSR) != 0) return 1;

    gid_t gid = getegid();
    if (gid == st.st_gid && (st.st_mode & S_IWGRP) != 0) return 1;

    return 0;
}

int should_prompt(ref const(stat) st) {
    if (opt_interactive) return 1;
    if (!can_write(st) && isatty(STDIN_FILENO) == 1) return 1;
    return 0;
}

// ----- core logic -----
int rmEntry(int dirfd, string dirn, string basen);

int iterateDirectory(int parentDirFd, string parentDir, string basen, bool force) {
    // save cwd
    int oldCwd = c_open(".", O_DIRECTORY);
    if (oldCwd < 0) { if (!force) perror(".".toStringz); return 1; }

    // open child directory
    int dfd = c_open(basen.toStringz, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        if (!force) perror(strpathcat(parentDir, basen).toStringz);
        close(oldCwd);
        return 1;
    }

    // verify still a directory after open (mitigate symlink race)
    stat stNow;
    if (fstat(dfd, &stNow) < 0) {
        if (!force) perror(strpathcat(parentDir, basen).toStringz);
        close(dfd); close(oldCwd);
        return 1;
    }
    if (!S_ISDIR(stNow.st_mode)) {
        if (!force) fprintf(stderr, PFX ~ "'%s' is no longer a directory\n".toStringz,
                            strpathcat(parentDir, basen).toStringz);
        close(dfd); close(oldCwd);
        return 1;
    }

    if (fchdir(dfd) < 0) {
        if (!force) perror(strpathcat(parentDir, basen).toStringz);
        close(dfd); close(oldCwd);
        return 1;
    }

    auto thisDir = strpathcat(parentDir, basen);
    DIR* dirp = fdopendir(dfd);
    if (dirp is null) {
        if (!force) perror(thisDir.toStringz);
        fchdir(oldCwd);
        close(dfd); close(oldCwd);
        return 1;
    }

    int rc = 0;
    while (true) {
        errno = 0;
        auto dent = readdir(dirp);
        if (dent is null) {
            if (errno != 0 && !force) perror(thisDir.toStringz);
            break;
        }
        auto name = (cast(char*)dent.d_name).fromStringz;
        if (have_dots(name)) continue;
        rc |= rmEntry(dfd, thisDir, name);
    }

    if (closedir(dirp) < 0 && !force) { perror(thisDir.toStringz); rc = 1; }

    if (fchdir(oldCwd) < 0) { perror(".".toStringz); rc = 1; }
    if (close(oldCwd) < 0 && !force) { perror(".".toStringz); rc = 1; }

    return rc;
}

int rmEntry(int dirfd, string dirn, string basen) {
    stat st;
    int rc = 0;

    if (have_dots(basen)) return 0;

    auto fn = strpathcat(dirn, basen);

    if (lstat(basen.toStringz, &st) < 0) {
        if (!opt_force) perror(fn.toStringz);
        return 1;
    }

    const bool isdir = S_ISDIR(st.st_mode) != 0;

    if (isdir) {
        if (!opt_recurse) {
            fprintf(stderr, PFX ~ "ignoring directory '%s'\n".toStringz, fn.toStringz);
            return 1;
        }

        if (!opt_force && should_prompt(st) != 0) {
            const(char)* msg = "%srecurse into '%s'?  ";
            if (!ask_question(PFX, msg, fn.toStringz)) goto out;
        }

        rc = iterateDirectory(dirfd, dirn, basen, opt_force != 0);

        if (rmdir(basen.toStringz) < 0) {
            perror(fn.toStringz);
            rc = 1;
        }
    } else {
        if (!opt_force && should_prompt(st) != 0) {
            const(char)* msg = "%sremove '%s'?  ";
            if (!ask_question(PFX, msg, fn.toStringz)) goto out;
        }

        if (unlink(basen.toStringz) < 0) {
            perror(fn.toStringz);
            rc = 1;
        }
    }

out:
    return rc;
}

// per-operand: chdir to parent, remove, chdir back
int rm_fn_actor(string fn) {
    int rc = 0;

    auto pe = path_split(fn);
    if (have_dots(pe.basen)) return 1;

    int old_dirfd = c_open(".", O_DIRECTORY);
    if (old_dirfd < 0) { perror(".".toStringz); return 1; }

    int dirfd = c_open(pe.dirn.toStringz, O_DIRECTORY);
    if (dirfd < 0) {
        if (!opt_force) perror(pe.dirn.toStringz);
        close(old_dirfd);
        return 1;
    }

    if (fchdir(dirfd) < 0) {
        perror(pe.dirn.toStringz);
        close(dirfd); close(old_dirfd);
        return 1;
    }

    rc = rmEntry(dirfd, pe.dirn, pe.basen);

    if (fchdir(old_dirfd) < 0) { perror(".".toStringz); rc = 1; }
    if (close(dirfd) < 0)     { perror(pe.dirn.toStringz); rc = 1; }
    if (close(old_dirfd) < 0) { perror(".".toStringz); rc = 1; }

    return rc;
}

// ----- minimal option parsing for -f, -i, -r/-R -----
void parse_options(ref size_t idx, string[] args) {
    idx = 1;
    while (idx < args.length) {
        auto a = args[idx];
        if (a == "--") { ++idx; break; }
        if (a.length >= 2 && a[0] == '-' && a != "-") {
            foreach (ch; a[1 .. $]) {
                final switch (ch) {
                    case 'f': opt_force = 1; break;
                    case 'i': opt_interactive = 1; break;
                    case 'r': opt_recurse = 1; break;
                    case 'R': opt_recurse = 1; break;
                    default:
                        fprintf(stderr, PFX ~ "unknown option -%c\n".toStringz, ch);
                        exit(2);
                }
            }
            ++idx;
        } else break;
    }
}

// ----- main -----
int main(string[] args) {
    if (args.length < 2) {
        fprintf(stderr, "rm - remove files or directories\n".toStringz);
        fprintf(stderr, "usage: %s [-f] [-i] [-rR] file...\n".toStringz, args[0].toStringz);
        return 2;
    }

    size_t idx;
    parse_options(idx, args);

    if (idx >= args.length) {
        fprintf(stderr, PFX ~ "missing operand\n".toStringz);
        return 2;
    }

    int rc = 0;
    for (; idx < args.length; ++idx)
        rc |= rm_fn_actor(args[idx]);

    return rc;
}
