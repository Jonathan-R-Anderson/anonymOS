module shell.executor;

import std.stdio;
import shell.ast;
import shell.job;
import core.sys.posix.unistd;
import core.sys.posix.sys.wait;
import core.sys.posix.fcntl;
import core.sys.posix.sys.types : mode_t;
import core.sys.posix.signal : SIGCONT, kill;
import std.process : environment;
import std.string : toStringz;
import core.stdc.string : strdup;
import core.stdc.stdio : perror;
import core.stdc.errno : errno, ECHILD;
import std.conv : to;
import std.algorithm : remove;
import std.array : array;

// --- Globals for Job Management ---
__gshared Job[] jobTable;
__gshared int nextJobId = 1;
__gshared pid_t shell_pgid;

// --- Forward Declarations ---
void launchJob(Node ast);
void execute_job_in_child(Node ast);

void updateJobStatusFromWait(Job job, int status) {
    if (WIFSTOPPED(status)) {
        job.status = JobStatus.Stopped;
    } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
        job.status = JobStatus.Completed;
    } else {
        job.status = JobStatus.Running;
    }
}

void refreshJobStatus(Job job) {
    int status;
    errno = 0;
    auto result = waitpid(job.pgid, &status, WNOHANG | WUNTRACED);
    if (result > 0) {
        updateJobStatusFromWait(job, status);
    } else if (result < 0 && errno == ECHILD && job.status == JobStatus.Running) {
        // The job has already been reaped elsewhere; treat it as completed.
        job.status = JobStatus.Completed;
    }
}

void refreshAllJobs() {
    foreach(job; jobTable) {
        refreshJobStatus(job);
    }
}

void pruneCompletedJobs() {
    jobTable = jobTable.remove!(j => j.status == JobStatus.Completed).array;
}

// --- Builtin Implementations ---
Job findJob(int jobId) {
    foreach(job; jobTable) {
        if (job.jobId == jobId) {
            return job;
        }
    }
    return null;
}

void builtin_bg(SimpleCommand cmd) {
    if (cmd.arguments.length < 2) {
        writeln("bg: usage: bg %job_id");
        return;
    }
    string jobSpec = cmd.arguments[1];
    if (jobSpec.length < 2 || jobSpec[0] != '%') {
        writeln("bg: invalid job spec");
        return;
    }

    int jobId;
    try {
        jobId = to!int(jobSpec[1 .. $]);
    } catch (Exception e) {
        writeln("bg: invalid job id");
        return;
    }

    Job job = findJob(jobId);
    if (job is null) {
        writeln("bg: job not found: ", jobSpec);
        return;
    }

    if (job.status == JobStatus.Stopped) {
        if (kill(-job.pgid, SIGCONT) < 0) {
            perror("kill (SIGCONT)");
            return;
        }
        job.status = JobStatus.Running;
        writeln("[", job.jobId, "]+ ", job.command, "&");
    }
}

void builtin_fg(SimpleCommand cmd) {
    if (cmd.arguments.length < 2) {
        writeln("fg: usage: fg %job_id");
        return;
    }
    string jobSpec = cmd.arguments[1];
    if (jobSpec.length < 2 || jobSpec[0] != '%') {
        writeln("fg: invalid job spec");
        return;
    }

    int jobId;
    try {
        jobId = to!int(jobSpec[1 .. $]);
    } catch (Exception e) {
        writeln("fg: invalid job id");
        return;
    }

    Job job = findJob(jobId);
    if (job is null) {
        writeln("fg: job not found: ", jobSpec);
        return;
    }

    if (job.status == JobStatus.Stopped) {
        if (kill(-job.pgid, SIGCONT) < 0) {
            perror("kill (SIGCONT)");
            return;
        }
        job.status = JobStatus.Running;
    }

    tcsetpgrp(STDIN_FILENO, job.pgid);

    int status;
    auto result = waitpid(job.pgid, &status, WUNTRACED);
    if (result < 0) {
        perror("waitpid");
    } else if (result > 0) {
        updateJobStatusFromWait(job, status);
    }

    tcsetpgrp(STDIN_FILENO, shell_pgid);

    if (job.status == JobStatus.Completed) {
        jobTable = jobTable.remove!(j => j.jobId == jobId).array;
    }
}

void builtin_jobs() {
    refreshAllJobs();
    foreach(job; jobTable) {
        writeln("[", job.jobId, "]\t", job.status, "\t", job.command);
    }
    pruneCompletedJobs();
}

// --- Builtin Dispatcher ---
bool handleBuiltin(SimpleCommand cmd) {
    if (cmd is null || cmd.arguments.length == 0) return false;

    auto commandName = cmd.arguments[0];
    if (commandName == "jobs") {
        builtin_jobs();
        return true;
    } else if (commandName == "fg") {
        builtin_fg(cmd);
        return true;
    } else if (commandName == "bg") {
        builtin_bg(cmd);
        return true;
    }
    return false;
}

// --- Main Execution Logic ---
public void execute(Node ast) {
    if (ast is null) return;

    if (auto cmd = cast(SimpleCommand)ast) {
        if (handleBuiltin(cmd)) {
            return;
        }
    }

    if (auto seq = cast(Sequence)ast) {
        if (seq.background) {
            launchJob(seq);
        } else {
            foreach(cmd; seq.commands) {
                execute(cmd);
            }
        }
        return;
    }

    launchJob(ast);
}

void launchJob(Node ast) {
    bool background = false;
    if (auto seq = cast(Sequence)ast) {
        background = seq.background;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return;
    }

    if (pid == 0) {
        setpgid(0, 0);
        if (!background) {
            tcsetpgrp(STDIN_FILENO, getpgrp());
        }
        execute_job_in_child(ast);
        _exit(127);
    }

    setpgid(pid, pid);
    if (background) {
        auto newJob = new Job(ast.toString(), pid, nextJobId, [pid]);
        jobTable ~= newJob;
        writeln("[", newJob.jobId, "] ", pid);
        nextJobId++;
    } else {
        tcsetpgrp(STDIN_FILENO, pid);
        int status;
        waitpid(pid, &status, WUNTRACED);
        tcsetpgrp(STDIN_FILENO, shell_pgid);
    }
}

void execute_job_in_child(Node ast) {
    if (auto cmd = cast(SimpleCommand)ast) {
        if (handleBuiltin(cmd)) {
            _exit(0);
        }
        char*[] args;
        foreach(arg; cmd.arguments) { args ~= strdup(arg.toStringz); }
        args ~= null;
        execvp(args[0], args.ptr);
        perror("lfe-sh");
        _exit(127);
    } else if (auto pipeline = cast(Pipeline)ast) {
        int numCommands = cast(int)pipeline.commands.length;
        if (numCommands <= 0) _exit(0);
        int[2][] pipes;
        pipes.length = numCommands - 1;
        for (int i = 0; i < numCommands - 1; i++) {
            if (pipe(pipes[i]) == -1) { perror("pipe"); _exit(1); }
        }
        pid_t[] pids;
        for (int i = 0; i < numCommands; i++) {
            pids ~= fork();
            if (pids[i] == -1) { perror("fork"); _exit(1); }
            if (pids[i] == 0) {
                if (i > 0) { dup2(pipes[i - 1][0], STDIN_FILENO); }
                if (i < numCommands - 1) { dup2(pipes[i][1], STDOUT_FILENO); }
                for (int j = 0; j < numCommands - 1; j++) {
                    close(pipes[j][0]);
                    close(pipes[j][1]);
                }
                execute_job_in_child(pipeline.commands[i]);
                _exit(127);
            }
        }
        for (int i = 0; i < numCommands - 1; i++) {
            close(pipes[i][0]);
            close(pipes[i][1]);
        }
        for (int i = 0; i < numCommands; i++) {
            int status;
            waitpid(pids[i], &status, 0);
        }
        _exit(0);
    } else if (auto redir = cast(Redirection)ast) {
        int target_fd = -1;
        int open_flags = 0;
        mode_t open_mode = 438;
        if (redir.type == RedirectionType.Input) {
            target_fd = STDIN_FILENO; open_flags = O_RDONLY;
        } else if (redir.type == RedirectionType.Output) {
            target_fd = STDOUT_FILENO; open_flags = O_WRONLY | O_CREAT | O_TRUNC;
        } else {
            target_fd = STDOUT_FILENO; open_flags = O_WRONLY | O_CREAT | O_APPEND;
        }
        int fd = open(redir.filename.toStringz, open_flags, open_mode);
        if (fd == -1) { perror(redir.filename.toStringz); _exit(1); }
        if (dup2(fd, target_fd) == -1) { perror("dup2"); _exit(1); }
        close(fd);
        execute_job_in_child(redir.command);
        _exit(127);
    } else if (auto seq = cast(Sequence)ast) {
        foreach(cmd; seq.commands) {
            execute(cmd);
        }
        _exit(0);
    }
}

public void initializeShell() {
    shell_pgid = getpid();
    if (isatty(STDIN_FILENO)) {
        while (tcgetpgrp(STDIN_FILENO) != getpgrp()) {
        }
        if (setpgid(shell_pgid, shell_pgid) < 0) {
            perror("setpgid");
            return;
        }
        tcsetpgrp(STDIN_FILENO, shell_pgid);
    }
}
