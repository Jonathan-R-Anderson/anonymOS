module shell.job;

import core.sys.posix.unistd : pid_t;

public enum JobStatus {
    Running,
    Stopped,
    Done
}

public class Job {
    public string command;
    public pid_t pgid;
    public JobStatus status;
    public int jobId;
    public bool notified = false;
    public pid_t[] pids;

    this(string cmd, pid_t pgid, int jobId, pid_t[] pids) {
        this.command = cmd;
        this.pgid = pgid;
        this.jobId = jobId;
        this.status = JobStatus.Running;
        this.pids = pids;
    }
}
