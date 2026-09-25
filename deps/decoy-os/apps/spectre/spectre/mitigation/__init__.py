import logging
import os
import signal

import psutil


class Container:
    """
    Active containment module.
    Takes actions (SIGSTOP/SIGKILL) against threat session leaders and their process trees.
    """

    def __init__(self, action: str = "none"):
        self.action = action.lower()
        self.logger = logging.getLogger("spectre_containment")
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self.logger.addHandler(ch)
            self.logger.setLevel(logging.INFO)

    def mitigate(self, pid: int, proc_name: str) -> bool:
        """
        Executes the configured mitigation action against a process and its children.
        """
        if self.action == "none":
            return False

        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            target_procs = children + [parent]
        except psutil.NoSuchProcess:
            self.logger.warning(f"Process {pid} no longer exists. Cannot apply mitigation.")
            return False
        except Exception as e:
            self.logger.exception(f"Error enumerating process tree for {pid}: {e}")
            return False

        success = True
        if self.action == "stop":
            self.logger.info(
                f"CONTAINMENT: Freezing (SIGSTOP) process tree for '{proc_name}' (PID: {pid}). Targets: {len(target_procs)}",
            )
            for p in target_procs:
                try:
                    p.send_signal(signal.SIGSTOP)
                except Exception as e:
                    self.logger.exception(f"Failed to STOP pid {p.pid}: {e}")
                    success = False

        elif self.action == "kill":
            self.logger.warning(
                "DANGER: Using SIGKILL with a polling sensor is susceptible to PID recycling race conditions. "
                "Consider using 'stop' instead for safety."
            )
            self.logger.info(
                f"CONTAINMENT: Terminating (SIGKILL) process tree for '{proc_name}' (PID: {pid}). Targets: {len(target_procs)}",
            )
            for p in target_procs:
                try:
                    p.kill()
                except Exception as e:
                    self.logger.exception(f"Failed to KILL pid {p.pid}: {e}")
                    success = False

        else:
            self.logger.warning(f"Unknown containment action: {self.action}")
            return False

        return success
