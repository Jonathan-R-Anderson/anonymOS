use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents a file system event captured by the monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileEvent {
    /// A file was opened by a process.
    Open { path: PathBuf, pid: u32 },
    /// A new file was created.
    Create { path: PathBuf },
    /// A file was modified.
    Modify { path: PathBuf },
    /// A file was deleted.
    Delete { path: PathBuf },
    /// A file was executed by a process.
    Execute { path: PathBuf, pid: u32 },
    /// A file was closed after being written to.
    CloseWrite { path: PathBuf },
    /// A file was renamed.
    Rename { from: PathBuf, to: PathBuf, pid: u32 },
}

/// Action to take in response to a file event (for blocking monitors).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileEventAction {
    /// Allow the file operation to proceed.
    Allow,
    /// Deny the file operation.
    Deny,
}

impl FileEvent {
    /// Returns the path associated with this event.
    pub const fn path(&self) -> &PathBuf {
        match self {
            Self::Open { path, .. }
            | Self::Create { path }
            | Self::Modify { path }
            | Self::Delete { path }
            | Self::Execute { path, .. }
            | Self::CloseWrite { path } => path,
            Self::Rename { to, .. } => to,
        }
    }

    /// Returns the PID associated with this event, if any.
    pub const fn pid(&self) -> Option<u32> {
        match self {
            Self::Open { pid, .. } | Self::Execute { pid, .. } | Self::Rename { pid, .. } => Some(*pid),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_returns_correct_path_for_open() {
        let event = FileEvent::Open {
            path: PathBuf::from("/tmp/test.txt"),
            pid: 42,
        };
        assert_eq!(event.path(), &PathBuf::from("/tmp/test.txt"));
    }

    #[test]
    fn test_path_returns_correct_path_for_create() {
        let event = FileEvent::Create {
            path: PathBuf::from("/home/user/new_file"),
        };
        assert_eq!(event.path(), &PathBuf::from("/home/user/new_file"));
    }

    #[test]
    fn test_path_returns_correct_path_for_modify() {
        let event = FileEvent::Modify {
            path: PathBuf::from("/var/log/syslog"),
        };
        assert_eq!(event.path(), &PathBuf::from("/var/log/syslog"));
    }

    #[test]
    fn test_path_returns_correct_path_for_delete() {
        let event = FileEvent::Delete {
            path: PathBuf::from("/tmp/old_file"),
        };
        assert_eq!(event.path(), &PathBuf::from("/tmp/old_file"));
    }

    #[test]
    fn test_path_returns_correct_path_for_execute() {
        let event = FileEvent::Execute {
            path: PathBuf::from("/usr/bin/malware"),
            pid: 1234,
        };
        assert_eq!(event.path(), &PathBuf::from("/usr/bin/malware"));
    }

    #[test]
    fn test_path_returns_correct_path_for_close_write() {
        let event = FileEvent::CloseWrite {
            path: PathBuf::from("/tmp/written"),
        };
        assert_eq!(event.path(), &PathBuf::from("/tmp/written"));
    }

    #[test]
    fn test_path_returns_to_path_for_rename() {
        let event = FileEvent::Rename {
            from: PathBuf::from("/tmp/old_name"),
            to: PathBuf::from("/tmp/new_name"),
            pid: 99,
        };
        assert_eq!(event.path(), &PathBuf::from("/tmp/new_name"));
    }

    #[test]
    fn test_pid_returns_some_for_open() {
        let event = FileEvent::Open {
            path: PathBuf::from("/tmp/f"),
            pid: 42,
        };
        assert_eq!(event.pid(), Some(42));
    }

    #[test]
    fn test_pid_returns_some_for_execute() {
        let event = FileEvent::Execute {
            path: PathBuf::from("/tmp/f"),
            pid: 1000,
        };
        assert_eq!(event.pid(), Some(1000));
    }

    #[test]
    fn test_pid_returns_some_for_rename() {
        let event = FileEvent::Rename {
            from: PathBuf::from("/tmp/a"),
            to: PathBuf::from("/tmp/b"),
            pid: 555,
        };
        assert_eq!(event.pid(), Some(555));
    }

    #[test]
    fn test_pid_returns_none_for_create() {
        let event = FileEvent::Create {
            path: PathBuf::from("/tmp/f"),
        };
        assert_eq!(event.pid(), None);
    }

    #[test]
    fn test_pid_returns_none_for_modify() {
        let event = FileEvent::Modify {
            path: PathBuf::from("/tmp/f"),
        };
        assert_eq!(event.pid(), None);
    }

    #[test]
    fn test_pid_returns_none_for_delete() {
        let event = FileEvent::Delete {
            path: PathBuf::from("/tmp/f"),
        };
        assert_eq!(event.pid(), None);
    }

    #[test]
    fn test_pid_returns_none_for_close_write() {
        let event = FileEvent::CloseWrite {
            path: PathBuf::from("/tmp/f"),
        };
        assert_eq!(event.pid(), None);
    }

    #[test]
    fn test_file_event_action_allow_deny_are_distinct() {
        assert_ne!(FileEventAction::Allow, FileEventAction::Deny);
    }

    #[test]
    fn test_file_event_action_equality() {
        assert_eq!(FileEventAction::Allow, FileEventAction::Allow);
        assert_eq!(FileEventAction::Deny, FileEventAction::Deny);
    }
}
