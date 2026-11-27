//! Running `ghostmesh up` in the background: systemd unit, launchd job or Windows scheduled task.
//!
//! The definitions are built as plain data so they can be tested and shown before anything is written.

use std::path::{Path, PathBuf};

pub enum Install {
    /// Write `content` to `path`, then run `then` commands.
    File {
        path: PathBuf,
        content: String,
        then: Vec<Vec<String>>,
    },
    /// Only run commands (Windows scheduled task).
    Commands(Vec<Vec<String>>),
}

fn v(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

pub fn systemd_unit(exe: &Path, port: u16) -> String {
    format!(
        "[Unit]\n\
         Description=GhostMesh node\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         ExecStart={exe} up --port {port}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=full\n\
         PrivateTmp=yes\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe.display()
    )
}

pub fn launchd_plist(exe: &Path, port: u16) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>Label</key><string>io.ghostmesh.node</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\
         \t\t<string>{exe}</string>\n\t\t<string>up</string>\n\t\t<string>--port</string>\n\t\t<string>{port}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key><true/>\n\
         \t<key>KeepAlive</key><true/>\n\
         </dict>\n</plist>\n",
        exe = exe.display()
    )
}

pub fn install_plan(exe: &Path, port: u16) -> Install {
    if cfg!(windows) {
        // A scheduled task at logon keeps the per-user configuration and the key vault of the user.
        let run = format!("\"{}\" up --port {port}", exe.display());
        Install::Commands(vec![v(&[
            "schtasks",
            "/Create",
            "/TN",
            "GhostMesh",
            "/TR",
            &run,
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/F",
        ])])
    } else if cfg!(target_os = "macos") {
        let path = PathBuf::from("/Library/LaunchDaemons/io.ghostmesh.node.plist");
        Install::File {
            content: launchd_plist(exe, port),
            then: vec![v(&["launchctl", "load", "-w", &path.display().to_string()])],
            path,
        }
    } else {
        Install::File {
            path: PathBuf::from("/etc/systemd/system/ghostmesh.service"),
            content: systemd_unit(exe, port),
            then: vec![
                v(&["systemctl", "daemon-reload"]),
                v(&["systemctl", "enable", "--now", "ghostmesh.service"]),
            ],
        }
    }
}

pub fn uninstall_plan() -> Vec<Vec<String>> {
    if cfg!(windows) {
        vec![v(&["schtasks", "/Delete", "/TN", "GhostMesh", "/F"])]
    } else if cfg!(target_os = "macos") {
        vec![
            v(&[
                "launchctl",
                "unload",
                "-w",
                "/Library/LaunchDaemons/io.ghostmesh.node.plist",
            ]),
            v(&["rm", "-f", "/Library/LaunchDaemons/io.ghostmesh.node.plist"]),
        ]
    } else {
        vec![
            v(&["systemctl", "disable", "--now", "ghostmesh.service"]),
            v(&["rm", "-f", "/etc/systemd/system/ghostmesh.service"]),
            v(&["systemctl", "daemon-reload"]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_and_plist_contain_the_command() {
        let exe = Path::new("/usr/local/bin/ghostmesh");
        let unit = systemd_unit(exe, 4242);
        assert!(unit.contains("ExecStart=/usr/local/bin/ghostmesh up --port 4242"));
        assert!(unit.contains("Restart=on-failure") && unit.contains("NoNewPrivileges=yes"));
        let plist = launchd_plist(exe, 4242);
        assert!(
            plist.contains("<string>/usr/local/bin/ghostmesh</string>")
                && plist.contains("<string>4242</string>")
        );
        assert!(plist.contains("RunAtLoad"));
    }

    #[test]
    fn plans_exist_for_this_platform() {
        match install_plan(Path::new("ghostmesh"), 4242) {
            Install::File {
                path,
                content,
                then,
            } => {
                assert!(!content.is_empty() && !then.is_empty());
                assert!(path.is_absolute() || cfg!(windows));
            }
            Install::Commands(c) => assert!(c[0][0] == "schtasks"),
        }
        assert!(!uninstall_plan().is_empty());
    }
}
