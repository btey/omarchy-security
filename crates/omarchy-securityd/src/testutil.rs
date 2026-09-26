// SPDX-License-Identifier: GPL-3.0-or-later

//! Test helpers shared by the modules' tests.

/// A private dbus-daemon, killed on drop.
pub struct Bus {
    child: std::process::Child,
    pub address: String,
    _dir: tempfile::TempDir,
}

impl Bus {
    pub fn start() -> Option<Self> {
        use std::io::BufRead;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<busconfig><type>session</type><listen>unix:dir={}</listen>
                <policy context="default"><allow send_destination="*" eavesdrop="true"/>
                <allow eavesdrop="true"/><allow own="*"/></policy></busconfig>"#,
                dir.path().display()
            ),
        )
        .unwrap();
        let mut child = std::process::Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .args(["--nofork", "--print-address"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .ok()?;
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take()?)
            .read_line(&mut line)
            .ok()?;
        Some(Self {
            child,
            address: line.trim().to_owned(),
            _dir: dir,
        })
    }

    pub async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
