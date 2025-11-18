use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::sleep;

use super::{key_uploader, CopyDirection, CopyOptions, Host, RebootOptions};
use crate::error::{ColmenaError, ColmenaResult};
use crate::job::JobHandle;
use crate::nix::{
    Goal,
    Key,
    NodeConfig,
    Profile,
    ProfileType,
    StorePath,
    CURRENT_PROFILE,
    SYSTEM_PROFILE,
};
use crate::util::{CommandExecution, CommandExt};

/// A remote machine connected over SSH.
#[derive(Debug)]
pub struct Ssh {
    /// The username to use to connect.
    user: Option<String>,

    /// The hostname or IP address to connect to.
    host: String,

    /// The port to connect to.
    port: Option<u16>,

    /// Local path to a ssh_config file.
    ssh_config: Option<PathBuf>,

    /// Command to elevate privileges with.
    privilege_escalation_command: Vec<String>,

    /// extra SSH options
    extra_ssh_options: Vec<String>,

    /// Whether to use the experimental `nix copy` command.
    use_nix3_copy: bool,

    job: Option<JobHandle>,
}

/// An opaque boot ID.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BootId(String);

#[async_trait]
impl Host for Ssh {
    async fn copy_closure(
        &mut self,
        closure: &StorePath,
        direction: CopyDirection,
        options: CopyOptions,
    ) -> ColmenaResult<()> {
        let command = self.nix_copy_closure(closure, direction, options);
        self.run_command(command).await
    }

    async fn realize_remote(&mut self, derivation: &StorePath) -> ColmenaResult<Vec<StorePath>> {
        let command = self.ssh(&[
            "nix-store",
            "--no-gc-warning",
            "--realise",
            derivation.as_path().to_str().unwrap(),
        ]);

        let mut execution = CommandExecution::new(command);
        execution.set_job(self.job.clone());

        let paths = execution.capture_output().await?;

        paths.lines().map(|p| p.to_string().try_into()).collect()
    }

    fn set_job(&mut self, job: Option<JobHandle>) {
        self.job = job;
    }

    async fn upload_keys(
        &mut self,
        keys: &HashMap<String, Key>,
        require_ownership: bool,
    ) -> ColmenaResult<()> {
        for (name, key) in keys {
            self.upload_key(name, key, require_ownership).await?;
        }

        Ok(())
    }

    async fn activate(&mut self, profile: &Profile, goal: Goal) -> ColmenaResult<()> {
        if !goal.requires_activation() {
            return Err(ColmenaError::Unsupported);
        }

        match profile.profile_type() {
            ProfileType::NixDarwin => {
                // For nix-darwin, we need to update the system profile symlink first
                // if we are switching profiles. This is similar to what `darwin-rebuild switch` does.
                if goal.should_switch_profile() {
                    let path = profile.as_path().to_str().unwrap();
                    let set_profile = self.ssh(&[
                        "nix-env",
                        "--profile",
                        SYSTEM_PROFILE,
                        "--set",
                        path,
                    ]);
                    self.run_command(set_profile).await?;
                }

                // For nix-darwin, we run the activation script directly to bypass potential issues
                // with darwin-rebuild path resolution (e.g., the "Not a directory" error).
                // We explicitly set systemConfig env var which the activation script expects.
                // The activation script is located at `${systemConfig}/activate`.
                let profile_path = profile.as_path().to_str().unwrap();
                let activate_script = profile.as_path().join("activate");
                let activate_script_str = activate_script.to_str().unwrap();

                let cmd_str = format!("systemConfig={} \"{}\"", profile_path, activate_script_str);
                let command = self.ssh(&["sh", "-c", &cmd_str]);
                self.run_command(command).await?;

                // Attempt to run `nh home switch` to handle standalone Home Manager configurations.
                // We run this without sudo as Home Manager runs as the target user.
                // We execute everything inside a login shell to ensure PATH and other env vars are loaded.
                // We try to cd into the local CWD on the remote host (useful for `apply-on $(hostname)`).
                // We only run nh if it exists. If it runs and fails, we allow the failure to propagate.
                let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let cwd_str = cwd.to_string_lossy();

                let inner_script = format!(
                    "cd \"{}\" 2>/dev/null; if command -v nh >/dev/null; then echo 'Running nh home switch...'; nh home switch .; else echo 'nh not found'; exit 0; fi",
                    cwd_str
                );

                let inner_escaped = inner_script.replace("'", "'\\''");
                let final_cmd = format!("exec $SHELL -l -c '{}'", inner_escaped);

                // We manually construct the SSH command to force TTY allocation (-t)
                // This is because `nh` (or its underlying tools) may behave differently or fail
                // without a TTY (e.g. "more values required" error from clap/progress bars).
                let mut nh_ssh = Command::new("ssh");
                nh_ssh.args(&["-o", "StrictHostKeyChecking=accept-new"]);
                nh_ssh.args(&["-o", "BatchMode=yes"]);
                nh_ssh.arg("-t"); // Force TTY allocation

                if let Some(port) = self.port {
                    nh_ssh.args(&["-p", &port.to_string()]);
                }
                if let Some(ssh_config) = &self.ssh_config {
                    nh_ssh.args(&["-F", ssh_config.to_str().unwrap()]);
                }

                nh_ssh.arg(self.ssh_target());
                nh_ssh.arg("--");
                nh_ssh.arg(final_cmd);

                // We map error to Ok to avoid failing deployment if nh fails (preserving "best effort" standalone support).
                let _ = self.run_command(nh_ssh).await;
            }
            ProfileType::NixOS => {
                if goal.should_switch_profile() {
                    let path = profile.as_path().to_str().unwrap();
                    let set_profile =
                        self.ssh(&["nix-env", "--profile", SYSTEM_PROFILE, "--set", path]);
                    self.run_command(set_profile).await?;
                }

                let activation_command = profile.activation_command(goal).unwrap();
                let v: Vec<&str> = activation_command.iter().map(|s| &**s).collect();
                let command = self.ssh(&v);
                self.run_command(command).await?;
            }
        }

        Ok(())
    }

    async fn get_current_system_profile(&mut self, config: &NodeConfig) -> ColmenaResult<Profile> {
        let paths = self
            .ssh(&["readlink", "-e", CURRENT_PROFILE])
            .capture_output()
            .await?;

        let path = paths
            .lines()
            .next()
            .ok_or(ColmenaError::FailedToGetCurrentProfile)?
            .to_string()
            .try_into()?;

        Ok(Profile::from_store_path_unchecked(
            path,
            config.profile_type(),
        ))
    }

    async fn get_main_system_profile(&mut self, config: &NodeConfig) -> ColmenaResult<Profile> {
        let command = format!(
            "\"readlink -e {} || readlink -e {}\"",
            SYSTEM_PROFILE, CURRENT_PROFILE
        );

        let paths = self.ssh(&["sh", "-c", &command]).capture_output().await?;

        let path = paths
            .lines()
            .next()
            .ok_or(ColmenaError::FailedToGetCurrentProfile)?
            .to_string()
            .try_into()?;

        Ok(Profile::from_store_path_unchecked(
            path,
            config.profile_type(),
        ))
    }

    async fn run_command(&mut self, command: &[&str]) -> ColmenaResult<()> {
        let command = self.ssh(command);
        self.run_command(command).await
    }

    async fn reboot(&mut self, config: &NodeConfig, options: RebootOptions) -> ColmenaResult<()> {
        if !options.wait_for_boot {
            return self.initate_reboot().await;
        }

        let old_id = self.get_boot_id().await?;

        self.initate_reboot().await?;

        if let Some(job) = &self.job {
            job.message("Waiting for reboot".to_string())?;
        }

        // Wait for node to come back up
        loop {
            // Ignore errors while waiting
            if let Ok(new_id) = self.get_boot_id().await {
                if new_id != old_id {
                    break;
                }
            }

            sleep(Duration::from_secs(2)).await;
        }

        // Ensure node has correct system profile
        if let Some(new_profile) = options.new_profile {
            let profile = self.get_current_system_profile(config).await?;

            if new_profile != profile {
                return Err(ColmenaError::ActiveProfileUnexpected { profile });
            }
        }

        Ok(())
    }
}

impl Ssh {
    pub fn new(user: Option<String>, host: String) -> Self {
        Self {
            user,
            host,
            port: None,
            ssh_config: None,
            privilege_escalation_command: Vec::new(),
            extra_ssh_options: Vec::new(),
            use_nix3_copy: false,
            job: None,
        }
    }

    pub fn set_port(&mut self, port: u16) {
        self.port = Some(port);
    }

    pub fn set_ssh_config(&mut self, ssh_config: PathBuf) {
        self.ssh_config = Some(ssh_config);
    }

    pub fn set_privilege_escalation_command(&mut self, command: Vec<String>) {
        self.privilege_escalation_command = command;
    }

    pub fn set_extra_ssh_options(&mut self, options: Vec<String>) {
        self.extra_ssh_options = options;
    }

    pub fn set_use_nix3_copy(&mut self, enable: bool) {
        self.use_nix3_copy = enable;
    }

    pub fn upcast(self) -> Box<dyn Host> {
        Box::new(self)
    }

    /// Returns a Tokio Command to run an arbitrary command on the host.
    pub fn ssh(&self, command: &[&str]) -> Command {
        let options = self.ssh_options();
        let options_str = options.join(" ");
        let privilege_escalation_command = if self.user.as_deref() != Some("root") {
            self.privilege_escalation_command.as_slice()
        } else {
            &[]
        };

        let mut cmd = Command::new("ssh");

        cmd.arg(self.ssh_target())
            .args(&options)
            .arg("--")
            .args(privilege_escalation_command)
            .args(command)
            .env("NIX_SSHOPTS", options_str);

        cmd
    }

    /// Returns a Tokio Command to run an arbitrary command on the host without
    /// applying the configured privilege escalation command. This is useful for
    /// call sites that want to manage `sudo` or other elevation mechanisms
    /// explicitly in the remote command arguments.
    pub fn ssh_no_escalation(&self, command: &[&str]) -> Command {
        let options = self.ssh_options();
        let options_str = options.join(" ");

        let mut cmd = Command::new("ssh");

        cmd.arg(self.ssh_target())
            .args(&options)
            .arg("--")
            .args(command)
            .env("NIX_SSHOPTS", options_str);

        cmd
    }

    async fn run_command(&mut self, command: Command) -> ColmenaResult<()> {
        let mut execution = CommandExecution::new(command);
        execution.set_job(self.job.clone());

        execution.run().await
    }

    fn ssh_target(&self) -> String {
        match &self.user {
            Some(n) => format!("{}@{}", n, self.host),
            None => self.host.clone(),
        }
    }

    fn nix_copy_closure(
        &self,
        path: &StorePath,
        direction: CopyDirection,
        options: CopyOptions,
    ) -> Command {
        let ssh_options = self.ssh_options();
        let ssh_options_str = ssh_options.join(" ");

        let mut command = if self.use_nix3_copy {
            // experimental `nix copy` command with ssh-ng://
            let mut command = Command::new("nix");

            command.args([
                "--extra-experimental-features",
                "nix-command",
                "copy",
                "--no-check-sigs",
            ]);

            if options.use_substitutes {
                command.args([
                    "--substitute-on-destination",
                    // needed due to UX bug in ssh-ng://
                    "--builders-use-substitutes",
                ]);
            }

            if let Some("drv") = path.extension().and_then(OsStr::to_str) {
                command.arg("--derivation");
            }

            match direction {
                CopyDirection::ToRemote => {
                    command.arg("--to");
                }
                CopyDirection::FromRemote => {
                    command.arg("--from");
                }
            }

            let mut store_uri = format!("ssh-ng://{}", self.ssh_target());
            if options.gzip {
                store_uri += "?compress=true";
            }
            command.arg(store_uri);

            command.arg(path.as_path());

            command
        } else {
            // nix-copy-closure (ssh://)
            let mut command = Command::new("nix-copy-closure");

            match direction {
                CopyDirection::ToRemote => {
                    command.arg("--to");
                }
                CopyDirection::FromRemote => {
                    command.arg("--from");
                }
            }

            // FIXME: Host-agnostic abstraction
            if options.include_outputs {
                command.arg("--include-outputs");
            }
            if options.use_substitutes {
                command.arg("--use-substitutes");
            }
            if options.gzip {
                command.arg("--gzip");
            }

            command.arg(&self.ssh_target()).arg(path.as_path());

            command
        };

        command.env("NIX_SSHOPTS", ssh_options_str);

        command
    }

    fn ssh_options(&self) -> Vec<String> {
        // TODO: Allow configuation of SSH parameters

        let mut options: Vec<String> = [
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-T",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(self.extra_ssh_options.clone())
        .collect();

        if let Some(port) = self.port {
            options.push("-p".to_string());
            options.push(port.to_string());
        }

        if let Some(ssh_config) = self.ssh_config.as_ref() {
            options.push("-F".to_string());
            options.push(ssh_config.to_str().unwrap().to_string());
        }

        options
    }

    /// Uploads a single key.
    async fn upload_key(
        &mut self,
        name: &str,
        key: &Key,
        require_ownership: bool,
    ) -> ColmenaResult<()> {
        if let Some(job) = &self.job {
            job.message(format!("Uploading key {}", name))?;
        }

        let path = key.path();
        let key_script = key_uploader::generate_script(key, path, require_ownership);

        let mut command = self.ssh(&["sh", "-c", &key_script]);

        command.stdin(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdout(Stdio::piped());

        let uploader = command.spawn()?;
        key_uploader::feed_uploader(uploader, key, self.job.clone()).await
    }

    /// Returns the current Boot ID.
    async fn get_boot_id(&mut self) -> ColmenaResult<BootId> {
        let boot_id = self
            .ssh(&["cat", "/proc/sys/kernel/random/boot_id"])
            .capture_output()
            .await?;

        Ok(BootId(boot_id))
    }

    /// Initiates reboot.
    async fn initate_reboot(&mut self) -> ColmenaResult<()> {
        match self.run_command(self.ssh(&["reboot"])).await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let ColmenaError::ChildFailure { exit_code: 255, .. } = e {
                    // Assume it's "Connection closed by remote host"
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}
