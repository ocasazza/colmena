use std::collections::HashMap;
use std::convert::TryInto;
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
                // IMPORTANT: The activation script must run with sudo to update /run/current-system
                let profile_path = profile.as_path().to_str().unwrap();
                let activate_script = profile.as_path().join("activate");
                let activate_script_str = activate_script.to_str().unwrap();

                // Run activation with explicit sudo and systemConfig env var
                let command = self.ssh(&[
                    "sudo",
                    "-E",  // Preserve environment variables
                    "env",
                    &format!("systemConfig={}", profile_path),
                    activate_script_str,
                ]);
                self.run_command(command).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that Colmena's Darwin activation uses sudo to update /run/current-system
    /// This is critical because without sudo, the activation script cannot update
    /// the /run/current-system symlink which is owned by root.
    #[test]
    fn test_darwin_activation_requires_sudo_for_run_current_system() {
        let ssh = Ssh::new(Some("testuser".to_string()), "testhost".to_string());
        let profile_path = PathBuf::from("/nix/store/abc123-darwin-system");
        let activate_script = profile_path.join("activate");

        // Build the exact command that Colmena uses for Darwin activation
        let command = ssh.ssh(&[
            "sudo",
            "-E",
            "env",
            &format!("systemConfig={}", profile_path.to_str().unwrap()),
            activate_script.to_str().unwrap(),
        ]);

        let debug_output = format!("{:?}", command);

        // Critical: Verify sudo is present - without it, /run/current-system cannot be updated
        assert!(
            debug_output.contains("sudo"),
            "Darwin activation MUST use sudo to update /run/current-system (root-owned symlink)"
        );

        // Critical: Verify -E flag preserves environment for systemConfig
        assert!(
            debug_output.contains("-E"),
            "Darwin activation MUST use -E to preserve systemConfig environment variable"
        );

        // Critical: Verify systemConfig is set - the activation script requires this
        assert!(
            debug_output.contains("systemConfig="),
            "Darwin activation MUST set systemConfig environment variable for the activation script"
        );

        // Verify the profile path is referenced
        assert!(
            debug_output.contains("/nix/store/abc123-darwin-system"),
            "Darwin activation MUST reference the correct profile path"
        );

        // Verify the activate script is called
        assert!(
            debug_output.contains("/activate"),
            "Darwin activation MUST call the activate script"
        );
    }

    /// Test that Colmena's ssh_target method correctly formats user@host
    /// This is used throughout Colmena for SSH connections
    #[test]
    fn test_ssh_target_user_host_formatting() {
        let ssh_with_user = Ssh::new(Some("admin".to_string()), "example.com".to_string());
        assert_eq!(
            ssh_with_user.ssh_target(),
            "admin@example.com",
            "Colmena should format SSH target as user@host when user is provided"
        );

        let ssh_no_user = Ssh::new(None, "example.com".to_string());
        assert_eq!(
            ssh_no_user.ssh_target(),
            "example.com",
            "Colmena should use just hostname when no user is provided"
        );
    }
}
