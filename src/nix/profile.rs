use std::convert::TryFrom;
use std::path::Path;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

use super::{
    BuildResult, ColmenaError, ColmenaResult, Goal, StoreDerivation, StorePath,
};

/// A Nix profile type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileType {
    /// A NixOS profile.
    #[serde(rename = "nixos")]
    NixOS,
    /// A nix-darwin profile.
    #[serde(rename = "nix-darwin")]
    NixDarwin,
}

impl Default for ProfileType {
    fn default() -> Self {
        Self::NixOS
    }
}

pub type ProfileDerivation = StoreDerivation<Profile>;

/// A NixOS system profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The store path to the profile.
    path: StorePath,

    /// The type of the profile.
    profile_type: ProfileType,
}

impl Profile {
    pub fn from_store_path(path: StorePath, profile_type: ProfileType) -> ColmenaResult<Self> {
        let activation_script = match profile_type {
            ProfileType::NixOS => "bin/switch-to-configuration",
            ProfileType::NixDarwin => "activate",
        };

        if !path.is_dir() || !path.join(activation_script).exists() {
            return Err(ColmenaError::InvalidProfile);
        }

        if path.to_str().is_none() {
            Err(ColmenaError::InvalidProfile)
        } else {
            Ok(Self { path, profile_type })
        }
    }

    /// Returns the command to activate this profile.
    pub fn activation_command(&self, goal: Goal) -> Option<Vec<String>> {
        if let Some(goal) = goal.as_str() {
            match self.profile_type {
                ProfileType::NixOS => {
                    let path = self.as_path().join("bin/switch-to-configuration");
                    let activation_command = path
                        .to_str()
                        .expect("The string should be UTF-8 valid")
                        .to_string();
                    Some(vec![activation_command, goal.to_string()])
                }
                ProfileType::NixDarwin => {
                    // For darwin, use the activate script directly instead of darwin-rebuild
                    // to avoid NIX_PATH requirements
                    let path = self.as_path().join("activate");
                    let activation_command = path
                        .to_str()
                        .expect("The string should be UTF-8 valid")
                        .to_string();
                    Some(vec![activation_command])
                }
            }
        } else {
            None
        }
    }

    /// Returns the store path.
    pub fn as_store_path(&self) -> &StorePath {
        &self.path
    }

    /// Returns the raw store path.
    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    /// Create a GC root for this profile.
    pub async fn create_gc_root(&self, path: &Path) -> ColmenaResult<()> {
        let mut command = Command::new("nix-store");
        command.args([
            "--no-build-output",
            "--indirect",
            "--add-root",
            path.to_str().unwrap(),
        ]);
        command.args(["--realise", self.as_path().to_str().unwrap()]);
        command.stdout(Stdio::null());

        let status = command.status().await?;
        if !status.success() {
            return Err(status.into());
        }

        Ok(())
    }

    pub(super) fn from_store_path_unchecked(path: StorePath, profile_type: ProfileType) -> Self {
        Self { path, profile_type }
    }
}

impl TryFrom<BuildResult<Profile>> for Profile {
    type Error = ColmenaError;

    fn try_from(result: BuildResult<Self>) -> ColmenaResult<Self> {
        let paths = result.paths();

        if paths.is_empty() {
            return Err(ColmenaError::BadOutput {
                output: String::from("There is no store path"),
            });
        }

        if paths.len() > 1 {
            return Err(ColmenaError::BadOutput {
                output: String::from("Build resulted in more than 1 store path"),
            });
        }

        let path = paths.iter().next().unwrap().to_owned();

        Ok(Self::from_store_path_unchecked(
            path,
            result.profile_type(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nix::Goal;

    #[test]
    fn test_activation_command_nix_darwin() {
        let sp = StorePath::try_from(String::from("/nix/store/fake-darwin-profile")).unwrap();
        let profile = Profile::from_store_path_unchecked(sp, ProfileType::NixDarwin);

        // For nix-darwin, activation_command should return the activate script only.
        let cmd = profile.activation_command(Goal::Switch).unwrap();
        assert_eq!(cmd.len(), 1);
        assert!(cmd[0].ends_with("activate"));
    }

    #[test]
    fn test_activation_command_nixos() {
        let sp = StorePath::try_from(String::from("/nix/store/fake-nixos-profile")).unwrap();
        let profile = Profile::from_store_path_unchecked(sp, ProfileType::NixOS);

        // For NixOS, activation_command should point to bin/switch-to-configuration and include the goal.
        let cmd = profile.activation_command(Goal::Boot).unwrap();
        assert_eq!(cmd.len(), 2);
        assert!(cmd[0].ends_with("bin/switch-to-configuration"));
        assert_eq!(cmd[1], "boot");
    }
}
