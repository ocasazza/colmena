//! Static files required to evaluate a Hive configuation.
//!
//! We embed Nix expressions (eval.nix, options.nix, modules.nix) as well as
//! as the auto-rollback script (auto-rollback.sh) into the resulting binary
//! to ease distribution. The files are written to a temporary path when
//! we need to use them.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use tempfile::{Builder as TempFileBuilder, TempDir};

use super::{Flake, HivePath};
use crate::error::ColmenaResult;
use crate::nix::flake::lock_flake_quiet;

const FLAKE_NIX: &str = "{
  description = \"Colmena Asset Flake\";
  inputs.hive.url = \"%hive%\";
  outputs = { self, hive }:
    let
      eval = import ./eval.nix;
      options = import ./options.nix;
      modules = import ./modules.nix;
    in {
      processFlake = eval {
        rawFlake = hive;
        hermetic = true;
        colmenaOptions = options;
        colmenaModules = modules;
      };
    };
}
";
const EVAL_NIX: &[u8] = include_bytes!("eval.nix");
const OPTIONS_NIX: &[u8] = b"{
  deploymentOptions = { config, lib, ... }: with lib; {
    options.deployment = {
      profileType = mkOption {
        type = types.enum [ \"nixos\" \"nix-darwin\" ];
        default = \"nixos\";
        description = \"Type of the profile to build and deploy.\";
      };

      targetHost = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = \"The host to deploy to.\";
      };

      targetUser = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = \"The user to use to connect to the host.\";
      };

      targetPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = \"The port to use to connect to the host.\";
      };

      buildOnTarget = mkOption {
        type = types.bool;
        default = false;
        description = \"Whether to build the profile on the target host.\";
      };

      replaceUnknownProfiles = mkOption {
        type = types.bool;
        default = false;
        description = \"Whether to replace unknown profiles on the target host.\";
      };

      privilegeEscalationCommand = mkOption {
        type = with types; listOf str;
        default = [ \"sudo\" ];
        description = \"The command to use to escalate privileges on the target host.\";
      };

      sshOptions = mkOption {
        type = with types; listOf str;
        default = [];
        description = \"Extra options to pass to SSH.\";
      };

      keys = mkOption {
        type = with types; attrsOf (submodule (import ./modules/key.nix));
        default = {};
        description = \"Secrets to upload to the host.\";
      };
    };
  };

  metaOptions = { config, lib, ... }: with lib; {
    options.meta = {
      nixpkgs = mkOption {
        type = types.unspecified;
        default = null;
        description = \"The Nixpkgs to use.\";
      };

      nodeNixpkgs = mkOption {
        type = with types; attrsOf types.unspecified;
        default = {};
        description = \"Per-node Nixpkgs to use.\";
      };

      specialArgs = mkOption {
        type = types.attrs;
        default = {};
        description = \"Special arguments to pass to the modules.\";
      };

      nodeSpecialArgs = mkOption {
        type = with types; attrsOf types.attrs;
        default = {};
        description = \"Per-node special arguments to pass to the modules.\";
      };

      machinesFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = \"A file containing a list of remote builders.\";
      };

      allowApplyAll = mkOption {
        type = types.bool;
        default = false;
        description = \"Whether to allow `colmena apply` without specifying nodes.\";
      };
    };
  };
}";
const MODULES_NIX: &[u8] = include_bytes!("modules.nix");

/// Static files required to evaluate a Hive configuration.
#[derive(Debug)]
pub(super) struct Assets {
    /// Path to the hive being evaluated.
    hive_path: HivePath,

    /// Temporary directory holding the files.
    temp_dir: TempDir,

    /// Locked Flake URI of the assets flake.
    assets_flake_uri: Option<String>,
}

impl Assets {
    pub async fn new(hive_path: HivePath) -> ColmenaResult<Self> {
        let temp_dir = TempFileBuilder::new().prefix("colmena-assets-").tempdir()?;

        create_file(&temp_dir, "eval.nix", false, EVAL_NIX)?;
        create_file(&temp_dir, "options.nix", false, OPTIONS_NIX)?;
        create_file(&temp_dir, "modules.nix", false, MODULES_NIX)?;

        let mut assets_flake_uri = None;

        if let HivePath::Flake(hive_flake) = &hive_path {
            // Emit a temporary flake, then resolve the locked URI
            let flake_nix = FLAKE_NIX.replace("%hive%", hive_flake.locked_uri());
            create_file(&temp_dir, "flake.nix", false, flake_nix.as_bytes())?;

            // We explicitly specify `path:` instead of letting Nix resolve
            // automatically, which would involve checking parent directories
            // for a git repository.
            let uri = format!(
                "path:{}",
                temp_dir.path().canonicalize().unwrap().to_str().unwrap()
            );
            let _ = lock_flake_quiet(&uri).await;
            let assets_flake = Flake::from_uri(uri).await?;
            assets_flake_uri = Some(assets_flake.locked_uri().to_owned());
        }

        Ok(Self {
            hive_path,
            temp_dir,
            assets_flake_uri,
        })
    }

    /// Returns the base expression from which the evaluated Hive can be used.
    pub fn get_base_expression(&self) -> String {
        match &self.hive_path {
            HivePath::Legacy(path) => {
                format!(
                    "with builtins; let eval = import {eval_nix}; hive = eval {{ rawHive = import {path}; colmenaOptions = import {options_nix}; colmenaModules = import {modules_nix}; }}; in ",
                    path = path.to_str().unwrap(),
                    eval_nix = self.get_path("eval.nix"),
                    options_nix = self.get_path("options.nix"),
                    modules_nix = self.get_path("modules.nix"),
                )
            }
            HivePath::Flake(_) => {
                format!(
                    "with builtins; let assets = getFlake \"{assets_flake_uri}\"; hive = assets.processFlake; in ",
                    assets_flake_uri = self.assets_flake_uri.as_ref().expect("The assets flake must have been initialized"),
                )
            }
        }
    }

    fn get_path(&self, name: &str) -> String {
        self.temp_dir
            .path()
            .join(name)
            .to_str()
            .unwrap()
            .to_string()
    }
}

fn create_file(base: &TempDir, name: &str, executable: bool, contents: &[u8]) -> ColmenaResult<()> {
    let mode = if executable { 0o700 } else { 0o600 };
    let path = base.path().join(name);
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)?;

    f.write_all(contents)?;

    Ok(())
}
