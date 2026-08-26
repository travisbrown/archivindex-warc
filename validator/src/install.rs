use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tempfile::tempdir_in;

const JWAT_VERSION: &str = "0.7.1";
const JWAT_URL: &str =
    "https://repo1.maven.org/maven2/org/jwat/jwat-tools/0.7.1/jwat-tools-0.7.1.tar.gz";
const JWAT_SHA256: &str = "d9930211446b7ca98a3c4e1830dcb758eb4ef2823aa2bd2c726850748ad512dd";
const WARCHAEOLOGY_VERSION: &str = "5.0.0";
/// The pip requirements installing warcio, pinned to the release artifacts by SHA-256 digest.
const WARCIO_REQUIREMENTS: &str = "\
warcio==1.8.1 \\
    --hash=sha256:82345c5914d36cb5e0513210dbf759e3db348bf8d0f7762996ccce3a5ce6e87b \\
    --hash=sha256:76f71b22159ca3c043521e10ee8a2478d167672ad1d137c7c15e40b0d5c73ccd
six==1.17.0 \\
    --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274 \\
    --hash=sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81
";

#[derive(Debug, Clone)]
pub struct ResolvedCommand {
    program: PathBuf,
    launcher: Launcher,
}

#[derive(Debug, Clone, Copy)]
enum Launcher {
    Direct,
    Shell,
    Cmd,
}

impl ResolvedCommand {
    const fn direct(program: PathBuf) -> Self {
        Self {
            program,
            launcher: Launcher::Direct,
        }
    }

    const fn script(program: PathBuf) -> Self {
        let launcher = if cfg!(windows) {
            Launcher::Cmd
        } else {
            Launcher::Shell
        };
        Self { program, launcher }
    }

    fn jwat(program: PathBuf) -> Self {
        match program.extension().and_then(|extension| extension.to_str()) {
            Some(extension) if extension.eq_ignore_ascii_case("sh") => Self {
                program,
                launcher: Launcher::Shell,
            },
            Some(extension) if extension.eq_ignore_ascii_case("cmd") => Self {
                program,
                launcher: Launcher::Cmd,
            },
            _ => Self::direct(program),
        }
    }

    pub fn command(&self) -> Command {
        match self.launcher {
            Launcher::Direct => Command::new(&self.program),
            Launcher::Shell => {
                let mut command = Command::new("sh");
                command.arg(&self.program);
                command
            }
            Launcher::Cmd => {
                let mut command = Command::new("cmd");
                command.arg("/C").arg(&self.program);
                command
            }
        }
    }
}

pub struct ToolResolver {
    tools_dir: PathBuf,
    install: bool,
}

impl ToolResolver {
    pub const fn new(tools_dir: PathBuf, install: bool) -> Self {
        Self { tools_dir, install }
    }

    pub fn warchaeology(&self) -> Result<ResolvedCommand> {
        if let Some(path) = env_command("WARC_VALIDATOR_WARCHAEOLOGY") {
            return Ok(ResolvedCommand::direct(path));
        }
        if let Some(path) = find_on_path(&["warc"]).filter(|path| is_warchaeology(path)) {
            return Ok(ResolvedCommand::direct(path));
        }
        let installed = self
            .tools_dir
            .join(format!("warchaeology-{WARCHAEOLOGY_VERSION}"))
            .join(executable("warc"));
        if installed.is_file() {
            return Ok(ResolvedCommand::direct(installed));
        }
        if !self.install {
            bail!("warc is not on PATH (automatic installation disabled)");
        }

        log::warn!("Warchaeology is missing; installing it in the local tools cache...");
        self.install_warchaeology()
            .map(ResolvedCommand::direct)
            .context("local Warchaeology installation failed")
    }

    pub fn jwat_tools(&self) -> Result<ResolvedCommand> {
        if let Some(path) = env_command("WARC_VALIDATOR_JWAT_TOOLS") {
            return Ok(ResolvedCommand::jwat(path));
        }
        if let Some(path) = find_on_path(&["jwattools", "jwattools.sh", "jwattools.cmd"]) {
            return Ok(ResolvedCommand::jwat(path));
        }
        let home = self.tools_dir.join(format!("jwat-tools-{JWAT_VERSION}"));
        let installed = home.join(if cfg!(windows) {
            "jwattools.cmd"
        } else {
            "jwattools.sh"
        });
        if installed.is_file() {
            return Ok(ResolvedCommand::script(installed));
        }
        if !self.install {
            bail!("jwattools is not on PATH (automatic installation disabled)");
        }
        if find_on_path(&[executable("java").to_string_lossy().as_ref()]).is_none() {
            bail!("jwattools is not on PATH and Java is unavailable for a local installation");
        }

        log::warn!("JWAT-Tools is missing; installing it in the local tools cache...");
        self.install_jwat_tools()
            .map(ResolvedCommand::script)
            .context("local JWAT-Tools installation failed")
    }

    pub fn warcio(&self) -> Result<ResolvedCommand> {
        if let Some(path) = env_command("WARC_VALIDATOR_WARCIO") {
            return Ok(ResolvedCommand::direct(path));
        }
        if let Some(path) = find_on_path(&["warcio"]) {
            return Ok(ResolvedCommand::direct(path));
        }
        let venv = self.tools_dir.join("warcio-venv");
        let installed = venv_executable(&venv, "warcio");
        if installed.is_file() {
            return Ok(ResolvedCommand::direct(installed));
        }
        if !self.install {
            bail!("warcio is not on PATH (automatic installation disabled)");
        }

        log::warn!("warcio is missing; installing it in a local Python environment...");
        self.install_warcio()
            .map(ResolvedCommand::direct)
            .context("local warcio installation failed")
    }

    fn install_warchaeology(&self) -> Result<PathBuf> {
        let (asset, sha256) = warchaeology_asset()?;
        let url = format!(
            "https://github.com/NationalLibraryOfNorway/warchaeology/releases/download/v{WARCHAEOLOGY_VERSION}/{asset}"
        );
        let archive = download(&url, sha256)?;
        let destination = self
            .tools_dir
            .join(format!("warchaeology-{WARCHAEOLOGY_VERSION}"));
        fs::create_dir_all(&destination)?;
        let temporary = tempdir_in(&destination)?;

        if Path::new(asset)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
        {
            extract_zip(&archive, temporary.path())?;
        } else {
            extract_tar_gz(&archive, temporary.path())?;
        }

        let source = find_recursively(temporary.path(), executable("warc").as_os_str())
            .context("release archive did not contain the warc executable")?;
        let installed = destination.join(executable("warc"));
        fs::copy(source, &installed)?;
        make_executable(&installed)?;
        Ok(installed)
    }

    fn install_jwat_tools(&self) -> Result<PathBuf> {
        fs::create_dir_all(&self.tools_dir)?;
        let archive = download(JWAT_URL, JWAT_SHA256)?;
        extract_tar_gz(&archive, &self.tools_dir)?;
        let installed = self
            .tools_dir
            .join(format!("jwat-tools-{JWAT_VERSION}"))
            .join(if cfg!(windows) {
                "jwattools.cmd"
            } else {
                "jwattools.sh"
            });
        if !installed.is_file() {
            bail!("JWAT-Tools archive did not contain the expected launcher");
        }
        make_executable(&installed)?;
        Ok(installed)
    }

    fn install_warcio(&self) -> Result<PathBuf> {
        let python = find_on_path(&[
            executable("python3").to_string_lossy().as_ref(),
            executable("python").to_string_lossy().as_ref(),
        ])
        .context("Python is unavailable")?;
        fs::create_dir_all(&self.tools_dir)?;
        let venv = self.tools_dir.join("warcio-venv");

        let status = Command::new(&python)
            .arg("-m")
            .arg("venv")
            .arg(&venv)
            .status()
            .context("could not create the Python virtual environment")?;
        if !status.success() {
            bail!("Python could not create the virtual environment");
        }

        let requirements = venv.join("requirements.txt");
        fs::write(&requirements, WARCIO_REQUIREMENTS)?;
        let venv_python = venv_executable(&venv, "python");
        let status = Command::new(&venv_python)
            .arg("-m")
            .arg("pip")
            .arg("install")
            .arg("--disable-pip-version-check")
            .arg("--require-hashes")
            .arg("--requirement")
            .arg(&requirements)
            .status()
            .context("could not run pip in the local virtual environment")?;
        if !status.success() {
            bail!("pip could not install warcio");
        }

        let installed = venv_executable(&venv, "warcio");
        if !installed.is_file() {
            bail!("pip completed but did not create a warcio executable");
        }
        Ok(installed)
    }
}

fn env_command(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn executable(name: &str) -> OsString {
    if cfg!(windows) {
        format!("{name}.exe").into()
    } else {
        name.into()
    }
}

fn venv_executable(venv: &Path, name: &str) -> PathBuf {
    if cfg!(windows) {
        venv.join("Scripts").join(executable(name))
    } else {
        venv.join("bin").join(name)
    }
}

fn find_on_path(names: &[&str]) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        for name in names {
            let candidate = directory.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
            #[cfg(windows)]
            if Path::new(name).extension().is_none() {
                for extension in ["exe", "cmd", "bat", "com"] {
                    let candidate = directory.join(format!("{name}.{extension}"));
                    if is_executable_file(&candidate) {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn is_warchaeology(path: &Path) -> bool {
    let Ok(output) = Command::new(path)
        .arg("version")
        .arg("--output")
        .arg("json")
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .is_some_and(|value| value.get("gitVersion").is_some() && value.get("platform").is_some())
}

/// Download an artifact and verify it against its pinned SHA-256 digest.
fn download(url: &str, sha256: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .header("User-Agent", "warc-validator")
        .call()
        .with_context(|| format!("could not download {url}"))?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(128 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("could not read {url}"))?;
    verify_sha256(url, &bytes, sha256)?;
    Ok(bytes)
}

fn verify_sha256(url: &str, bytes: &[u8], sha256: &str) -> Result<()> {
    let actual = Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
            hex
        });
    if actual == sha256 {
        Ok(())
    } else {
        bail!("{url} does not match its pinned SHA-256 digest: expected {sha256}, got {actual}")
    }
}

fn extract_tar_gz(bytes: &[u8], destination: &Path) -> Result<()> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(destination)
        .context("could not unpack tar.gz archive")
}

fn extract_zip(bytes: &[u8], destination: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("invalid zip archive")?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let Some(name) = entry.enclosed_name() else {
            bail!("zip archive contains an unsafe path");
        };
        let target = destination.join(name);
        if entry.is_dir() {
            fs::create_dir_all(target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = File::create(target)?;
        std::io::copy(&mut entry, &mut output)?;
        output.flush()?;
    }
    Ok(())
}

/// The Warchaeology release archive for this host and its SHA-256 digest from the release's
/// `checksums.txt`.
fn warchaeology_asset() -> Result<(&'static str, &'static str)> {
    Ok(match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => (
            "warchaeology_Linux_x86_64.tar.gz",
            "7c30286a0d3948166328d90bd2012cb2c1157188f30d2aed468f01275195a059",
        ),
        ("linux", "x86") => (
            "warchaeology_Linux_i386.tar.gz",
            "2b3db5a88b7218bd24566ac851c46cb0672ce606eec3d1a2b8a630666a8d6230",
        ),
        ("macos", "x86_64") => (
            "warchaeology_Darwin_x86_64.tar.gz",
            "a5eeade1705fb57700ffce82b31a8d3aa7efab35c5b13080d2f2cc1965fdd2bb",
        ),
        ("windows", "x86_64") => (
            "warchaeology_Windows_x86_64.zip",
            "c7a0de1287ed4ddff5c592360513c9bd3777be42254b23bfbb91dd8e74b89956",
        ),
        ("windows", "x86") => (
            "warchaeology_Windows_i386.zip",
            "27a0911a39a5c4b162d538812b7a344113e2eef55e0af68c74ee69f166f83242",
        ),
        (os, arch) => bail!("Warchaeology {WARCHAEOLOGY_VERSION} has no release for {os} {arch}"),
    })
}

/// Find a regular file by name below `directory`, without following symbolic links and skipping
/// entries that cannot be read.
fn find_recursively(directory: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
    fs::read_dir(directory).ok()?.flatten().find_map(|entry| {
        let file_type = entry.file_type().ok()?;
        let path = entry.path();
        if file_type.is_dir() {
            find_recursively(&path, name)
        } else if file_type.is_file() && path.file_name() == Some(name) {
            Some(path)
        } else {
            None
        }
    })
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_asset_matches_supported_host() {
        let result = warchaeology_asset();
        if matches!(env::consts::OS, "linux" | "macos" | "windows")
            && matches!(env::consts::ARCH, "x86" | "x86_64")
        {
            let (asset, sha256) = result.unwrap();
            assert!(asset.starts_with("warchaeology_"));
            assert_eq!(sha256.len(), 64);
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn verifies_pinned_digests() {
        const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert!(verify_sha256("x", b"", EMPTY).is_ok());
        let error = verify_sha256("x", b"y", EMPTY).unwrap_err();
        assert!(error.to_string().contains("pinned SHA-256 digest"));
    }
}
