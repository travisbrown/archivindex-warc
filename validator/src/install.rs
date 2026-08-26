use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde::Deserialize;
use tempfile::tempdir_in;

const JWAT_VERSION: &str = "0.7.1";
const JWAT_URL: &str =
    "https://repo1.maven.org/maven2/org/jwat/jwat-tools/0.7.1/jwat-tools-0.7.1.tar.gz";
const WARCHAEOLOGY_RELEASE_URL: &str =
    "https://api.github.com/repos/NationalLibraryOfNorway/warchaeology/releases/latest";

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
        let installed = self.tools_dir.join("warchaeology").join(executable("warc"));
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
        #[derive(Deserialize)]
        struct Release {
            assets: Vec<Asset>,
        }
        #[derive(Deserialize)]
        struct Asset {
            name: String,
            browser_download_url: String,
        }

        let expected = warchaeology_asset_name()?;
        let release: Release = serde_json::from_slice(&download(WARCHAEOLOGY_RELEASE_URL)?)
            .context("invalid GitHub release response")?;
        let asset = release
            .assets
            .into_iter()
            .find(|asset| asset.name.eq_ignore_ascii_case(&expected))
            .with_context(|| format!("the latest release does not contain {expected}"))?;
        let archive = download(&asset.browser_download_url)?;
        let destination = self.tools_dir.join("warchaeology");
        fs::create_dir_all(&destination)?;
        let temporary = tempdir_in(&destination)?;

        if Path::new(&asset.name)
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
        let archive = download(JWAT_URL)?;
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

        let venv_python = venv_executable(&venv, "python");
        let status = Command::new(&venv_python)
            .arg("-m")
            .arg("pip")
            .arg("install")
            .arg("--disable-pip-version-check")
            .arg("warcio==1.8.1")
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
            if candidate.is_file() {
                return Some(candidate);
            }
            #[cfg(windows)]
            if Path::new(name).extension().is_none() {
                for extension in ["exe", "cmd", "bat", "com"] {
                    let candidate = directory.join(format!("{name}.{extension}"));
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
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

fn download(url: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "warc-validator")
        .call()
        .with_context(|| format!("could not download {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(128 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("could not read {url}"))
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

fn warchaeology_asset_name() -> Result<String> {
    let os = match env::consts::OS {
        "linux" => "Linux",
        "macos" => "Darwin",
        "windows" => "Windows",
        other => bail!("Warchaeology does not publish releases for {other}"),
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "x86_64",
        "x86" => "i386",
        other => bail!("Warchaeology does not publish releases for {other}"),
    };
    let extension = if cfg!(windows) { "zip" } else { "tar.gz" };
    Ok(format!("warchaeology_{os}_{arch}.{extension}"))
}

fn find_recursively(directory: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
    for entry in fs::read_dir(directory).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_recursively(&path, name) {
                return Some(found);
            }
        } else if path.file_name() == Some(name) {
            return Some(path);
        }
    }
    None
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
        let result = warchaeology_asset_name();
        if matches!(env::consts::OS, "linux" | "macos" | "windows")
            && matches!(env::consts::ARCH, "x86" | "x86_64")
        {
            assert!(result.unwrap().starts_with("warchaeology_"));
        } else {
            assert!(result.is_err());
        }
    }
}
