// src/exclude.rs

//! Per-app module exclusion list, managed from the WebUI.
//!
//! The WebUI stores two keys in `config.prop`:
//! - `exclude_apps=<pkg>,<pkg>,...`: packages that must not load any Zygisk module.
//! - `exclude_unmount=0|1`: whether excluded apps also get their module mounts reverted
//!   (defaults to enabled when the key is absent).
//!
//! Only regular application uids can ever match, so system_server and the system uids
//! are never affected, whatever the file contains.

use log::{debug, warn};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Mutex;
use std::time::SystemTime;

const CONFIG_PATH: &str = "/data/adb/nyazygisk/config.prop";
const PACKAGES_LIST_PATH: &str = "/data/system/packages.list";

const PER_USER_RANGE: u32 = 100_000;
const AID_APP_START: u32 = 10_000;
const AID_APP_END: u32 = 19_999;

#[derive(Default)]
struct State {
    loaded: bool,
    config_mtime: Option<SystemTime>,
    list_mtime: Option<SystemTime>,
    unmount: bool,
    packages: HashSet<String>,
    /// App ids (uid % PER_USER_RANGE) whose every package is in the exclusion list.
    app_ids: HashSet<u32>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn mtime(path: &str) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The modification time of `config.prop`, used by the daemon to notice WebUI changes.
pub fn config_mtime() -> Option<SystemTime> {
    mtime(CONFIG_PATH)
}

fn parse_config(text: &str) -> (HashSet<String>, bool) {
    let mut packages = HashSet::new();
    let mut unmount = true;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("exclude_apps=") {
            packages = value
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect();
        } else if let Some(value) = line.strip_prefix("exclude_unmount=") {
            unmount = value.trim() != "0";
        }
    }
    (packages, unmount)
}

fn resolve_app_ids(packages: &HashSet<String>) -> HashSet<u32> {
    if packages.is_empty() {
        return HashSet::new();
    }
    let text = match fs::read_to_string(PACKAGES_LIST_PATH) {
        Ok(text) => text,
        Err(e) => {
            warn!("exclude: cannot read {}: {}", PACKAGES_LIST_PATH, e);
            return HashSet::new();
        }
    };

    // packages.list line: "<package> <uid> <debuggable> <dataDir> <seinfo> <gids>".
    // Packages sharing one uid are either all excluded or none is, so that excluding one
    // app can never silently strip modules from an unrelated one.
    let mut by_app_id: HashMap<u32, (usize, usize)> = HashMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(uid)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Ok(uid) = uid.parse::<u32>() else {
            continue;
        };
        let app_id = uid % PER_USER_RANGE;
        if !(AID_APP_START..=AID_APP_END).contains(&app_id) {
            continue;
        }
        let entry = by_app_id.entry(app_id).or_insert((0, 0));
        entry.0 += 1;
        if packages.contains(name) {
            entry.1 += 1;
        }
    }
    by_app_id
        .into_iter()
        .filter(|(_, (total, excluded))| *excluded > 0 && total == excluded)
        .map(|(app_id, _)| app_id)
        .collect()
}

fn reload(state: &mut State) {
    let config_mtime = mtime(CONFIG_PATH);
    let list_mtime = mtime(PACKAGES_LIST_PATH);
    if state.loaded && state.config_mtime == config_mtime && state.list_mtime == list_mtime {
        return;
    }

    let (packages, unmount) = match fs::read_to_string(CONFIG_PATH) {
        Ok(text) => parse_config(&text),
        Err(_) => (HashSet::new(), true),
    };
    state.app_ids = resolve_app_ids(&packages);
    state.packages = packages;
    state.unmount = unmount;
    state.config_mtime = config_mtime;
    state.list_mtime = list_mtime;
    state.loaded = true;
    debug!(
        "exclude: {} package(s), {} app id(s), unmount={}",
        state.packages.len(),
        state.app_ids.len(),
        state.unmount
    );
}

/// Re-reads the exclusion list if `config.prop` or `packages.list` changed.
pub fn refresh() {
    let mut guard = STATE.lock().unwrap();
    reload(guard.get_or_insert_with(State::default));
}

/// Returns `Some(unmount)` when `uid` belongs to an excluded user app.
pub fn lookup(uid: u32) -> Option<bool> {
    let app_id = uid % PER_USER_RANGE;
    if !(AID_APP_START..=AID_APP_END).contains(&app_id) {
        return None;
    }
    let mut guard = STATE.lock().unwrap();
    let state = guard.get_or_insert_with(State::default);
    reload(state);
    state.app_ids.contains(&app_id).then_some(state.unmount)
}
