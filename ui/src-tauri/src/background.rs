//! The app in the background (v0.2, N4): a tray icon, and a small checker
//! that turns what the service reports into Windows notifications.
//!
//! The service runs as SYSTEM and cannot show notifications to the user, so
//! the app does it. When it starts at sign-in (`--background`) it shows only
//! the tray icon; the window, with its web view, exists only while it is
//! open, so the app uses little memory in the tray.
//!
//! Notifications never name apps or sites unless the user allowed it:
//! Windows keeps a history of notifications and may show them on the lock
//! screen.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewWindowBuilder, Wry};
use tauri_plugin_notification::NotificationExt;
use whereabouts_client::{Client, Problem, unexpected};
use whereabouts_core::text::display_safe;
use whereabouts_ipc::{NoticeKind, PIPE_NAME, Request, Response, Status};

use crate::settings::AppState;

/// How often the checker asks the service.
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// How long the service must be unreachable before the user is told.
const DOWN_AFTER: Duration = Duration::from_secs(20);
/// How long blocking may stay paused before a reminder.
const PAUSED_REMINDER: Duration = Duration::from_secs(60 * 60);
/// At most one "new app" notification this often; more are grouped.
const NEW_APPS_EVERY: Duration = Duration::from_secs(60);

/// The tray menu's pause item, kept to update its text.
pub struct TrayMenu {
    pause: MenuItem<Wry>,
}

/// What the checker last learned, shared with the tray menu.
#[derive(Debug, Default)]
pub struct Watched {
    /// Whether blocking is paused, when known.
    pub paused: Option<bool>,
}

/// Opens the main window, or brings it to the front.
pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    let Some(config) = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .cloned()
    else {
        return;
    };
    match WebviewWindowBuilder::from_config(app, &config).and_then(|builder| builder.build()) {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(error) => eprintln!("could not open the window: {error}"),
    }
}

/// Adds the tray icon and its menu.
pub fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Whereabouts", true, None::<&str>)?;
    let pause = MenuItem::with_id(app, "pause", "Pause blocking", false, None::<&str>)?;
    let close = MenuItem::with_id(
        app,
        "close",
        "Close the app (Whereabouts keeps watching)",
        true,
        None::<&str>,
    )?;
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &PredefinedMenuItem::separator(app)?,
            &pause,
            &PredefinedMenuItem::separator(app)?,
            &close,
        ],
    )?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Whereabouts")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "pause" => toggle_pause(app),
            "close" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    app.manage(TrayMenu { pause });
    app.manage(Mutex::new(Watched::default()));
    Ok(())
}

/// Pauses or resumes blocking from the tray menu (off the UI thread).
fn toggle_pause(app: &AppHandle) {
    let paused = app
        .state::<Mutex<Watched>>()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .paused;
    let Some(paused) = paused else {
        return;
    };
    let app = app.clone();
    std::thread::spawn(move || {
        let result = Client::connect(PIPE_NAME).and_then(|mut client| {
            match client.ask(&Request::SetBlockingPaused { paused: !paused })? {
                Response::Rules { paused, .. } => Ok(paused),
                other => Err(unexpected(&other)),
            }
        });
        match result {
            Ok(now_paused) => {
                app.state::<Mutex<Watched>>()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .paused = Some(now_paused);
                set_pause_item(&app, Some(now_paused), true);
            }
            Err(problem) => notify(&app, "Could not change blocking", &problem.message),
        }
    });
}

fn set_pause_item(app: &AppHandle, paused: Option<bool>, has_rules: bool) {
    let menu = app.state::<TrayMenu>();
    let _ = menu.pause.set_text(if paused == Some(true) {
        "Resume blocking"
    } else {
        "Pause blocking"
    });
    let _ = menu.pause.set_enabled(paused.is_some() && has_rules);
}

fn set_tooltip(app: &AppHandle, text: &str) {
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(text));
    }
}

/// Shows a Windows notification, if the user has not turned them off.
pub fn notify(app: &AppHandle, title: &str, body: &str) {
    let on = app
        .state::<AppState>()
        .settings
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .notifications;
    if !on {
        return;
    }
    if let Err(error) = app.notification().builder().title(title).body(body).show() {
        eprintln!("could not show a notification: {error}");
    }
}

/// What the checker remembers between checks.
#[derive(Debug, Default)]
struct Checker {
    client: Option<Client>,
    /// When the service was first found unreachable, and whether the user
    /// was told.
    down_since: Option<Instant>,
    told_down: bool,
    /// When blocking was first seen paused, and whether the user was
    /// reminded.
    paused_since: Option<Instant>,
    told_paused: bool,
    /// The newest notice already handled; `None` until the first answer
    /// (notices from before the app started are not shown).
    last_notice: Option<u64>,
    /// New apps waiting to be announced, and when the last announcement was.
    new_apps: Vec<String>,
    last_new_apps: Option<Instant>,
}

/// What one check learned.
struct Snapshot {
    status: Status,
    new_apps: Vec<String>,
    last_notice: u64,
}

/// Starts the background checker.
pub fn start_checker(app: AppHandle) {
    let spawned = std::thread::Builder::new()
        .name(String::from("whereabouts-checker"))
        .spawn(move || {
            let mut checker = Checker::default();
            loop {
                checker.check(&app, Instant::now());
                std::thread::sleep(CHECK_EVERY);
            }
        });
    if let Err(error) = spawned {
        eprintln!("could not start the background checker: {error}");
    }
}

impl Checker {
    fn ask(&mut self) -> Result<Snapshot, Problem> {
        let client = match self.client.as_mut() {
            Some(client) => client,
            None => self.client.insert(Client::connect(PIPE_NAME)?),
        };
        let status = match client.ask(&Request::Status {})? {
            Response::Status(status) => status,
            other => return Err(unexpected(&other)),
        };
        // The first time, only the newest ID is wanted.
        let after = self.last_notice.unwrap_or(u64::MAX);
        let (notices, last_notice) = match client.ask(&Request::Notices { after })? {
            Response::Notices { notices, last } => (notices, last),
            other => return Err(unexpected(&other)),
        };
        let new_apps = notices
            .into_iter()
            .map(|notice| match notice.kind {
                NoticeKind::NewApp { app, .. } => display_safe(&app),
            })
            .collect();
        Ok(Snapshot {
            status,
            new_apps,
            last_notice,
        })
    }

    fn check(&mut self, app: &AppHandle, now: Instant) {
        match self.ask() {
            Ok(snapshot) => self.reachable(app, snapshot, now),
            Err(_) => {
                self.client = None;
                self.unreachable(app, now);
            }
        }
    }

    fn unreachable(&mut self, app: &AppHandle, now: Instant) {
        let since = *self.down_since.get_or_insert(now);
        set_tooltip(app, "Whereabouts · not connected to its service");
        set_pause_item(app, None, false);
        app.state::<Mutex<Watched>>()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .paused = None;
        if !self.told_down && now.duration_since(since) >= DOWN_AFTER {
            self.told_down = true;
            notify(
                app,
                "Whereabouts stopped watching",
                "Its background service isn't answering, so new connections aren't being \
                 recorded. Blocks already in place stay.",
            );
        }
    }

    fn reachable(&mut self, app: &AppHandle, snapshot: Snapshot, now: Instant) {
        if self.told_down {
            notify(
                app,
                "Whereabouts is watching again",
                "Its background service is back.",
            );
        }
        self.down_since = None;
        self.told_down = false;

        let status = &snapshot.status;
        let rules = status.block_rules;
        let paused = status.blocking_paused && rules > 0;
        app.state::<Mutex<Watched>>()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .paused = Some(status.blocking_paused);
        set_pause_item(app, Some(status.blocking_paused), rules > 0);
        set_tooltip(
            app,
            if paused {
                "Whereabouts · watching · blocking paused"
            } else {
                "Whereabouts · watching"
            },
        );
        if paused {
            let since = *self.paused_since.get_or_insert(now);
            if !self.told_paused && now.duration_since(since) >= PAUSED_REMINDER {
                self.told_paused = true;
                notify(
                    app,
                    "Blocking is still paused",
                    &format!(
                        "Your {rules} blocking {} haven't blocked anything for an hour. Resume \
                         from the tray icon or the Rules screen.",
                        if rules == 1 { "rule" } else { "rules" }
                    ),
                );
            }
        } else {
            self.paused_since = None;
            self.told_paused = false;
        }

        // Only notices that arrive while the app runs are announced.
        if self.last_notice.is_some() {
            self.new_apps.extend(snapshot.new_apps);
        }
        self.last_notice = Some(snapshot.last_notice);
        let due = self
            .last_new_apps
            .is_none_or(|last| now.duration_since(last) >= NEW_APPS_EVERY);
        if !self.new_apps.is_empty() && due {
            let show_names = app
                .state::<AppState>()
                .settings
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .show_names;
            let (title, body) = new_apps_text(&self.new_apps, show_names);
            notify(app, &title, &body);
            self.new_apps.clear();
            self.last_new_apps = Some(now);
        }
    }
}

/// The notification for new apps: without names unless allowed.
fn new_apps_text(apps: &[String], show_names: bool) -> (String, String) {
    let more = "Open Whereabouts to see where it connects; you can block it there.";
    match (apps, show_names) {
        ([app], true) => (
            format!("{app} used the internet for the first time"),
            String::from(more),
        ),
        ([_], false) => (
            String::from("A new app used the internet"),
            String::from(
                "An app connected to the internet for the first time. Open Whereabouts to see \
                 which.",
            ),
        ),
        (apps, true) => (
            format!("{} new apps used the internet", apps.len()),
            format!(
                "{} connected for the first time. Open Whereabouts to see where they connect.",
                list(apps)
            ),
        ),
        (apps, false) => (
            format!("{} new apps used the internet", apps.len()),
            String::from(
                "Some apps connected to the internet for the first time. Open Whereabouts to \
                 see which.",
            ),
        ),
    }
}

/// "a, b and 3 more".
fn list(apps: &[String]) -> String {
    match apps {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [a, b, rest @ ..] => format!("{a}, {b} and {} more", rest.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn notifications_name_nothing_unless_allowed() {
        for list in [
            apps(&["chat.exe"]),
            apps(&["chat.exe", "game.exe", "x.exe"]),
        ] {
            let (title, body) = new_apps_text(&list, false);
            for name in &list {
                assert!(!title.contains(name.as_str()) && !body.contains(name.as_str()));
            }
        }
        let (title, _) = new_apps_text(&apps(&["chat.exe"]), true);
        assert_eq!(title, "chat.exe used the internet for the first time");
        let (title, body) = new_apps_text(&apps(&["a.exe", "b.exe", "c.exe", "d.exe"]), true);
        assert_eq!(title, "4 new apps used the internet");
        assert!(body.starts_with("a.exe, b.exe and 2 more"), "{body}");
    }
}
