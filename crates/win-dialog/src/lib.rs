//! Native Windows confirmation dialogs whose **safe** answer is the default.
//!
//! The app's other dialogs come from Tauri's dialog plugin, which always
//! makes the first button (the action) the default, so pressing Enter in
//! "Delete everything Whereabouts saved?" deleted everything. For actions
//! that cannot be undone, or that silence a security warning, this asks with
//! Windows' task dialog instead: **Cancel** is the default button, and
//! Escape or closing the window also mean Cancel.
//!
//! `unsafe` is used only for the one Windows call; it has a `// SAFETY:`
//! comment.

#![allow(unsafe_code)]

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TD_WARNING_ICON,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_POSITION_RELATIVE_TO_WINDOW, TDF_SIZE_TO_CONTENT,
    TaskDialogIndirect,
};
use windows::core::PCWSTR;

/// Button IDs of our own. Windows' common IDs (IDOK..IDCONTINUE) are 1..11,
/// and Escape or closing the dialog give IDCANCEL (2), never `ACTION`.
const ACTION: i32 = 1000;
const CANCEL: i32 = 1001;
const _: () = assert!(ACTION > 100 && CANCEL > 100 && ACTION != CANCEL);

/// A UTF-16 string with a terminating null.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Asks `text` with a warning icon and two buttons, `action` and "Cancel",
/// where Cancel is the default. `owner` is the window the dialog belongs to
/// (its raw handle), if any. Returns `true` only if the user chose `action`;
/// closing the dialog, Escape, Enter on the default button, or a failure to
/// show it all return `false`.
pub fn confirm(owner: Option<isize>, title: &str, text: &str, action: &str) -> bool {
    let (title, text, action, cancel) = (wide(title), wide(text), wide(action), wide("Cancel"));
    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: ACTION,
            pszButtonText: PCWSTR(action.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: CANCEL,
            pszButtonText: PCWSTR(cancel.as_ptr()),
        },
    ];
    let mut flags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
    if owner.is_some() {
        flags |= TDF_POSITION_RELATIVE_TO_WINDOW;
    }
    let config = TASKDIALOGCONFIG {
        cbSize: u32::try_from(std::mem::size_of::<TASKDIALOGCONFIG>()).unwrap_or(0),
        hwndParent: HWND(owner.unwrap_or(0) as *mut core::ffi::c_void),
        dwFlags: flags,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        Anonymous1: TASKDIALOGCONFIG_0 {
            pszMainIcon: TD_WARNING_ICON,
        },
        pszContent: PCWSTR(text.as_ptr()),
        cButtons: u32::try_from(buttons.len()).unwrap_or(0),
        pButtons: buttons.as_ptr(),
        nDefaultButton: CANCEL,
        ..Default::default()
    };
    let mut chosen = 0i32;
    // SAFETY: `config` and every string and button it points to live until
    // the call returns; `chosen` is a valid out-pointer. The dialog is modal
    // and returns when the user answers.
    let shown = unsafe { TaskDialogIndirect(&config, Some(&mut chosen), None, None) };
    shown.is_ok() && chosen == ACTION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_end_in_a_null() {
        assert_eq!(wide("ab"), vec![u16::from(b'a'), u16::from(b'b'), 0]);
        assert_eq!(wide(""), vec![0]);
    }
}
