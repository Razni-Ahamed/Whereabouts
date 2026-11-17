; Whereabouts installer hooks (NSIS), run by Tauri's installer template.
;
; The background service runs as SYSTEM and only trusts programs in
; C:\Program Files\Whereabouts, which only administrators can change. So:
; - Whereabouts installs there and nowhere else;
; - an older version's service is stopped and removed before its files are
;   replaced (saved history is kept);
; - after copying, the service is registered and started in place;
; - before uninstalling, the service is stopped and removed, the app stops
;   starting at sign-in, its blocks are
;   removed from the firewall, and the user chooses whether to delete the
;   saved history (default: keep it). When updating, blocks stay in place
;   (the new version applies the saved rules again when it starts).

!macro NSIS_HOOK_PREINSTALL
  ${If} $INSTDIR != "$PROGRAMFILES64\Whereabouts"
    MessageBox MB_ICONSTOP "Whereabouts must be installed in $PROGRAMFILES64\Whereabouts.$\r$\n$\r$\nIts background service only trusts programs in that folder, which only administrators can change." /SD IDOK
    Abort "Whereabouts must be installed in $PROGRAMFILES64\Whereabouts."
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\whereabouts-service.exe"
    DetailPrint "Stopping the running Whereabouts service (saved history is kept)..."
    nsExec::ExecToLog '"$INSTDIR\whereabouts-service.exe" --unregister'
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Registering and starting the Whereabouts service..."
  nsExec::ExecToLog '"$INSTDIR\whereabouts-service.exe" --register'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION "The Whereabouts background service could not be started (code $0).$\r$\n$\r$\nThe details are shown above. You can try again later as administrator:$\r$\n$\"$INSTDIR\whereabouts-service.exe$\" --register" /SD IDOK
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  StrCpy $1 ""
  ; Keep the history and the blocks when updating to a newer version.
  ${If} $UpdateMode <> 1
    StrCpy $1 "--remove-blocks"
    MessageBox MB_YESNO|MB_ICONQUESTION "Also delete your saved connection history?$\r$\n$\r$\nIt is kept encrypted in $COMMONPROGRAMDATA\Whereabouts. Choose No to keep it for a later reinstall." /SD IDNO IDNO +2
    StrCpy $1 "--remove-blocks --delete-data"
  ${EndIf}
  DetailPrint "Stopping and removing the Whereabouts service..."
  nsExec::ExecToLog '"$INSTDIR\whereabouts-service.exe" --unregister $1'
  Pop $0
  ${If} $UpdateMode <> 1
    ; Stop starting the app at sign-in (for the user running the uninstaller;
    ; for anyone else the entry points to a removed program and does nothing).
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Whereabouts"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "Whereabouts"
  ${EndIf}
!macroend
