; VibeTrace's installer: per user, no admin, one exe (with its licence and the third-party
; notices beside it). Built by installer\build.ps1:
;   makensis /DVERSION=0.1.0 /DVERSION4=0.1.0.0 /DEXE=<VibeTrace.exe> /DLICENSE=<LICENSE>
;            /DNOTICES=<THIRD-PARTY-NOTICES.txt> /DOUTFILE=<setup.exe> app.nsi
;
; Interactive: folder (inside the user's own profile only), install, finish (with "Run VibeTrace").
; /S /RUN    silent (an updater), then VibeTrace starts again.
; The new exe is unpacked next to the old one first and swapped in only once it is complete, so a
; failed or interrupted install leaves the old version working; with /RUN it is started again
; even then, so an update never leaves the user without the app.

Unicode true
SetCompressor /SOLID lzma
RequestExecutionLevel user
ManifestDPIAware true

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"

; build.ps1 -Sign only (/DSIGN=<sign.json> /DSIGNED_UNINSTALLER=<copy>): sign.ps1 signs the
; uninstaller before it is packed (WriteUninstaller writes that signed file) and keeps a copy for
; build.ps1's check, then signs the finished installer. Any failure fails the build.
!ifdef SIGN
  !define SIGN_WITH '"$%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${__FILEDIR__}\sign.ps1" -Config "${SIGN}"'
  !uninstfinalize '${SIGN_WITH} -File "%1" -Keep "${SIGNED_UNINSTALLER}"' = 0
  !finalize '${SIGN_WITH} -File "%1"' = 0
!endif

!define NAME "VibeTrace"
!define PUBLISHER "Ted K. Johansen"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NAME}"

Name "${NAME}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\${NAME}"
InstallDirRegKey HKCU "${UNINSTALL_KEY}" "InstallLocation"
BrandingText "${NAME} ${VERSION}"

VIProductVersion "${VERSION4}"
VIAddVersionKey "ProductName" "${NAME}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "${NAME} installer"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "LegalCopyright" "${PUBLISHER}"

!define MUI_ICON "..\assets\app.ico"
!define MUI_UNICON "..\assets\app.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${NAME}.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Run ${NAME}"
!define MUI_DIRECTORYPAGE_TEXT_TOP "Setup will install ${NAME} in the folder below. It has to be a folder inside your own user folder ($PROFILE), so no other account on this PC can change the app. For a folder anywhere else, Next stays greyed out."

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Started by an updater (/RUN): start VibeTrace, whichever version is in place.
Function RestartIfAsked
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/RUN" $R1
  ${IfNot} ${Errors}
  ${AndIf} ${FileExists} "$INSTDIR\${NAME}.exe"
    Exec '"$INSTDIR\${NAME}.exe"'
  ${EndIf}
FunctionEnd

; Only a folder inside the user's own profile, $PROFILE or $LOCALAPPDATA (review X15SIG-1): a
; folder made anywhere else, say C:\Tools\${NAME}, inherits the drive's "Authenticated Users:
; Modify", so another account on the PC could swap the exe. No ".." anywhere, so a path that
; starts in the profile can't climb out of it. $R8 is 1 when $INSTDIR is fine, else 0.
Function CheckInstDir
  StrCpy $R8 0
  StrLen $R6 $INSTDIR
  StrCpy $R5 0
  ${DoWhile} $R5 < $R6
    StrCpy $R4 $INSTDIR 2 $R5
    ${If} $R4 == ".."
      Return
    ${EndIf}
    IntOp $R5 $R5 + 1
  ${Loop}
  ${If} $PROFILE != ""
    StrLen $R5 "$PROFILE\"
    StrCpy $R4 $INSTDIR $R5
    ${If} $R4 == "$PROFILE\"
    ${AndIf} $R6 > $R5
      StrCpy $R8 1
    ${EndIf}
  ${EndIf}
  ${If} $LOCALAPPDATA != ""
    StrLen $R5 "$LOCALAPPDATA\"
    StrCpy $R4 $INSTDIR $R5
    ${If} $R4 == "$LOCALAPPDATA\"
    ${AndIf} $R6 > $R5
      StrCpy $R8 1
    ${EndIf}
  ${EndIf}
FunctionEnd

; The folder page: Next stays greyed out for a folder CheckInstDir refuses.
Function .onVerifyInstDir
  Call CheckInstDir
  ${If} $R8 != 1
    Abort
  ${EndIf}
FunctionEnd

!macro Fail code message
  Delete "$INSTDIR\${NAME}.exe.new"
  DetailPrint "${message}"
  Call RestartIfAsked
  SetErrorLevel ${code}
  Abort "${message}"
!macroend

; Rename $0 to $1, a few tries (an antivirus scan can hold a new file for a moment). Errors set
; when it never worked.
Function RenameRetry
  StrCpy $R3 0
  ${Do}
    ClearErrors
    Rename $0 $1
    ${IfNot} ${Errors}
      Return
    ${EndIf}
    IntOp $R3 $R3 + 1
    Sleep 300
  ${LoopWhile} $R3 < 10
  SetErrors
FunctionEnd

Section "Install"
  ; Again here, before anything is made: a silent install (/S, /D=, an old install's folder from
  ; the registry) never shows the folder page.
  Call CheckInstDir
  ${If} $R8 != 1
    !insertmacro Fail 5 "${NAME} installs only inside your own user folder ($PROFILE), so no other account on this PC can change it; the installed version is unchanged."
  ${EndIf}
  SetOutPath "$INSTDIR"
  SetOverwrite on

  ; Unpack in full first. A running exe can be renamed but not overwritten: the old one steps
  ; aside, the new one takes its name, and the old one goes once nothing runs it any more.
  Delete "$INSTDIR\${NAME}.exe.new"
  ClearErrors
  File "/oname=${NAME}.exe.new" "${EXE}"
  ${If} ${Errors}
    !insertmacro Fail 2 "Could not unpack ${NAME}.exe; the installed version is unchanged."
  ${EndIf}
  ; The last update's old exe may still be running (it is deleted once it is not).
  Delete "$INSTDIR\${NAME}.exe.old"
  Delete "$INSTDIR\${NAME}.exe.old2"
  StrCpy $R9 "$INSTDIR\${NAME}.exe.old"
  ${If} ${FileExists} $R9
    StrCpy $R9 "$INSTDIR\${NAME}.exe.old2"
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\${NAME}.exe"
    ${If} ${FileExists} $R9
      !insertmacro Fail 3 "Older copies of ${NAME} are still running; close them and install again. The installed version is unchanged."
    ${EndIf}
    StrCpy $0 "$INSTDIR\${NAME}.exe"
    StrCpy $1 $R9
    Call RenameRetry
    ${If} ${Errors}
      !insertmacro Fail 3 "${NAME}.exe could not be replaced; the installed version is unchanged."
    ${EndIf}
  ${EndIf}
  StrCpy $0 "$INSTDIR\${NAME}.exe.new"
  StrCpy $1 "$INSTDIR\${NAME}.exe"
  Call RenameRetry
  ${If} ${Errors}
    ; The old one back, as patiently: without it nothing restarts.
    ${If} ${FileExists} $R9
      StrCpy $0 $R9
      StrCpy $1 "$INSTDIR\${NAME}.exe"
      Call RenameRetry
      ${If} ${Errors}
        !insertmacro Fail 4 "Could not put the new ${NAME}.exe in place, nor the old one back ($R9); install again."
      ${EndIf}
    ${EndIf}
    !insertmacro Fail 4 "Could not put the new ${NAME}.exe in place; the installed version is unchanged."
  ${EndIf}
  Delete $R9 ; still running: it goes with the next install

  ; VibeTrace's licence (AGPL-3.0) and the third-party notices, next to the exe.
  File "/oname=LICENSE.txt" "${LICENSE}"
  File "/oname=THIRD-PARTY-NOTICES.txt" "${NOTICES}"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${NAME}.lnk" "$INSTDIR\${NAME}.exe"

  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${NAME}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\${NAME}.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "EstimatedSize" $0

  Call RestartIfAsked
SectionEnd

; Settings (%APPDATA%\com.tedkj.vibetrace) and local state (%LOCALAPPDATA%\com.tedkj.vibetrace)
; stay: a reinstall finds them where they were.
Section "Uninstall"
  ; Older copies first: if one still runs, nothing else has been touched yet. ($R6, not the
  ; error flag across checks: LogicLib's ${Errors} test clears it.)
  StrCpy $R6 0
  ClearErrors
  Delete "$INSTDIR\${NAME}.exe.old"
  Delete "$INSTDIR\${NAME}.exe.old2"
  IfErrors 0 +2
    StrCpy $R6 1
  ${If} $R6 == 0
    ClearErrors
    Delete "$INSTDIR\${NAME}.exe"
    IfErrors 0 +2
      StrCpy $R6 1
  ${EndIf}
  ${If} $R6 == 1
    MessageBox MB_OK|MB_ICONEXCLAMATION "${NAME} is running. Close it, then uninstall again." /SD IDOK
    SetErrorLevel 3
    Abort
  ${EndIf}
  Delete "$INSTDIR\${NAME}.exe.new"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${NAME}.lnk"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
SectionEnd
