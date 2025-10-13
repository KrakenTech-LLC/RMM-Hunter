package common

// KnownRMMDirectories contains known directory names/paths
// These will be searched in common installation locations defined in SearchBasePaths
var KnownRMMDirectories = []string{
	// A
	`Action1`,
	`Almageste\DragonDisk`,
	`AlpemixSrvc`,
	`AMMYY`,
	`AnyDesk`,
	`AnyViewer`,
	`Atera Networks`,
	`ATERA NETWORKS`,
	`ATERA NETWORKS\AteraAgent`,

	// B
	`Bitvise SSH Client`,
	`Bitvise SSH Server`,
	`Bluetrait Agent`,

	// D
	`Danware Data\NetOp Packn Deploy`,
	`DesktopCentral_Agent`,
	`DesktopCentral_Agent\bin`,

	// G
	`GoTo Opener`,
	`GoTo Machine Installer`,
	`GoToMyPC`,
	`Google\Chrome Remote Desktop`,
	`Google\Chrome\User Data\Default\Extensions\iodihamcpbpeioajjeobimgagajmlibd`,

	// I
	`Insync`,
	`Insync\App`,
	`ISL Online`,

	// K
	`Kaseya`,

	// L
	`LANDesk`,
	`Level`,
	`LiteManager Pro`,
	`LiteManager Pro – Viewer`,

	// M
	`ManageEngine\ManageEngine Free Tools`,
	`ManageEngine\ManageEngine Free Tools\Launcher`,
	`MEGAsync`,
	`Mikogo`,
	`mRemoteNG`,

	// N
	`NetSarang`,
	`NetSarang\xShell`,

	// O
	`OnionShare`,

	// P
	`PJ Technologies`,
	`PJ Technologies\GOVsrv`,

	// R
	`Radmin Viewer 3`,
	`RealVNC`,
	`RealVNC\VNC Serve`,
	`Remote Utilities`,
	`Remote Utilities\Agent`,
	`RemotePC`,
	`RustDesk`,

	// S
	`S3 Browser`,
	`ScreenConnect Client (`, // Prefix pattern for ScreenConnect Client (<string ID>)
	`SmartFTP Client`,
	`Solar-Putty-v4`,
	`SolarWinds\Dameware Mini Remote Control`,
	`Splashtop`,
	`SuperPuTTY`,
	`SyncTrayzor`,
	`Sysprogs`,
	`Sysprogs\SmarTTY`,
	`SysAidServer`,
	`SysWOW64\rserver30`,
	`SysWOW64\rserver30\FamItrfc`,
	`SysWOW64\rserver30\FamItrf2`,

	// T
	`TeamViewer`,
	`TightVNC`,
	`Total Software Deployment`,

	// U
	`UltraViewer`,
	`uvnc bvba`,
	`uvnc bvba\UltraVNC`,

	// W
	`WinSCP-5.21.6-Portable`,
	`dwrcs`,

	// X
	`Xpra`,

	// Y
	`Yandex`,

	// Z
	`ZOC8`,
}

// SearchBasePaths defines the base directories to search within
var SearchBasePaths = []string{
	`C:\Program Files`,
	`C:\Program Files (x86)`,
	`C:\ProgramData`,
	`C:\ProgramFiles`,       // Installers variant 1
	`C:\ProgramFiles (x86)`, // Installers variant 2
	`C:\Windows`,
	`{{APPDATA}}\Local`,
	`{{APPDATA}}\Roaming`,
	`{{USERPROFILE}}\Downloads`,
	`C:\Downloads`, // Standard downloads location
	`C:\`,          // Root for edge cases (AlpemixSrvc)
}
