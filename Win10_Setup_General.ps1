taskkill /f /im explorer.exe
taskkill /f /im Skype*
taskkill /f /im TextInput*
taskkill /f /im WinStore*
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name AppPrivacy -Force
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name AppPrivacy -Force
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion -Name PushNotifications -Force
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\InputPersonalization -Name RestrictImplicitInkCollection -Type DWord -Value 1
Set-ItemProperty -Path HKCU:\Software\Microsoft\InputPersonalization -Name RestrictImplicitTextCollection -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications -Name NoCloudApplicationNotification -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessContacts -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessCallHistory -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessCalendar -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessEmail -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessCamera -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessMessaging -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessRadios -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsSyncWithDevices -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessMicrophone -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessNotifications -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessAccountInfo -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsAccessTasks -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsRunInBackground -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy -Name LetAppsGetDiagnosticInfo -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary -Name Value -Type String -Value Deny
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall -Name Value -Type String -Value Deny
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary -Name Value -Type String -Value Deny
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary -Name Value -Type String -Value Deny
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess -Name Value -Type String -Value Deny
set-service AJRouter -StartupType Disabled
set-service ALG -StartupType Disabled
set-service AppIDSvc -StartupType Manual
set-service Appinfo -StartupType Manual
set-service AppReadiness -StartupType Manual
set-service AtherosSvc -StartupType Auto
set-service AudioEndpointBuilder -StartupType Auto
set-service Audiosrv -StartupType Auto
set-service autotimesvc -StartupType Disabled
set-service AxInstSV -StartupType Disabled
set-service BDESVC -StartupType Disabled
set-service BFE -StartupType Auto
set-service BITS -StartupType Manual
set-service Browser -StartupType Manual
set-service BTAGService -StartupType Disabled
set-service BthAvctpSvc -StartupType Manual
set-service bthserv -StartupType Disabled
set-service camsvc -StartupType Manual
set-service CDPSvc -StartupType Auto(Delayed)
set-service CertPropSvc -StartupType Auto
set-service COMSysApp -StartupType Manual
set-service cphs -StartupType Manual
set-service cplspcon -StartupType Auto
set-service CryptSvc -StartupType Auto
set-service defragsvc -StartupType Disabled
set-service DeviceAssociationService -StartupType Disabled
set-service DeviceInstall -StartupType Disabled
set-service DevQueryBroker -StartupType Disabled
set-service Dhcp -StartupType Auto
set-service diagnosticshub.standardcollector.service -StartupType Manual
set-service diagsvc -StartupType Disabled
set-service DiagTrack -StartupType Auto
set-service DispBrokerDesktopSvc -StartupType Auto(Delayed)
set-service DisplayEnhancementService -StartupType Disabled
set-service DmEnrollmentSvc -StartupType Disabled
set-service dmwappushservice -StartupType Disabled
set-service Dnscache -StartupType Auto
set-service DoSvc -StartupType Manual
set-service dot3svc -StartupType Manual
set-service DPS -StartupType Disabled
set-service DsmSvc -StartupType Manual
set-service DsSvc -StartupType Disabled
set-service DusmSvc -StartupType Auto
set-service Eaphost -StartupType Disabled
set-service EFS -StartupType Manual
set-service embeddedmode -StartupType Manual
set-service esifsvc -StartupType Auto
set-service EventLog -StartupType Auto
set-service EventSystem -StartupType Auto
set-service Fax -StartupType Disabled
set-service fdPHost -StartupType Disabled
set-service FDResPub -StartupType Disabled
set-service fhsvc -StartupType Disabled
set-service FontCache -StartupType Auto
set-service FrameServer -StartupType Disabled
set-service GoogleChromeElevationService -StartupType Disabled
set-service GraphicsPerfSvc -StartupType Disabled
set-service gupdate -StartupType Disabled
set-service gupdatem -StartupType Disabled
set-service hidserv -StartupType Disabled
set-service HvHost -StartupType Disabled
set-service icssvc -StartupType Disabled
set-service igccservice -StartupType Auto
set-service igfxCUIService2.0.0.0 -StartupType Auto
set-service IKEEXT -StartupType Disabled
set-service InstallService -StartupType Manual
set-service Intel(R) -StartupType Capability
set-service Intel(R) -StartupType TPM
set-service IntelAudioService -StartupType Auto
set-service iphlpsvc -StartupType Auto
set-service IpxlatCfgSvc -StartupType Manual
set-service jhi_service -StartupType Auto
set-service KeyIso -StartupType Manual
set-service Killer -StartupType Network
set-service KNDBWM -StartupType Manual
set-service KtmRm -StartupType Disabled
set-service LanmanServer -StartupType Auto
set-service LanmanWorkstation -StartupType Auto
set-service lfsvc -StartupType Disabled
set-service LicenseManager -StartupType Disabled
set-service lltdsvc -StartupType Disabled
set-service lmhosts -StartupType Manual
set-service LxpSvc -StartupType Disabled
set-service MapsBroker -StartupType Disabled
set-service MixedRealityOpenXRSvc -StartupType Disabled
set-service MozillaMaintenance -StartupType Manual
set-service MSDTC -StartupType Manual
set-service MSiSCSI -StartupType Disabled
set-service NaturalAuthentication -StartupType Disabled
set-service NcaSvc -StartupType Disabled
set-service NcbService -StartupType Manual
set-service NcdAutoSetup -StartupType Disabled
set-service Netlogon -StartupType Disabled
set-service Netman -StartupType Disabled
set-service netprofm -StartupType Manual
set-service NetSetupSvc -StartupType Manual
set-service NetTcpPortSharing -StartupType Disabled
set-service NlaSvc -StartupType Auto
set-service nsi -StartupType Auto
set-service NVDisplay.ContainerLocalSystem -StartupType Auto
set-service p2pimsvc -StartupType Disabled
set-service p2psvc -StartupType Disabled
set-service PcaSvc -StartupType Auto
set-service perceptionsimulation -StartupType Disabled
set-service PerfHost -StartupType Disabled
set-service PhoneSvc -StartupType Disabled
set-service pla -StartupType Disabled
set-service PlugPlay -StartupType Manual
set-service PNRPAutoReg -StartupType Disabled
set-service PNRPsvc -StartupType Disabled
set-service PolicyAgent -StartupType Disabled
set-service Power -StartupType Auto
set-service PrintNotify -StartupType Disabled
set-service ProfSvc -StartupType Auto
set-service PushToInstall -StartupType Disabled
set-service QcomWlanSrv -StartupType Auto
set-service QWAVE -StartupType Disabled
set-service RasAuto -StartupType Manual
set-service RasMan -StartupType Manual
set-service RemoteAccess -StartupType Disabled
set-service RemoteRegistry -StartupType Disabled
set-service RetailDemo -StartupType Disabled
set-service RmSvc -StartupType Disabled
set-service RpcLocator -StartupType Disabled
set-service RtkAudioService -StartupType Auto
set-service SamSs -StartupType Auto
set-service SCardSvr -StartupType Disabled
set-service ScDeviceEnum -StartupType Disabled
set-service SCPolicySvc -StartupType Disabled
set-service SDRSVC -StartupType Disabled
set-service seclogon -StartupType Disabled
set-service SEMgrSvc -StartupType Disabled
set-service SENS -StartupType Auto
set-service SensorDataService -StartupType Disabled
set-service SensorService -StartupType Disabled
set-service SensrSvc -StartupType Disabled
set-service SessionEnv -StartupType Disabled
set-service SgrmBroker -StartupType Auto(Delayed)
set-service SharedAccess -StartupType Disabled
set-service SharedRealitySvc -StartupType Disabled
set-service ShellHWDetection -StartupType Auto
set-service shpamsvc -StartupType Disabled
set-service smphost -StartupType Disabled
set-service SmsRouter -StartupType Disabled
set-service SNMPTRAP -StartupType Disabled
set-service spectrum -StartupType Disabled
set-service Spooler -StartupType Auto
set-service SSDPSRV -StartupType Manual
set-service ssh-agent -StartupType Disabled
set-service SstpSvc -StartupType Manual
set-service Steam -StartupType Client
set-service stisvc -StartupType Disabled
set-service StorSvc -StartupType Manual
set-service svsvc -StartupType Disabled
set-service swprv -StartupType Disabled
set-service SysMain -StartupType Auto
set-service TabletInputService -StartupType Manual
set-service TapiSrv -StartupType Manual
set-service TeamViewer -StartupType Disabled
set-service TermService -StartupType Disabled
set-service Themes -StartupType Auto
set-service TieringEngineService -StartupType Disabled
set-service TimeBrokerSvc -StartupType Manual
set-service TokenBroker -StartupType Manual
set-service TrkWks -StartupType Auto
set-service TroubleshootingSvc -StartupType Disabled
set-service TrustedInstaller -StartupType Manual
set-service tzautoupdate -StartupType Disabled
set-service UmRdpService -StartupType Disabled
set-service upnphost -StartupType Disabled
set-service UserManager -StartupType Auto
set-service VacSvc -StartupType Disabled
set-service VaultSvc -StartupType Manual
set-service vds -StartupType Manual
set-service VMAuthdService -StartupType Auto
set-service vmicguestinterface -StartupType Disabled
set-service vmicheartbeat -StartupType Disabled
set-service vmickvpexchange -StartupType Disabled
set-service vmicrdv -StartupType Disabled
set-service vmicshutdown -StartupType Disabled
set-service vmictimesync -StartupType Disabled
set-service vmicvmsession -StartupType Disabled
set-service vmicvss -StartupType Manual
set-service VMnetDHCP -StartupType Auto
set-service VMUSBArbService -StartupType Auto
set-service VMware -StartupType NAT
set-service VMwareHostd -StartupType Auto
set-service VSS -StartupType Manual
set-service W32Time -StartupType Disabled
set-service WaaSMedicSvc -StartupType Manual
set-service WalletService -StartupType Disabled
set-service WarpJITSvc -StartupType Disabled
set-service WavesSysSvc -StartupType Disabled
set-service wbengine -StartupType Disabled
set-service WbioSrvc -StartupType Disabled
set-service Wcmsvc -StartupType Auto
set-service wcncsvc -StartupType Disabled
set-service WdiServiceHost -StartupType Manual
set-service WdiSystemHost -StartupType Disabled
set-service WebClient -StartupType Disabled
set-service Wecsvc -StartupType Manual
set-service WEPHOSTSVC -StartupType Disabled
set-service wercplsupport -StartupType Disabled
set-service WerSvc -StartupType Manual
set-service WFDSConMgrSvc -StartupType Disabled
set-service WiaRpc -StartupType Disabled
set-service WindscribeService -StartupType Auto
set-service WinHttpAutoProxySvc -StartupType Manual
set-service Winmgmt -StartupType Auto
set-service WinRM -StartupType Disabled
set-service wisvc -StartupType Disabled
set-service WlanSvc -StartupType Auto
set-service wlidsvc -StartupType Manual
set-service wlpasvc -StartupType Disabled
set-service WManSvc -StartupType Disabled
set-service wmiApSrv -StartupType Disabled
set-service WMPNetworkSvc -StartupType Disabled
set-service workfolderssvc -StartupType Disabled
set-service WpcMonSvc -StartupType Disabled
set-service WPDBusEnum -StartupType Disabled
set-service WpnService -StartupType Auto
set-service wscsvc -StartupType Auto(Delayed)
set-service WSearch -StartupType Auto(Delayed)
set-service wuauserv -StartupType Auto
set-service WwanSvc -StartupType Disabled
set-service XblAuthManager -StartupType Disabled
set-service XblGameSave -StartupType Disabled
set-service XboxGipSvc -StartupType Disabled
set-service XboxNetApiSvc -StartupType Disabled
set-service AarSvc_????? -StartupType Manual
set-service BluetoothUserService_????? -StartupType Manual
set-service CaptureService_????? -StartupType Manual
set-service cbdhsvc_????? -StartupType Manual
set-service CDPUserSvc_????? -StartupType Auto
set-service ConsentUxUserSvc_????? -StartupType Manual
set-service CredentialEnrollmentManagerUserSvc_????? -StartupType Manual
set-service DeviceAssociationBrokerSvc_????? -StartupType Manual
set-service MessagingService_????? -StartupType Manual
set-service OneSyncSvc_????? -StartupType Auto
set-service UdkUserSvc_????? -StartupType Manual
Write-Output "Privacy: Let apps use my advertising ID: Disable"
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
## To Restore:
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 1
## Privacy: SmartScreen Filter for Store Apps: Disable
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0
## To Restore:
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 1
Write-Output "WiFi Sense: Shared HotSpot Auto-Connect: Disable"
	Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0
Write-Output "Activity Tracking: Disable"
	@('EnableActivityFeed','PublishUserActivities','UploadUserActivities') |% { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name $_ -Type DWord -Value 0 }
Write-Output "Start Menu: Disable Bing Search Results"
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
## To Restore (Enabled):
	# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 1
Write-Output "Disable Telemetry (requires a reboot to take effect)"
	Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
	Get-Service DiagTrack,Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled
Write-Output "Change Explorer home screen back to "This PC""
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
## Change it back to "Quick Access" (Windows 10 default)
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2
## These make "Quick Access" behave much closer to the old "Favorites"
Write-Output "Disable Quick Access: Recent Files"
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0
Write-Output "Disable Quick Access: Frequent Folders"
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 0
## To Restore:
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 1
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 1
## Disable the Lock Screen (the one before password prompt - to prevent dropping the first character)
	#If (-Not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) {
	#New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Personalization | Out-Null
	#}
	#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
## To Restore:
	#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
Write-Output "Dark Theme for Windows" # (commenting out by default because this one's probbly a minority want)
# Note: the title bar text and such is still black with low contrast, and needs additional tweaks (it'll probably be better in a future build)
	If (-Not (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize)) {
	New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes -Name Personalize | Out-Null
	}
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 0
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 0
## To Restore (Light Theme):
	#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 1
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 1
#Write-Output "Disable P2P Update downlods outside of local network"
	#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
	#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
## To restore (PCs on my local network and PCs on the internet)
	#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 3
	#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 1
## To disable P2P update downloads completely:
	#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 0
Write-Output "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
Write-Output "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
Write-Output "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
Write-Output "Disabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}
Write-Output "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
Write-Output "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
Write-Output "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
Write-Output "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
## Performance Settings / preferences:
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows -Name CheckedValue -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing -Name CheckedValue -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon -Name CheckedValue -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation -Name CheckedValue -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Type DWord -Value 1
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type DWord -Value 1
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Input\TIPC -Name Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -Type DWord -Value 0
##Setting CST Timezone
Write-Output "Set TimeZone"
	Set-TimeZone -Name "Central Standard Time"
## Windows 10 Metro App Removals
Write-Output "Remove: CandyCrush"
	Get-AppxPackage *king.com.* | Remove-AppxPackage
Write-Output " Remove: Bing Weather, News, Sports, and Finance (Money)"
	Get-AppxPackage *Bing* | Remove-AppxPackage
Write-Output "Xbox:"
	Get-AppxPackage *Xbox* | Remove-AppxPackage
Write-Output "Windows Phone Companion"
	Get-AppxPackage Microsoft.WindowsPhone | Remove-AppxPackage
Write-Output "Solitaire Collection"
	Get-AppxPackage Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage
Write-Output "People"
	Get-AppxPackage Microsoft.People | Remove-AppxPackage
Write-Output "Groove Music"
	Get-AppxPackage *Zune* | Remove-AppxPackage
Write-Output "OneNote"
	Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage
Write-Output "Photos"
	Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage
Write-Output "Sound Recorder"
	Get-AppxPackage Microsoft.WindowsSoundRecorder | Remove-AppxPackage
Write-Output "Mail & Calendar"
	Get-AppxPackage microsoft.windowscommunicationsapps | Remove-AppxPackage
Write-Output "Skype (Metro version)"
	Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
Write-Output "3DViewer"
Get-AppxPackage Microsoft.Microsoft3DViewer | Remove-AppxPackage
Write-Output "GetHelp"
Get-AppxPackage Microsoft.GetHelp | Remove-AppxPackage
Write-Output "Messaging"
Get-AppxPackage Microsoft.Messaging | Remove-AppxPackage
Write-Output "MixedReality"
Get-AppxPackage Microsoft.MixedReality.Portal | Remove-AppxPackage
Write-Output "Office"
Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage
Write-Output "WindowsFeedbackHub"
Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage
Write-Output "Wallet"
Get-AppxPackage Microsoft.Wallet | Remove-AppxPackage
Write-Output "Getstarted"
Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage
Write-Output "OneConnect"
Get-AppxPackage Microsoft.OneConnect | Remove-AppxPackage
Write-Output "YourPhone"
Get-AppxPackage Microsoft.YourPhone | Remove-AppxPackage
Write-Output "Maps"
Get-AppxPackage Microsoft.WindowsMaps | Remove-AppxPackage
Write-Output "Disabling OneDrive..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
Write-Output "Uninstalling OneDrive..."
	Stop -Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
start explorer.exe
Write-Output "Reboot, press Enter"
Write-Output "Crtl+C to cancle"
PAUSE
shutdown -r -t 2