//! Hand-rolled i18n: compile-time key safety, additive locales.
//!
//! Every translatable string is one variant of [`Key`]. [`t`] matches on
//! [`Key`] exhaustively per locale, so a key forgotten in any locale table is
//! a COMPILE error, never a runtime miss. Adding a locale is purely additive:
//! one variant on `crate::model::settings::Language` + one table module + one
//! match arm in [`t`] — zero call-site changes.
//!
//! English is the fallback locale: `Language`'s serde maps any unknown or
//! absent tag to `Language::En` (see `src/model/settings.rs`), and `En` is the
//! only pack that ships today.
//!
//! # Text standard
//!
//! Every string in this file is user-visible text, and text is maintained
//! like code. The writing rules are the flavored adaptation of ASD-STE100
//! (Simplified Technical English, Issue 9) for UI copy:
//!
//! - One idea per sentence. A sentence that starts with an imperative verb
//!   is an instruction and has at most 20 words; any other sentence has at
//!   most 25.
//! - Active voice. Name the actor: "The app writes the file."
//! - Simple tenses only: infinitive, imperative, simple present, simple
//!   past, simple future, past participle as an adjective. A compound form
//!   is allowed only where it carries current relevance ("The core has
//!   stopped") and counts as a recorded exception.
//! - No semicolons. Write two sentences.
//! - No contractions.
//! - At most three nouns in a noun cluster ("server certificate pin").
//! - Use the verb, not the action-noun: "analyze the log", not "perform an
//!   analysis of the log".
//! - No marketing adjectives ("seamless", "robust") and no two-word verbs
//!   where one verb does the work ("spin up" → "start").
//! - Keep every fact, number, unit, condition, and hedge. "may have
//!   failed" is not "failed". When a rule and the precision of the original
//!   text conflict, keep the precise text and record the exception
//!   together with its reason.
//! - `…` marks a control that opens a dialog ("Import ZIP…") or an operation
//!   in progress ("Starting…"), and nothing else.
//! - Placeholders keep their order and their count.
//!
//! One word per meaning is a preference here, not a rule: choose the term
//! from the table below, and add a ruling whenever a new string has to
//! choose between words. Text the app does not author — core output,
//! captured diagnostics, the QUIC transcript — is passthrough: show it
//! verbatim, and write nothing that looks like it.
//!
//! # Adding a string
//!
//! 1. Add one [`Key`] variant.
//! 2. Add its English arm in `mod en`. The match is exhaustive, so a
//!    forgotten arm is a compile error.
//! 3. Use `{}` placeholders for the values, in order; [`t_fmt`] fills them.
//! 4. Never splice one sentence out of two [`t`] results. Every combination
//!    gets its own key, so a translation never inherits English word order.
//!
//! # Terminology
//!
//! One term per concept, spelled and capitalized as written here. These are
//! technical names: keep them, and do not rotate synonyms.
//!
//! | term | what it names | do not write |
//! |---|---|---|
//! | broccoli | the app's own name, always lowercase; prose names the actor as "the app" | Broccoli |
//! | core | the running Xray process | xray process, daemon |
//! | Xray core | the installed product and its release; the hyphen stays only in file and URL names | xray core, Xray-core (in prose) |
//! | server | one saved server profile the user picks and connects through | node, config entry |
//! | active server | the server the generated configuration routes to by default | default server, main server |
//! | TUN, Off | the two network modes | tunnel mode, proxy mode |
//! | Connect, Disconnect | the lifecycle actions on the core | start, stop, turn on |
//! | Apply | commit pending configuration to the running core | deploy, commit |
//! | Save, Discard | commit or drop server-editor edits | submit, revert |
//! | Remove | take an item out of a list (row, rule, header, listener) | delete |
//! | Delete | destroy a saved server | remove |
//! | Test latency | the button that starts an on-demand latency probe; prose calls the action a latency test | probe test |
//! | Ping test | the Settings group that configures that probe | — |
//!
//! The full form "server profile" is allowed where a sentence needs it; bare
//! "profile" alone never names a server. The certificate-pin buttons say
//! "Apply to server": installing a pin is not the configuration action, and
//! the phrase stays.

use crate::model::safety::{HazardClass, SafetyCode, SafetyFinding};
use crate::model::settings::Language;
use crate::model::stream::Network;
use crate::model::validation::{ValidationCode, ValidationIssue};

/// Declares [`Key`] and [`ALL`] from one variant list, so the enum and the
/// list cannot drift apart.
macro_rules! keys {
    ( $( $(#[$meta:meta])* $variant:ident ),* $(,)? ) => {
        /// Every user-facing string in the UI, listed once here. Removing a key (or
        /// adding one without updating every locale table) fails to compile.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Key {
            $( $(#[$meta])* $variant, )*
        }

        /// Every key in declaration order, generated from the same list as
        /// [`Key`], so the two cannot drift.
        pub const ALL: &[Key] = &[ $( Key::$variant, )* ];
    };
}

keys! {
    Language,
    LanguageEnglish,
    Theme,
    ThemeSystem,
    ThemeSystemHint,
    ThemeDark,
    ThemeDarkHint,
    ThemeLight,
    ThemeLightHint,
    AccentColor,
    AccentColorReset,
    AccentColorResetHint,
    AccentColorHint,
    // Shared copy used by several screens.
    Servers,
    Preview,
    Tun,
    Off,
    Close,
    Cancel,
    Delete,
    DeleteServer,
    CopyLink,
    Generate,
    Remove,
    Enabled,
    UserLevel,
    PortLower,
    AddressLower,
    Ips,
    ValueLower,
    HeaderHint,
    ValueHint,
    EmDash,
    DeleteRow,
    ProbeRow,
    AddRow,
    AddKvRow,
    InvalidJson,
    RuntimeChannelClosed,
    WorkerExitedWithoutResult,
    InvalidGoDuration,
    InvalidGoDurationShort,
    WaitingForXray,
    WaitingForXrayEllipsis,
    OperationInProgress,
    LatencyMs,
    Dead,
    LatencyTimeout,
    NotInstalled,
    // Screen labels (nav sidebar + headings).
    ScreenDashboard,
    ScreenServers,
    ScreenProfilePreview,
    ScreenRouting,
    ScreenDns,
    ScreenInbounds,
    ScreenLogs,
    ScreenSettings,
    ScreenAbout,
    ScreenTun,
    // Phase action labels (top bar, dashboard, tray).
    PhaseConnect,
    PhaseDisconnect,
    PhaseCancelRetry,
    // Core-setup shared surface (Settings → Updates, first-run wizard).
    CoreSetupDownloading,
    CoreSetupFailed,
    CoreSetupInstalled,
    CoreSetupNotInstalled,
    CoreSetupFirstUseHint,
    CoreSetupXrayCore,
    CoreSetupPinnedRelease,
    CoreSetupOpenReleaseHint,
    CoreSetupArchiveSep,
    CoreSetupCopyLink,
    CoreSetupStopFirst,
    CoreSetupBusy,
    CoreSetupDownloadButton,
    CoreSetupImportZip,
    CoreSetupHint,
    CoreSetupProgress,
    CoreSetupInstalledVersion,
    CoreSetupHealthCheck,
    CoreSetupContinue,
    CoreSetupContinueDisabled,
    CoreSetupFailedError,
    CoreSetupSetUpLater,
    CoreSetupLaterDisabled,
    LatencyRequiresProfile,
    LatencyCoreUnavailable,
    LatencyFeedbackComplete,
    LatencyFeedbackPartial,
    LatencyFeedbackFailed,
    LatencyProbeOneResponded,
    LatencyProbeOneDead,
    LatencyProbeOneFailed,
    LatencyProbeOneDeadReason,
    LatencyProbeOneDeadAt,
    LatencyProbeOneDeadAtReason,
    LatencyFeedbackPartialWarn,
    // App shell: phase badge, mode label, top-bar status strip, tray.
    AppPhaseStopped,
    AppPhaseNoConfig,
    AppPhaseStarting,
    AppPhaseRunning,
    AppPhaseRetrying,
    AppPhaseError,
    ModeOff,
    ModeTun,
    TrayShow,
    TrayConnectDisconnect,
    TrayQuit,
    TrayTooltipStopped,
    TopbarMode,
    TopbarActiveServer,
    TopbarCoreNotInstalled,
    TopbarChangesPending,
    TopbarServerEditsUnsaved,
    TopbarApplyNow,
    ApplyResultOk,
    ApplyResultFailed,
    TopbarConfigInvalid,
    TopbarSettingsNotSaved,
    TopbarRetrySave,
    TopbarOpenStateFolder,
    // Topbar right edge: xray core + broccoli app versions.
    TopbarXrayAppVersions,
    TopbarAppVersion,
    TopbarStateLoadFailed,
    AppOperationInProgress,
    LogCoreError,
    LogConnectBlocked,
    LogDisconnectBlocked,
    LogBroccoliMessage,
    LogOpenStateFolderFailed,
    CreateProfileDirsFailed,
    SaveServersFailed,
    SaveSettingsFailed,
    ApplyResultUnsaved,
    ApplyResultOlder,
    RollbackRestored,
    RollbackFailed,
    ConnectBlockedSave,
    ConnectBlockedRawMode,
    ConnectBlockedInstallCore,
    ConnectBlockedOperation,
    GenerationFailed,
    CoreRuntimeUnavailable,
    StateFileLoadFailed,
    ApplyBlockedNotSaved,
    ApplyBlockedOperation,
    RawOverrideOffMode,
    RawOverrideDefineApi,
    RawOverrideStatsService,
    RawOverrideNoTun,
    // Tray tooltip (icon presentation).
    IconTooltipError,
    IconTooltipCoreRunning,
    IconTooltipTun,
    // First-run wizard.
    WizardWelcome,
    WizardCoreMissing,
    // About screen.
    AboutBroccoliVersion,
    AboutTagline,
    AboutCoreVersion,
    AboutCoreNotInstalled,
    AboutUpstreamLink,
    AboutRepoLink,
    AboutLicenses,
    AboutLicenseXray,
    AboutLicenseWintun,
    AboutLicenseTexts,
    AboutBuiltWith,
    // TUN screen.
    TunBadgeElevated,
    TunBadgeNotElevated,
    TunBadgeHelperActive,
    TunExplain,
    TunDnsListenerNote,
    TunEnableCheckbox,
    TunRestartHint,
    TunSectionIdentity,
    TunIfaceNameLabel,
    TunDescLabel,
    TunMtuLabel,
    TunSectionGateways,
    TunGatewaysLabel,
    TunSectionAutoRoutes,
    TunAutoRoutingTableLabel,
    TunAutoOutboundsLabel,
    TunAutoOutboundsHint,
    TunAutoOutboundsDown,
    TunAutoOutboundsMissing,
    TunSectionIfaces,
    // Dashboard screen.
    DashboardNetworkMode,
    DashboardLocalEndpoints,
    DashboardEndpointHint,
    LocalStatusUp,
    LocalStatusDown,
    LocalStatusDisabled,
    LocalStatusStarting,
    TunStatusActive,
    TunStatusElevation,
    TunStatusOff,
    EndpointRow,
    TunStatus,
    DashboardTunHoverElevated,
    DashboardTunHoverNotElevated,
    DashboardActiveServer,
    NoneSelected,
    DashboardRateUp,
    DashboardRateDown,
    DashboardUptime,
    DashboardGoroutines,
    DashboardNoStatsStarting,
    DashboardNoStatsRunning,
    DashboardNoStatsStopped,
    DashboardNoStatsNoConfig,
    DashboardNoStatsBackoff,
    DashboardNoStatsError,
    DashboardPlotSecondsAgo,
    DashboardPlotBytesPerSec,
    PlotUp,
    PlotDown,
    DashboardNoServers,
    GridName,
    GridTag,
    GridLatency,
    GridDetail,
    HealthPingSummary,
    DashboardDownloadProgress,
    DashboardDownloadFailed,
    ConnectUnavailable,
    DashboardPhaseStopped,
    DashboardPhaseNoConfig,
    DashboardPhaseStarting,
    DashboardPhaseRunning,
    DashboardPhaseRetry,
    DashboardPhaseError,
    // Logs screen.
    LogsLevelAll,
    LogsLevelInfoPlus,
    LogsLevelWarningPlus,
    LogsLevelErrorPlus,
    LogsLevelLabel,
    LogsFilterLabel,
    LogsFilterHint,
    LogsAutoscroll,
    LogsCopyAll,
    LogsCopySelection,
    LogsClearView,
    LogsClearViewHint,
    LogsOpenFolder,
    LogsOpenFolderFailed,
    LogsRestartLogger,
    LogsRestartLoggerHint,
    LogsRestartDisabledNotRunning,
    LogsRestartDisabledBusy,
    LogsRestarting,
    LogsLineCount,
    LogsRestartFeedbackOk,
    // Profile preview screen.
    PreviewNoLaunch,
    PreviewCredentialsWarning,
    PreviewActiveConfig,
    PreviewLoadFailed,
    PreviewPhaseStarting,
    PreviewPhaseRunning,
    PreviewPhaseBackoff,
    PreviewPhaseNoConfig,
    PreviewPhaseStopped,
    // DNS screen.
    DnsSectionServers,
    DnsPriorityHint,
    DnsMoveUp,
    DnsMoveDown,
    DnsNoAddress,
    DnsDomainsCount,
    DnsEditServer,
    DnsAddServer,
    DnsSectionHosts,
    DnsHostsKeyHint,
    DnsHostsValueHint,
    DnsSectionGlobal,
    DnsClientIp,
    DnsClientIpHint,
    DnsBootstrapLabel,
    DnsBootstrapHint,
    DnsTag,
    DnsTagHint,
    DnsQueryStrategy,
    DnsDisableCache,
    DnsDisableFallback,
    DnsDisableFallbackIfMatched,
    DnsSkipFallbackHint,
    DnsServeStale,
    DnsServeStaleHint,
    DnsParallelQueries,
    DnsUseSystemHosts,
    DnsServeExpiredTtl,
    DnsSectionFakedns,
    DnsEnableFakedns,
    DnsFakednsExplain,
    DnsPoolTitle,
    DnsIpPool,
    DnsPoolCidrRequired,
    DnsPoolCidrInvalid,
    DnsPoolSize,
    DnsAddPool,
    DnsAddress,
    DnsAddressHint,
    DnsAddressRequired,
    DnsPort,
    DnsDomains,
    DnsDomainsHint,
    DnsExpectedIps,
    DnsExpectedIpsHint,
    DnsUnexpectedIps,
    DnsUnexpectedIpsHint,
    DnsClientIpOverride,
    DnsTagOutbound,
    DnsSkipFallback,
    DnsFinalQuery,
    DnsTimeoutRequired,
    DnsTimeoutInteger,
    DnsTimeoutRange,
    DnsTimeoutMs,
    DnsTimeoutHint,
    DnsTimeoutDefault,
    DnsSchemeDefault,
    Inherit,
    BoolFalse,
    BoolTrue,
    // Inbounds screen.
    InboundsPostureWarn,
    InboundsListenAddress,
    InboundsUdpSupport,
    InboundsUdpRelayIp,
    InboundsUdpRelayIpHint,
    InboundsUdpWildcardHint,
    InboundsRequireAuth,
    // Password-mode HTTP with zero accounts ("require authentication"
    // ticked, empty list): the row error text shared with the apply gate —
    // the model code `LocalInboundAuthRequiresAccounts` renders exactly this
    // English text.
    InboundsAuthRequiresAccounts,
    InboundsSectionDokodemo,
    InboundsStableTagHint,
    InboundsDeleteDokodemo,
    InboundsUsedByRules,
    InboundsDeleteBlocked,
    InboundsUnixPath,
    InboundsUnixHint,
    InboundsListenPort,
    InboundsImportedHint,
    InboundsTargetAddress,
    InboundsTargetAddressHint,
    InboundsTargetPort,
    InboundsPortMap,
    InboundsAddPortMapping,
    InboundsAddDokodemo,
    InboundsListener,
    InboundsModeTcp,
    InboundsModeUdp,
    InboundsModeTcpUdp,
    InboundsPreserveImported,
    InboundsPreserveImportedHint,
    InboundsImportedUnsupported,
    ListenerLabelSocks,
    ListenerLabelHttp,
    ListenerLabelDokodemo,
    // Local listeners list: user-managed SOCKS/HTTP endpoints.
    LocalListeners,
    AddSocks,
    AddHttp,
    RemoveEndpoint,
    EndpointProtocolSocks,
    EndpointProtocolHttp,
    EmptyLocalListeners,
    // Safety warnings (hazard taxonomy).
    SafetySocksListenerExposed,
    SafetyHttpListenerExposed,
    SafetyDokodemoListenerExposed,
    SafetyTunDnsUnprotected,
    SafetyBalancerSelectorNoMatch,
    HazardClassExposure,
    HazardClassPrivacy,
    HazardClassBreakage,
    // Apply-gate hazard acknowledgment dialog.
    SafetyAckTitle,
    SafetyAckExplanation,
    SafetyAckApplyAnyway,
    CollisionInvalidNetwork,
    CollisionNeedsPort,
    CollisionNeedsUnix,
    CollisionEndpoint,
    CollisionConflict,
    DokodemoTagMissing,
    DokodemoTagBuiltin,
    DokodemoTagDuplicate,
    Accounts,
    AccountUserHint,
    AccountPasswordHint,
    AddAccount,
    SniffingSection,
    SniffingDestOverride,
    SniffingFakednsHint,
    SniffingDomainsExcluded,
    SniffingIpsExcluded,
    SniffingMetadataOnly,
    SniffingRouteOnly,
    // Routing screen.
    GeodataAddGeosite,
    GeodataAddGeoip,
    RoutingRulesSection,
    RoutingMoveUp,
    RoutingMoveDown,
    RoutingDeleteRule,
    RoutingEditRule,
    RoutingNoTarget,
    RoutingTargetArrow,
    RoutingNoRules,
    RoutingAddRule,
    RuleTag,
    RuleTagHint,
    Network,
    Domains,
    DomainsHint,
    IpsHint,
    Port,
    PortHint,
    SourcePort,
    SourcePortHint,
    LocalPort,
    LocalPortHint,
    RoutingPortListInvalid,
    RoutingIpListInvalid,
    InboundTags,
    InboundTagsHint,
    SourceIps,
    SourceIpsHint,
    LocalIps,
    LocalIpsHint,
    Protocols,
    ProtocolsHint,
    Processes,
    ProcessesHint,
    LocalOs,
    LocalOsHint,
    VlessRoute,
    VlessRouteHint,
    Attrs,
    AttrsKeyHint,
    AttrsValueHint,
    WebhookOnMatch,
    WebhookOnMatchHint,
    Url,
    UrlHint,
    Deduplication,
    Headers,
    HeadersKeyHint,
    HeadersValueHint,
    Target,
    Outbound,
    Balancer,
    BalancerNeededHint,
    NoBalancers,
    UseDirect,
    GeodataLoaderFailed,
    GeodataLoaderStopped,
    GeodataLoading,
    GeodataRefresh,
    GeodataRefreshBusy,
    GeodataReading,
    GeodataCodesBytes,
    GeodataModified,
    GeodataModifiedUnavailable,
    GeodataSearch,
    GeodataNoMatches,
    RuntimeStateRefreshed,
    RuntimeOverrideTitle,
    RuntimeOverrideEphemeral,
    RuntimeOverrideScopeHint,
    CurrentOverride,
    CurrentOverrideNone,
    PrincipleTargets,
    PrincipleTargetsNone,
    PrincipleTargetsHidden,
    RuntimeStateNotRefreshed,
    CoreNotRunningControls,
    RefreshRuntimeState,
    KnownOutbound,
    CustomExactTag,
    ExactOutboundTag,
    ApplyTarget,
    ApplyTargetDisabledEmpty,
    ApplyTargetDisabledBusy,
    ClearOverride,
    BalancersSection,
    Untagged,
    BalancerStrategy,
    BalancerSelector,
    DeleteBalancer,
    BalancerUsedBy,
    EditBalancer,
    BalancerDeleteBlocked,
    AddBalancer,
    AddBalancerDisabled,
    Tag,
    BalancerNameHint,
    TagRequired,
    TagDuplicate,
    SetTag,
    RenameUpdateRules,
    TagUniqueHint,
    Selectors,
    SelectorsHint,
    SelectorRequired,
    SelectAllServers,
    StrategyLabel,
    RequiresObservatory,
    Fallback,
    Costs,
    MatchRegexpHint,
    Match,
    MatchHint,
    Weight,
    AddCost,
    Baselines,
    BaselinesHint,
    MaxRtt,
    InvalidGoDurationExample,
    ExpectedNodes,
    ExpectedSpeedMode,
    Tolerance,
    Auto,
    ObservabilitySection,
    DomainStrategy,
    ObservatoryLatencyProbing,
    ObservatoryEmitted,
    ObservatoryForcedByBalancer,
    BurstObservatoryHint,
    BurstObservatoryGated,
    HealthEngineConflict,
    ProbeInterval,
    ProbeIntervalHint,
    ProbeIntervalHint2,
    SubjectSelectors,
    SubjectSelectorsHint,
    ProbeUrl,
    EnableConcurrency,
    BurstObservatory,
    Destination,
    ConnectivityCheck,
    ConnectivityCheckHint,
    Interval,
    IntervalHint,
    Sampling,
    Timeout,
    TimeoutHint,
    HttpMethod,
    TestRoute,
    TestRouteWindow,
    TestRouteExplain,
    TestTargetHeading,
    TestDomain,
    TestDomainHint,
    TestTargetIps,
    TestTargetIpsHint,
    TestTargetPort,
    TestSourceHeading,
    TestSourceIps,
    TestSourceIpsHint,
    TestSourcePort,
    TestLocalIps,
    TestLocalIpsHint,
    TestLocalPort,
    TestInboundTag,
    TestVlessRoute,
    TestProcessNote,
    TestDetectedProtocol,
    TestNetwork,
    TestProtocol,
    TestProtocolHint,
    TestAttributes,
    TestAttrKeyHint,
    TestAttrValueHint,
    TestCoreNotRunning,
    TestExactContext,
    TestDisabledNotRunning,
    TestDisabledBusy,
    TestDisabledPending,
    TestDisabledIncomplete,
    AttributeKeyRequired,
    DuplicateAttributeKey,
    Any,
    RuleSummaryDomain,
    RuleSummaryIp,
    RuleSummaryPort,
    RuleSummaryProto,
    RuleSummaryIn,
    RuleSummaryProc,
    RuleSummaryMatchAll,
    RuleTargetBalancer,
    // Settings screen.
    SettingsAppearance,
    SettingsUiScale,
    SettingsScaleHint,
    SettingsCore,
    SettingsLogLevel,
    SettingsAccessLog,
    SettingsAccessLogHint,
    SettingsEnvVars,
    SettingsPolicyLevels,
    SettingsUserLevel,
    SettingsRemoveLevel,
    SettingsAddUserLevel,
    SettingsUpdates,
    SettingsCheckForUpdates,
    SettingsCheckForUpdatesHint,
    SettingsUpdateChecking,
    SettingsUpdateDetected,
    SettingsUpdateUpToDate,
    SettingsUpdateFailed,
    SettingsUpdateReleasesLink,
    // Settings → Cleanup: exit-time footprint removal.
    SettingsCleanup,
    SettingsCleanupHint,
    SettingsCleanUpAndExit,
    SettingsCleanUpAndExitHint,
    SettingsCleanupTitle,
    SettingsCleanupBody,
    SettingsCleanupFull,
    SettingsCleanupFullHint,
    // Settings → Reset to default.
    SettingsResetToDefault,
    SettingsResetToDefaultHint,
    SettingsResetTitle,
    SettingsResetBody,
    SettingsResetConfirm,
    SettingsAdvanced,
    SettingsPingTest,
    SettingsPingTestHint,
    SettingsRawOverrideActive,
    SettingsRawOverrideHeader,
    SettingsRawOverrideExplain,
    SettingsRawOverridePasteHint,
    SettingsRawOverrideParsing,
    SettingsRawOverrideTooLarge,
    SettingsRawOverrideWorkerFailed,
    SettingsValidateWithCore,
    SettingsValidateHint,
    SettingsEnableOverride,
    SettingsEnableOverrideHint,
    SettingsDisableOverride,
    SettingsCoreAccepts,
    SettingsCoreRejects,
    SettingsTimeoutsHeader,
    SettingsHandshake,
    SettingsConnIdle,
    SettingsUplinkOnly,
    SettingsDownlinkOnly,
    SettingsBufferSize,
    SettingsStatsUserUplink,
    SettingsStatsUserDownlink,
    SettingsStatsUserOnline,
    ProbeIntervalPositive,
    // Settings → Geodata: core-native `geodata` key.
    SettingsGeodata,
    SettingsGeodataCronLabel,
    SettingsGeodataCronHint,
    SettingsGeodataEmptyHint,
    SettingsGeodataScheduleHint,
    // Settings → Geodata provenance + Restore.
    SettingsGeodataProvenanceRelease,
    SettingsGeodataProvenanceUserOn,
    SettingsGeodataProvenanceUserUnknown,
    SettingsGeodataRestore,
    SettingsGeodataRestoreHint,
    SettingsGeodataRestoreBusy,
    SettingsGeodataRestoreDone,
    SettingsGeodataRestoreFailed,
    SettingsGeodataRestoreWorkerFailed,
    GeodataUrlNotHttps,
    GeodataCronNotFiveFields,
    // Servers screen: validators + tool errors.
    SrvRequired,
    SrvUuidRequired,
    SrvMustBeUuid,
    SrvWgKey,
    SrvCertPinHex,
    SrvVlessEncryptionRequired,
    SrvVlessEncryptionFormat,
    SrvAddressRequired,
    SrvPortRequired,
    SrvManagedCoreVerificationFailed,
    SrvLaunchXrayFailed,
    SrvCollectOutputFailed,
    SrvXrayExited,
    SrvReapTimedOutFailed,
    SrvXrayDeadline,
    SrvWaitXrayFailed,
    SrvValidationAlreadyRunning,
    SrvNoProfilesToValidate,
    SrvDraftValidationRequiresIdentity,
    SrvScratchConfigDirFailed,
    SrvScratchConfigSerializeFailed,
    SrvScratchConfigWriteFailed,
    SrvXrayTestSilent,
    SrvDuplicateAcceptedId,
    SrvWorkerExitedWithoutResult,
    SrvDiscardedMismatchedResult,
    SrvDiscardedStaleImport,
    SrvDraftValidationWithoutIdentity,
    SrvXrayRejectedServer,
    SrvServerValidatedAndAdded,
    SrvServerDeletedWhileValidating,
    SrvServerValidatedAndSaved,
    SrvImportedCount,
    SrvImportOutcome,
    SrvAnotherToolRunning,
    SrvSpawnToolFailed,
    SrvStartValidationFailed,
    SrvToolStoppedWithoutResult,
    SrvUuidInvalid,
    SrvUuidTargetNoId,
    SrvUuidGenerated,
    SrvToolTargetFieldNotFound,
    SrvVlessencInvalid,
    SrvVlessencTargetFieldNotFound,
    SrvClientEncryptionGenerated,
    SrvVlessencNoValue,
    SrvWgInvalidPrivateKey,
    SrvWgCouldNotParse,
    SrvWgSecretGenerated,
    SrvWgTargetFieldNotFound,
    SrvMldsa65InvalidKey,
    SrvMldsa65CouldNotParse,
    SrvMldsa65Generated,
    SrvMldsa65TargetFieldNotFound,
    SrvTlsPinMalformed,
    SrvTlsPinNoHash,
    SrvTlsPinComputedLeaf,
    SrvTlsPinComputed,
    SrvTlsPinTargetFieldNotFound,
    SrvTlsHandshakeSucceeded,
    SrvTlsProbeNoHandshake,
    SrvRealityPubKeyDerived,
    SrvRealityTargetFieldNotFound,
    SrvX25519InvalidPublicKey,
    SrvX25519CouldNotParse,
    // Servers screen: list + editor chrome.
    SrvAddServer,
    SrvImportLinks,
    SrvTestLatencyHint,
    SrvProbeServerLatencyHint,
    SrvLatencyTestAlreadyRunning,
    SrvAnotherOperationWorking,
    SrvAddServerBeforeLatency,
    SrvTestingLatencyIsolated,
    SrvSortByLatency,
    SrvDragToReorder,
    SrvSetActive,
    SrvDuplicate,
    SrvExportLinkQr,
    SrvDeleteEllipsis,
    SrvCopySuffix,
    SrvLinkCopiedToClipboard,
    SrvExportFailed,
    SrvUnnamed,
    SrvSelectServerOrAdd,
    SrvPrepareDraftFailed,
    SrvFixBeforeValidate,
    SrvConfigurationWarningsHeader,
    SrvValidateAndSave,
    SrvValidateAndSaveHint,
    SrvDiscardChanges,
    SrvUnsavedChanges,
    SrvUnsavedLeaveBody,
    SrvUnsavedLeaveSave,
    SrvValidatingXrayTest,
    SrvValidationFailedColon,
    SrvCompleteRequired,
    SrvWaitCoreOperation,
    SrvValidateAndAdd,
    SrvValidateAndAddHint,
    SrvKeygenDraftOnly,
    SrvDeleteCannotUndone,
    SrvCannotDeleteReferences,
    SrvDerive,
    SrvDerivingXray,
    SrvPrivateKeyRequired,
    SrvPrivateKeyLabel,
    SrvPrivateKeyHint,
    SrvShareTitle,
    SrvQrTooLong,
    SrvImportShareLinks,
    SrvImportHint,
    SrvImportPasteHint,
    SrvParse,
    SrvPasteCtrlV,
    SrvOkTotal,
    SrvValidateAndAddServers,
    SrvValidateAndAddServersHint,
    SrvValidatingProfiles,
    SrvParsingLinks,
    SrvImportTooLarge,
    SrvParseWorkerFailed,
    SrvRejectedProfileDetails,
    SrvWaitCoreOperationImports,
    SrvImportOkMark,
    SrvImportErrMark,
    SrvInvalidJson,
    // Servers screen: editor sub-forms + finalmask + transports.
    SrvShadowsocksMethodRequired,
    SrvShadowsocksLevelRange,
    SrvAtLeastOneWgPeer,
    SrvWgPeerPublicKeyNote,
    SrvReservedBytesFound,
    SrvResetThreeZeroBytes,
    SrvRemovePeer,
    SrvAddPeer,
    SrvRemove,
    SrvFragmentationInvalid,
    SrvBlackholeResponseInvalid,
    SrvDnsRuleActionRequired,
    SrvAddDnsRule,
    SrvSniffing,
    SrvHysteriaNote,
    SrvReverseProxy,
    SrvReverseSniffing,
    SrvReservedBytes,
    SrvPeersColon,
    SrvTcpFragmentation,
    SrvCustomResponse,
    SrvHttpCamouflageHeader,
    SrvRequestCamouflage,
    SrvResponseCamouflage,
    SrvEnableXmux,
    SrvSeparateDownlinkStream,
    SrvConnectionLimit,
    SrvCoreDefaults,
    SrvMaxConcurrency,
    SrvMaxConnections,
    SrvMutuallyExclusive,
    SrvDownloadNotAllowed,
    SrvRemoveSplitDownload,
    SrvDownloadDepth,
    SrvUnavailableStreamOne,
    SrvDepthExceeded,
    SrvSerializationError,
    SrvPreservedOverLimit,
    SrvSwitchAwayReality,
    SrvHysteriaSelectsTls,
    SrvHysteriaRequiresTls,
    SrvSwitchToTls,
    SrvUseVersion2,
    SrvRewriteHost,
    SrvSkipTlsVerify,
    SrvCongestionNote,
    SrvGrpcDeprecated,
    SrvWsDeprecated,
    SrvHttpupgradeDeprecated,
    SrvMinVersionExceedsMax,
    SrvComputePinFromCert,
    SrvComputePinHint,
    SrvProbeTlsCertificate,
    SrvProbeTlsHandshake,
    SrvProbeTlsHint,
    SrvProbeQuicHandshake,
    SrvProbeQuicHint,
    SrvTlsProbeDomainRequired,
    SrvTlsProbeIpInvalid,
    SrvTlsProbeRunning,
    SrvQuicProbeDomainInvalid,
    SrvQuicProbeResolveFailed,
    SrvQuicProbeHandshakeFailed,
    SrvQuicProbeTimeout,
    SrvQuicProbeNoCert,
    SrvLeafPin,
    SrvCaPins,
    SrvCopyPin,
    SrvApplyPin,
    SrvPinApplied,
    SrvPinCaution,
    SrvProbeNoPin,
    SrvShowProbeOutput,
    SrvProbeOutputTitle,
    SrvUseServerAddress,
    SrvUseServerName,
    SrvFromMitmOnlyAlpn,
    SrvCustomCertificate,
    SrvCertificateN,
    SrvCertificateFileRequired,
    SrvAddCertificate,
    SrvPlaintextNote,
    SrvPublicKeyDerivationDraftOnly,
    SrvEnvelope,
    SrvFinalmask,
    SrvTcpMasks,
    SrvUdpMasks,
    SrvUnknownType,
    SrvMissingType,
    SrvTcpN,
    SrvUdpN,
    SrvAddTcpMask,
    SrvAddUdpMask,
    SrvSockopt,
    SrvAddServerWindow,
    SrvProtocol,
    SrvBasics,
    SrvPadding,
    SrvUpload,
    SrvSession,
    SrvLimits,
    SrvXmux,
    SrvAddRow,
    SrvArgumentN,
    SrvSequenceN,
    SrvItemN,
    SrvRemoveSequence,
    SrvRemoveItem,
    SrvAddItem,
    SrvAddSequence,
    SrvAddRange,
    SrvNoiseN,
    SrvAddNoise,
    SrvMinecraftProfileN,
    SrvAddMinecraftProfile,
    SrvCertificatePem,
    SrvKeyPem,
    SrvAddRealmTlsCertificate,
    SrvRealmTlsWireNote,
    SrvAllowInsecureRemoved,
    SrvUnknownFutureFinalmask,
    SrvPreservedRawValue,
    SrvSetLabel,
    SrvLabelSyntax,
    SrvUp,
    SrvDown,
    SrvCustomSockoptN,
    SrvUnknownFutureFields,
    SrvUnknownFutureFieldsSockopt,
    SrvUnknownFutureFieldsCustom,
    SrvNonWindowsSockopt,
    SrvNonWindowsSockoptNote,
    SrvKeepAliveNote,
    SrvTcpMptcpNote,
    SrvListenerOnlySockopt,
    SrvListenerOnlySockoptNote,
    SrvPenetrateNote,
    SrvPenetrateEchNote,
    SrvEchDnsQuerySockopt,
    SrvEchSockoptNote,
    SrvHappyEyeballs,
    SrvAddCustomSockopt,
    SrvUseDefault,
    SrvHostReserved,
    SrvWsHostDeprecated,
    SrvMoveHostToHost,
    SrvRemoveLegacyHost,
    SrvUnset,
    SrvDefault,
    SrvTrueEnable,
    SrvFalseDisable,
    SrvNumericWindow,
    SrvInvalidImportedValue,
    SrvPreserved,
    SrvWindow,
    SrvBrowse,
    SrvRemoveObsoleteDomain,
    SrvImportedDomainRemoved,
    // Server editor tabs (appended tail block; enum order == table order).
    SrvTabBasic,
    SrvTabTransport,
    SrvTabSecurity,
    SrvTabMux,
    SrvTabAdvanced,
    CoreSetupVersionLink,
    RoutingOverrideApplied,
    RoutingOverrideCleared,
    SrvNewDraftName,
    SrvTcpMptcpEditedAbove,
    SrvAddTransformArgument,
    SrvProtocolSettingsMismatch,
    SrvVlessIdUuid,
    SrvVlessEncryptionInvalid,
    SrvVlessReverseTagRequired,
    SrvVmessIdUuid,
    SrvVmessSecurityUnsupported,
    SrvShadowsocksLevelRangeShort,
    SrvWgSecretInvalid,
    SrvWgReservedThreeBytes,
    SrvWgAtLeastOnePeer,
    SrvWgPeerPublicKeyRequired,
    SrvWgPeerEndpointRequired,
    SrvWgPresharedInvalid,
    SrvWgRemoteDnsInvalid,
    SrvWgRemoteDnsEntryInvalid,
    SrvWgRemoteDnsLocalOnly,
    SrvFreedomFragmentInvalid,
    SrvFreedomNoiseInvalid,
    SrvFreedomFinalRuleInvalid,
    SrvBlackholeResponseInvalidShort,
    SrvDnsRuleActionInvalidShort,
    SrvLoopbackTagRequired,
    SrvHysteriaVersion,
    SrvRealityRequiresTransport,
    SrvHysteriaTransportTls,
    SrvXhttpSettingsMissing,
    SrvKcpSettingsMissing,
    SrvGrpcSettingsMissing,
    SrvWsSettingsMissing,
    SrvHttpupgradeSettingsMissing,
    SrvHysteriaTransportSettingsMissing,
    SrvStreamOneNoDownload,
    SrvXhttpHeaderValueString,
    SrvDownloadNestingExceeds,
    SrvMasterKeyLogNotSupported,
    SrvProxySettingsRemoved,
    SrvRemoveProxySettingsKey,
    SrvRemoveProxySettingsKeyNote,
    SrvRemoveUdpHopKey,
    SrvRemoveUdpHopKeyNote,
    SrvMaskSockoptNote,
    SrvPenetrateMaskNote,
    SrvWsHeaderValueString,
    SrvHttpupgradeHeaderValueString,
    SrvFromMitmOnlyAlpnShort,
    SrvTlsCertFileOrPem,
    SrvRealitySettingsMissing,
    SrvTlsSettingsMissing,
    SrvSendThroughInvalidShort,
    SrvNetwork,
    SrvSecurity,
    SrvName,
    SrvGenerateUuidHint,
    SrvGenerateVlessencHint,
    SrvGenerateWgHint,
    SrvGenerateMldsa65Hint,
    SrvRandomHexHint,
    SrvHysteria2RequiresTls,
    SrvHysteria2RequiresTlsSelectBelow,
    SrvOnlyHysteria2,
    SrvMasquerade,
    SrvUseAuto,
    SrvCookieHeaderNeedsPacketUp,
    SrvSendThroughInvalid,
    SrvMuxDeprecatedHint,
    SrvRulesColon,
    SrvNoisesUdpObfuscation,
    SrvNoiseInvalid,
    SrvRemoveNoise,
    SrvFinalRulesPostFragment,
    SrvFinalRuleActionInvalid,
    SrvRemoveRule,
    SrvAddFinalRule,
    SrvDerivePublicKey,
    TestLatency,
    NoServersYet,
    // Servers screen: descriptive labels (decorated/humanized; wire-key
    // names stay literal).
    SrvInterfaceBindNic,
    SrvRandLength,
    SrvPaddingMinLegacy,
    SrvPaddingMaxLegacy,
    SrvCustomTableLegacy,
    SrvAllowInsecureRemovedLabel,
    SrvAlpn,
    SrvIdUuid,
    SrvLocalAddresses,
    SrvWgRemoteDns,
    SrvWgRemoteDnsHint,
    SrvWgRemoteDnsNote,
    SrvDomainStrategy,
    SrvReservedColon,
    SrvKeepaliveS,
    SrvIntervalMs,
    SrvMaxSplit,
    SrvProxyProtocol,
    SrvRewritePort,
    SrvTtiMs,
    SrvUplinkCapacity,
    SrvCwndMultiplier,
    SrvMaxSendingWindow,
    SrvIdleTimeoutS,
    SrvHealthCheckTimeoutS,
    SrvHeartbeatPeriodS,
    SrvAuthPassword,
    SrvUdpIdleTimeoutS,
    SrvStatusCode,
    SrvServerNameSni,
    SrvMinVersion,
    SrvMaxVersion,
    SrvShowDebug,
    SrvOfficialSourceToken,
    SrvConcurrencyLegacy,
    SrvDelayMs,
    SrvBlockDelayMs,
    SrvIntervalS,
    SrvReverseTag,
    SrvSecretKey,
    SrvPublicKey,
    SrvPreSharedKey,
    SrvTargetStrategy,
    SrvResponseType,
    SrvRewriteNetwork,
    SrvInboundTag,
    SrvCertificateFile,
    SrvKeyFile,
    SrvPublicKeyPassword,
    SrvTcpKeepAliveIdleS,
    SrvTcpKeepAliveIntervalS,
    SrvTcpUserTimeoutMs,
    SrvPenetrateInherit,
    SrvPenetrateDownloadOnly,
    SrvCustomTablesLegacy,
    SrvLengthsPrecedence,
    SrvDelaysPrecedence,
    SrvOcspStaplingS,
    SrvDomainsServer,
    SrvResolversClient,
    SrvMaxIdleTimeoutS,
    SrvKeepAlivePeriodS,
    SrvRewriteAddress,
    SrvHKeepAlivePeriodS,
    SrvDownlinkCapacity,
    SrvCipherSuites,
    SrvCurvePreferences,
    SrvServerNameTarget,
    // Informational hint copy (option semantics — UI copy only, no
    // validation codes).
    SrvTlsServerNameEmptyHint,
    SrvRealityServerNameEmptyHint,
    SrvTlsFingerprintHint,
    SrvRealityFingerprintHint,
    SrvVisionUdp443Hint,
    SrvXudpProxyUdp443Hint,
    SrvGrpcMuxHint,
    SrvGrpcMultiModeHint,
    ErrorBullet,
    // Model-layer validation errors, translated at the source.
    SockoptDomainStrategyInvalid,
    SockoptAddressPortStrategyInvalid,
    SockoptTcpFastOpenType,
    SockoptKeepaliveSigns,
    SockoptCustomOptRequired,
    SockoptCustomTypeInvalid,
    OutboundVisionRequiresTls,
    OutboundPublicVlessNeedsTls,
    OutboundPublicTrojanNeedsTls,
    ListenAddressInvalid,
    // Configuration-warning messages (Severity::Warning codes).
    OutboundMuxWithVisionFlow,
    OutboundServerNameImplausible,
    // Protocol-settings vocabulary / required-value messages (outbound
    // `settings` model rules).
    OutboundVlessFlowUnsupported,
    OutboundVlessEncryptionUnsupported,
    OutboundShadowsocksMethodUnsupported,
    OutboundShadowsocks2022KeyInvalid,
    OutboundTrojanSettingsIncomplete,
    OutboundShadowsocksSettingsIncomplete,
    OutboundSettingsPortZero,
    OutboundSettingsIdNotUuid,
    // Transport-security format rules (stream TLS/REALITY blocks).
    OutboundRealityPublicKeyInvalid,
    OutboundRealityShortIdInvalid,
    OutboundRealitySpiderXInvalid,
    OutboundRealityMldsa65Invalid,
    OutboundTlsFingerprintUnsupported,
    OutboundRealityFingerprintUnsupported,
    OutboundRealityFingerprintUntested,
    OutboundPinnedPeerCertSha256Invalid,
    OutboundTlsVersionRangeInvalid,
    // Stream/sockopt/strategy enum rules (xhttp vocabulary + cross-field
    // rules, inbound sniffing destOverride, outbound targetStrategy —
    // Error tier, mirroring the share-link xhttp grammar texts; the rest
    // are configuration warnings).
    SrvXhttpModeUnsupported,
    SrvXhttpPaddingBytesInvalid,
    SrvXhttpPaddingPlacementInvalid,
    SrvXhttpPaddingMethodInvalid,
    SrvXhttpUplinkPlacementInvalid,
    SrvXhttpUplinkPlacementPacketUp,
    SrvXhttpUplinkMethodPacketUp,
    SrvXhttpSessionPlacementInvalid,
    SrvXhttpSeqPlacementInvalid,
    SrvXhttpSessionLengthRequired,
    SrvXhttpSessionTableInvalid,
    SrvXhttpXmuxExclusive,
    XhttpExtraShadowsSettings,
    SniffingDestOverrideInvalid,
    OutboundTargetStrategyInvalid,
    SockoptTproxySilentOff,
    KcpRangeSoft,
    /// mKCP values Xray's conf build load-refuses (mtu < 21, tti outside
    /// 10..=1000) — the model's Error tier.
    KcpRangeInvalid,
    /// XHTTP serverMaxHeaderBytes negative — Xray refuses at load (Error
    /// tier, model).
    XhttpServerMaxHeaderBytesInvalid,
    GrpcNegativeClamp,
    // Mux-block rules (outbound `mux` model rules; the xudpProxyUDP443
    // whitelist Error, plus the concurrency-reinterpretation and
    // xudp-knobs-without-enabled configuration warnings).
    OutboundMuxXudpProxyUdp443Unsupported,
    OutboundMuxConcurrencyReinterpreted,
    OutboundMuxXudpKnobsInert,
    FinalmaskQuicCongestionInvalid,
    FinalmaskQuicBbrProfileInvalid,
    FinalmaskQuicBandwidthTooSmall,
    FinalmaskQuicBandwidthSyntax,
    FinalmaskQuicBandwidthNonFinite,
    FinalmaskQuicBandwidthTooLarge,
    FinalmaskQuicBandwidthUnitInvalid,
    FinalmaskQuicForceBrutalNeedsUp,
    FinalmaskQuicHopMoved,
    FinalmaskUdpHopModeInvalid,
    FinalmaskUdpHopIntervalTooSmall,
    FinalmaskUdpHopIpInvalid,
    FinalmaskUdpHopDialerProxyConflict,
    FinalmaskQuicReceiveWindowTooSmall,
    FinalmaskQuicMaxIdleTimeoutInvalid,
    FinalmaskQuicKeepAlivePeriodInvalid,
    FinalmaskQuicMaxIncomingStreamsInvalid,
    FinalmaskPortNumberRange,
    FinalmaskPortEnvNameRequired,
    FinalmaskPortListInvalid,
    FinalmaskBytesValueRequired,
    FinalmaskArrayByteSyntax,
    FinalmaskStrByteSyntax,
    FinalmaskHexByteSyntax,
    FinalmaskBase64ByteSyntax,
    FinalmaskUnknownByteSyntax,
    FinalmaskTransformOpRequired,
    FinalmaskTransformArgRequired,
    FinalmaskTransformArgExclusive,
    FinalmaskVarNameInvalid,
    FinalmaskCustomItemExclusive,
    FinalmaskRandRangeInvalid,
    FinalmaskXmcProfilesRequired,
    FinalmaskXmcPasswordRequired,
    FinalmaskXmcUsernameInvalid,
    FinalmaskXmcUuidInvalid,
    FinalmaskXmcTexturesRequired,
    FinalmaskPacketsFirstNotZero,
    FinalmaskPacketsSyntax,
    FinalmaskLengthsStartAboveZero,
    FinalmaskUnknownTcpMask,
    FinalmaskUdpHeaderModeInvalid,
    FinalmaskMkcpHeaderInvalid,
    FinalmaskNoisePacketExclusive,
    FinalmaskSalamanderPacketSize,
    FinalmaskXdnsDomainRemoved,
    FinalmaskXdnsEmpty,
    FinalmaskXdnsResolverUdp,
    FinalmaskXicmpIpInvalid,
    FinalmaskRealmScheme,
    FinalmaskRealmHostRequired,
    FinalmaskRealmTokenBeforeAt,
    FinalmaskRealmIdInPath,
    FinalmaskRealmUrlSyntax,
    FinalmaskRealmStunRequired,
    FinalmaskRealmStunFormat,
    FinalmaskRealmAllowInsecureRemoved,
    FinalmaskRealmFingerprintUnknown,
    FinalmaskRealmAlpnFromMitm,
    FinalmaskRealmCertRequired,
    FinalmaskRealmEchKeysBase64,
    FinalmaskUnknownUdpMask,
    // Dashboard: listener traffic + sys-stats surface.
    DashboardMemory,
    DashboardInboundTraffic,
    GridUp,
    GridDown,
    GridType,
    // ProfilePreview: runtime state tab.
    PreviewConfigTab,
    PreviewRuntimeTab,
    RuntimeInbounds,
    RuntimeOutbounds,
    RuntimeRefresh,
    RuntimeNotRunning,
    RuntimeLoadFailed,
    RuntimeEmpty,
    // Routing: trial rules.
    TrialRulesSection,
    TrialRulesExplain,
    TrialRulesAdd,
    TrialRulesWindow,
    TrialRuleTag,
    TrialRuleTagHint,
    TrialRuleTarget,
    TrialRulesOutbound,
    TrialRulesBalancer,
    TrialRulesOrderHint,
    TrialRuleDomains,
    TrialRuleDomainsHint,
    TrialRuleIps,
    TrialRuleIpsHint,
    TrialRuleProcesses,
    TrialRulesInject,
    TrialRulesRemove,
    TrialRulesClearAll,
    TrialRulesEmpty,
    TrialRulesNotRunning,
    TrialRuleTagTaken,
    TrialRuleTagRequired,
    TrialRuleTargetRequired,
    TrialRuleNeedsCondition,
    TrialRuleTargetNotLive,
    TrialRuleAddedUnlisted,
    TrialRuleCodeUnknown,
    TrialRulesPending,
    TrialRulesRefresh,
    TopbarTrialRules,
    // Dashboard: traffic units + session totals.
    DashboardTrafficUnits,
    TrafficUnitAuto,
    TrafficUnitBps,
    TrafficUnitKiBps,
    TrafficUnitMiBps,
    TrafficUnitGiBps,
    GridUpTotal,
    GridDownTotal,
    // Top-bar speed readout (ui::topbar): one label with both directions.
    TopbarSpeed,
    // Extra-passthrough scan messages (removed/inert extra keys).
    OutboundTrojanFlowRemoved,
    KcpSeedHeaderRemoved,
    KcpHeaderTypeIgnored,
    OutboundVmessAlterIdIgnored,
    OutboundVlessSeedIgnored,
    OutboundFreedomNoiseRemoved,
    OutboundFreedomDomainStrategyUnsupported,
    OutboundRealityServerFormKeysInert,
    HysteriaQuicKnobsMoved,
    // Settings-level verdict messages (`validate_settings` /
    // `validate_profiles`): one key per rule. Parameterized keys hold the
    // `{}`/`{:?}` template that `validation_issue_message` fills with the
    // code-carried values; each template reproduces the exact bytes the
    // generator's free-form strings emitted.
    SettingsActiveProfileMissing,
    SettingsActiveProfileAmbiguous,
    SettingsProfilesRequired,
    SettingsProfileIdEmpty,
    SettingsProfileIdDuplicated,
    SettingsProfileTagEmpty,
    SettingsProfileTagInvalid,
    SettingsProfileTagReserved,
    SettingsProfileTagDuplicated,
    SettingsOutboundChainMissing,
    SettingsOutboundChainCycle,
    SettingsBalancerNoTag,
    SettingsBalancerNoSelector,
    SettingsBalancerTagDuplicated,
    SettingsBalancerFallbackMissing,
    SettingsLocalInboundPortZero,
    SettingsInboundTagDuplicated,
    SettingsDokodemoTagMissing,
    SettingsDokodemoNetworkInvalid,
    SettingsDokodemoUnixSocketRequired,
    SettingsDokodemoUnixSocketConflict,
    SettingsDokodemoPortZero,
    SettingsTunIpv4GatewayRequired,
    SettingsListenerConflict,
    SettingsRoutingRuleTarget,
    SettingsRoutingRuleOutboundMissing,
    SettingsRoutingRuleBalancerMissing,
    SettingsRoutingRuleInboundMissing,
    SettingsDnsServerAddressMissing,
    SettingsFakeDnsPoolCidrInvalid,
    SettingsFakeDnsPoolSizeInvalid,
    SettingsFakeDnsPoolCapacityExceeded,
    SettingsGeodataUrlInvalid,
    SettingsGeodataCronInvalid,
    // Stray strings routed out of consumer code: runtime log lines and
    // frames, probe sentences, and file-dialog strings.
    RtLogHelperDisconnected,
    RtLogConnectRejectedStopping,
    RtLogConnectIgnoredRunning,
    RtLogTransportChangeRestart,
    RtLogTunModeOn,
    RtLogTunModeOff,
    RtLogCoreStartedHelper,
    RtLogConfigApplied,
    RtLogInternalStartRejected,
    RtLogNoConfigConnect,
    RtLogHelperLaunchWait,
    RtLogTunInboundClosed,
    RtLogTunCloseTimeout,
    RtLogTunCoreExited,
    RtLogTunCoreAlive,
    RtLogDnsFlushExit,
    RtLogStartupConfigRetry,
    RtLogCoreReady,
    RtLogExitNotReported,
    RtLogSuppressedOne,
    RtLogSuppressedMany,
    RtPhaseHelperUnavailable,
    RtPhaseHelperConfigLost,
    RtPhaseHelperStartFailed,
    RtPhaseBackendReplacementCancelled,
    RtPhaseUpdateRecoveryFailed,
    RtPhaseApiListenerReadFailed,
    RtPhaseConfigReadFailed,
    RtPhaseCoreSpawnFailed,
    RtPhaseHelperExitUnconfirmed,
    RtPhaseConfigError,
    RtPhaseReadinessTimeout,
    RtPhaseRestartCancelled,
    RtFrameCandidateExited,
    RtFrameUpdatedCoreExited,
    RtFrameNoCoreOutput,
    RtFrameCandidateReadyTimeout,
    RtFrameUpdatedCoreReadyTimeout,
    RtFrameCommandRejectedBusy,
    RtFrameBackgroundFailed,
    ProbeExitStatus,
    ProbeExitNoStatus,
    ProbeWaitFailed,
    ProbeInterfaceTunSelf,
    ProbeInterfaceDown,
    ProbeInterfaceMissing,
    ProbeHostBlocked,
    ProbePortAllocateFailed,
    ProbePortReadFailed,
    ProbeConfigRejected,
    ProbeTempDirFailed,
    ProbeConfigSerializeFailed,
    ProbeConfigWriteFailed,
    ProbeChildLaunchFailed,
    ProbeNoProfiles,
    ProbeCancelled,
    ProbeTimedOut,
    ProbeTimedOutMissing,
    ProbeTimedOutApiError,
    ProbeTimedOutMissingApiError,
    ProbeDiagnosticsWall,
    ShellXrayArchiveFilter,
    ShellMasterKeyLogFileName,
    ShellCertificateFilter,
    // Error chains and runtime messages, rendered at the display boundary.
    LinkPercentTruncated,
    LinkPercentEscape,
    LinkPercentUtf8,
    LinkQueryDuplicate,
    LinkNameTooLong,
    LinkHostMissing,
    LinkHostIdn,
    LinkHostInvalid,
    LinkHostIpv4,
    LinkHostIpv6,
    LinkHostIpv6Brackets,
    LinkHostBracketed,
    LinkHostIpv6Unbracketed,
    LinkPortMissing,
    LinkPortInvalid,
    LinkPortZero,
    LinkUuidInvalid,
    LinkUuidMissing,
    LinkNumericParam,
    LinkQueryEmpty,
    LinkTransportUnknown,
    LinkSecurityUnknown,
    LinkRealityMldsaDuplicate,
    LinkGrpcModeUnknown,
    LinkXhttpModeUnknown,
    LinkXhttpExtraJson,
    LinkXhttpExtraObject,
    LinkXhttpExtraReserved,
    LinkFinalmaskJson,
    LinkUserinfoMissing,
    LinkUserinfoAt,
    LinkVmessBase64,
    LinkVmessJson,
    LinkVmessObject,
    LinkLegacyFieldType,
    LinkVmessAdd,
    LinkVmessPort,
    LinkVmessTcpType,
    LinkVmessNet,
    LinkTrojanPasswordEmpty,
    LinkSsUserinfoAt,
    LinkSsBase64,
    LinkSsUtf8,
    LinkSsUserinfoFormat,
    LinkSsMethodEmpty,
    LinkSsPasswordEmpty,
    LinkRealityServerNameEmpty,
    LinkRealityFingerprint,
    LinkRealityPbk,
    LinkRealitySid,
    LinkRealityPqv,
    LinkRealitySpx,
    LinkTlsFingerprint,
    LinkTlsAlpnFromMitm,
    LinkTlsPcs,
    LinkXhttpMode,
    LinkXhttpHeaderValues,
    LinkXhttpHostHeader,
    LinkXhttpPaddingBytes,
    LinkXhttpPaddingPlacement,
    LinkXhttpPaddingMethod,
    LinkXhttpUplinkPlacement,
    LinkXhttpUplinkMode,
    LinkXhttpUplinkMethod,
    LinkXhttpSessionPlacement,
    LinkXhttpSeqPlacement,
    LinkXhttpSessionLength,
    LinkXhttpSessionSpace,
    LinkXhttpServerMaxHeader,
    LinkXhttpXmux,
    LinkXhttpStreamOne,
    LinkRawHeaderType,
    LinkRawCamouflage,
    LinkRawHeaderValues,
    LinkKcpMtu,
    LinkKcpTti,
    LinkKcpCwnd,
    LinkKcpWindow,
    LinkWsHeaderValues,
    LinkGrpcServiceName,
    LinkHttpupgradeHeaderValues,
    LinkProtocolMismatch,
    LinkVlessFlow,
    LinkVlessEncryption,
    LinkTrojanIncomplete,
    LinkSsIncomplete,
    LinkSsMethod,
    LinkSsKeyMaterial,
    LinkTooLong,
    LinkNoScheme,
    LinkBadScheme,
    LinkSubscriptionTooLarge,
    LinkFinalmaskInvalid,
    LinkUnsupportedTypeHttp,
    LinkUnsupportedTypeQuic,
    LinkUnsupportedXtls,
    LinkUnsupportedTrojanEncryption,
    LinkUnsupportedFlow,
    LinkUnsupportedGrpcGuna,
    LinkUnsupportedTransportMode,
    LinkUnsupportedAllowInsecure,
    LinkUnsupportedField,
    LinkUnsupportedVmessAlterId,
    LinkUnsupportedQueryField,
    LinkUnsupportedHysteria,
    LinkUnsupportedLegacyField,
    LinkUnsupportedLegacyVersion,
    LinkUnsupportedVmessAlterIdValue,
    LinkUnsupportedVmessTls,
    LinkUnsupportedVmessTcpHostPath,
    LinkUnsupportedVmessKcp,
    LinkUnsupportedVmessWebsocket,
    LinkUnsupportedVmessHttpupgrade,
    LinkUnsupportedVmessXhttp,
    LinkUnsupportedVmessNetHttp,
    LinkUnsupportedVmessNetQuic,
    LinkUnsupportedSsPlugin,
    LinkUnsupportedSsQueryField,
    LinkUnsupportedVmessEncryption,
    LinkUnsupportedProtocol,
    LinkUnsupportedScheme,
    LinkLossyPolicyLevel,
    LinkLossyEmail,
    LinkLossyVlessReverse,
    LinkLossyVlessExtra,
    LinkLossyVmessExtra,
    LinkLossyTrojanExtra,
    LinkLossySsExtra,
    LinkLossyVmessExperiments,
    LinkLossyTlsAdvanced,
    LinkLossyRealityAdvanced,
    LinkLossySockopt,
    LinkLossyStreamExtra,
    LinkLossyTlsMissing,
    LinkLossyRealityMissing,
    LinkLossyTlsUnselected,
    LinkLossyRealityUnselected,
    LinkLossyRawCamouflage,
    LinkLossyKcp,
    LinkLossyWs,
    LinkLossyGrpc,
    LinkLossyHttpupgrade,
    LinkLossyTransportUnselected,
    LinkLossySsStream,
    LinkLossyProfileExtra,
    LinkLossyDialerProxy,
    LinkLossySendThrough,
    LinkLossyTargetStrategy,
    LinkLossyMux,
    LinkLossyOutboundExtra,
    LinkLossyProfileName,
    LinkLossyProfileRoundtrip,
    LinkLossyXhttpSerialize,
    LinkLossyXhttpEncode,
    LinkLossyFinalmaskEncode,
    GenRawOverride,
    GenApiListenerPortZero,
    GenProbePortZero,
    GenProbeUrlInvalid,
    GenProbeUrlNotAbsolute,
    GenObservatoryProbeHostBlocked,
    GenProbeHostBlocked,
    GenApiPort,
    IntegrityBalancerMissing,
    IntegrityBalancerTagEmpty,
    IntegrityBalancerTagDuplicate,
    IntegrityBalancerReferenced,
    IntegrityRuleTargetRequired,
    IntegrityRuleTargetExclusive,
    IntegrityRouteTargetRequired,
    IntegrityRouteTargetPort,
    IntegrityRoutePort,
    IntegrityRouteIp,
    IntegrityRouteNetwork,
    IntegrityRouteAttributeKey,
    RtLogOperationCancelled,
    RtLogUpdateFinishedAfterStop,
    RtLogApiEndpointCommitted,
    RtLogApiEndpointRecovered,
    RtLogCoreStartedDirect,
    RtLogTunGracefulCloseFailed,
    RtLogTunCoreStopWindow,
    RtLogHelperStopFailed,
    RtLogDnsFlushFailed,
    RtLogCoreExitBackoff,
    RtLogDnsInListenerAdded,
    RtLogDnsInListenerNotAdded,
    RtLogUpdateCancelRequested,
    RtLogValidationCancelRequested,
    RtLogUpdateAckFailed,
    RtFramePreviewReadFailed,
    RtPhaseHelperLaunchFailed,
    RtFrameApplyRejected,
    RtFrameCandidateWriteFailed,
    RtFrameApplyCaptureFailed,
    RtFrameApplyCommitFailed,
    RtFrameUpdatedCoreSpawnRestored,
    RtFrameUpdatedCoreSpawnNoLastGood,
    RtFrameUpdatedCoreSpawnRollbackFailed,
    RtFrameRolledBackLastGood,
    RtFrameRollbackFailed,
    RtFrameCoreRestored,
    RtFrameCoreNoLastGood,
    RtFrameCoreRollbackFailed,
    RtFrameStartupRollbackFailed,
    RtFrameApplyCancelled,
    RtFrameConfigTestCancelled,
    RtFrameProfileValidationCancelled,
    RtFrameConfigRollbackCancelled,
    RtFrameCoreRollbackCancelled,
    RtFrameCandidateRetryBindRace,
    RtFrameCandidateRetryTeardownRace,
    RtFrameUpdateRetryBindRace,
    RtFrameUpdateStopCoreFirst,
    RtFrameUpdateHealthCheckPending,
    RtFrameUpdatedCoreReadyTimeoutApi,
    RtFrameStageCheckingRelease,
    RtFrameStageVerifyingArchive,
    RtFrameArchiveWorkerFailed,
    RtFrameCandidateLostHelper,
    RtFrameUpdatedCoreLostHelper,
    RtFrameApiListenerNotOwned,
    RtFrameApiProbeFailed,
    RtReasonStopRequested,
    RtReasonShutdownRequested,
    RtReasonGuiChannelClosed,
    RtReasonCoreExitedUnexpectedly,
    RtReasonHelperDisconnected,
    OperationConnect,
    OperationDisconnect,
    OperationRestart,
    OperationApplyConfig,
    OperationTestConfig,
    OperationUpdateCore,
    OperationLatencyProbe,
    OperationValidateProfiles,
    SeatRuntimeStopping,
    SeatCoreNotRunning,
    SeatBalancerTagRequired,
    SeatOverrideTargetRequired,
    SeatRuleTagRequired,
    SeatInvalidRouteTest,
    SeatInvalidTrialRule,
    SeatBusyWithOperation,
    SeatValidationCancelled,
    GrpcTestRouteFailed,
    GrpcBalancerInfoFailed,
    GrpcBalancerInfoMissing,
    GrpcBalancerNotFound,
    GrpcBalancerOverrideFailed,
    GrpcBalancerOverrideClearFailed,
    GrpcRestartLoggerFailed,
    GrpcAddRuleFailed,
    GrpcRemoveRuleFailed,
    GrpcListRulesFailed,
    GrpcRuntimeStateFailed,
    GrpcTrialRuleTagRequired,
    GrpcTrialRuleFieldUnsupported,
    GrpcTrialRuleTargetRequired,
    GrpcTrialRuleTargetConflict,
    GrpcGeodataSyntaxError,
    GrpcGeodataEmptyFile,
    GrpcGeodataEmptyAttr,
    GrpcGeodataEmptyCode,
    GrpcDotlessRuleContainsDot,
    GrpcUnsupportedAddressFamily,
    GrpcInvalidCidrPrefix,
    GrpcCidrPrefixTooLong,
    GrpcInvalidRouteIp,
    GrpcUnsupportedNetwork,
    // Error chains and runtime messages, rendered at the display boundary.
    HelperPipeIdInvalid,
    HelperParentArgMissing,
    HelperParentArgDuplicate,
    HelperParentArgInvalid,
    HelperProcessOpenFailed,
    HelperProcessTimeReadFailed,
    HelperParentExitedBeforeConnect,
    HelperConnectTimeout,
    HelperConnectFailed,
    HelperParentOpenFailed,
    HelperParentExitedBeforePipe,
    HelperParentTimeReadFailed,
    HelperParentTokenOpenFailed,
    HelperParentSidReadFailed,
    HelperOwnTokenOpenFailed,
    HelperOwnSidReadFailed,
    HelperWellKnownSidFailed,
    HelperPipeAttributesFailed,
    HelperPipeCreateFailed,
    HelperPipeModeFailed,
    HelperClientPidReadFailed,
    HelperClientTimeReadFailed,
    HelperClientNotLaunchingGui,
    HelperPipeDuplicateFailed,
    HelperAuthReadFailed,
    HelperAuthMessageMissing,
    HelperAuthParseFailed,
    HelperAuthRejected,
    HelperAuthTimeout,
    HelperPipeClosed,
    HelperAuthTokenInvalid,
    HelperParentPidInvalid,
    HelperConnectCancelled,
    HelperClientPipeModeFailed,
    HelperPipeWriterPoisoned,
    HelperAuthWriteFailed,
    HelperAuthFlushFailed,
    HelperReaderThreadFailed,
    HelperStartPortInvalid,
    HelperStartCorePathNotAbsolute,
    HelperPipeWriteFailed,
    HelperPipeFlushFailed,
    HelperProgramDataResolveFailed,
    HelperProgramDataDecodeFailed,
    HelperProgramDataInspectFailed,
    HelperProgramDataNotDirectory,
    HelperDirectoryInspectFailed,
    HelperDirectoryNotOrdinary,
    HelperDescriptorSizeQueryFailed,
    HelperDescriptorReadFailed,
    HelperDescriptorControlReadFailed,
    HelperOwnerReadFailed,
    HelperDaclReadFailed,
    HelperDaclMissingOrInherited,
    HelperOwnerUnexpected,
    HelperDaclMissing,
    HelperDaclUnexpectedPrincipals,
    HelperAceReadFailed,
    HelperAceMalformed,
    HelperAceNotFullControl,
    HelperAceSystemRepeated,
    HelperAceAdministratorsRepeated,
    HelperAceUnexpectedSid,
    HelperAcePrincipalMissing,
    HelperDeviationNotBenign,
    HelperDescriptorBuildFailed,
    HelperDaclRepairFailed,
    HelperDirectoryAttributesFailed,
    HelperDirectoryCreateFailed,
    HelperStageEnumerateFailed,
    HelperStageEntryReadFailed,
    HelperStageEntryInspectFailed,
    HelperStageEntryUnexpected,
    HelperStageMarkerMissing,
    HelperStageEntryRemoveFailed,
    HelperStageRemoveFailed,
    HelperStagedConfigCreateFailed,
    HelperStagedConfigWriteFailed,
    HelperStagedConfigFlushFailed,
    HelperStagedConfigLockFailed,
    HelperStagedConfigProofFailed,
    HelperStageMarkerCreateFailed,
    HelperStageMarkerWriteFailed,
    HelperStageMarkerFlushFailed,
    HelperHashRewindFailed,
    HelperHashReadFailed,
    HelperWirePathMissing,
    HelperWirePathLengthInvalid,
    HelperWirePathUnitInvalid,
    HelperWirePathNul,
    HelperWirePathNotAbsolute,
    HelperWireConfigMissing,
    HelperWireConfigEncodingInvalid,
    HelperWirePortInvalid,
    HelperConfigTooLarge,
    HelperMalformedStartCommand,
    HelperStageValidated,
    HelperStageRefused,
    HelperCoreSpawnFailed,
    HelperJobSetupFailed,
    HelperShieldRemovedAfterExit,
    HelperShieldNotInstalledAfterExit,
    HelperDnsShieldTeardownFailed,
    HelperDnsShieldNotEngaged,
    HelperTunAdapterMissing,
    HelperConfigNoTunAdapter,
    HelperTunCleanupConfigReadFailed,
    HelperTunCleanupTimeout,
    HelperStagedValidationSpawnFailed,
    HelperStagedValidationIsolateFailed,
    HelperStagedConfigRejected,
    HelperStagedValidationTimeout,
    HelperStagedValidationWaitFailed,
    ApplyActiveReadFailed,
    ApplyListenMissing,
    ApplyListenInvalid,
    ApplyListenNotLoopback,
    ApplyFileReadFailed,
    ApplyFileParseFailed,
    ApplyValidationSpawnFailed,
    ApplyValidationChildExited,
    ApplyValidationJobCreateFailed,
    ApplyValidationJobAssignFailed,
    ApplyFilesystemWorkerFailed,
    ApplyConfigDirCreateFailed,
    ApplyCandidateSerializeFailed,
    ApplyFileCreateFailed,
    ApplyFileWriteFailed,
    ApplyFileFlushFailed,
    ApplyLastgoodStageFailed,
    ApplyLastgoodReplaceFailed,
    ApplyActiveReplaceFailed,
    ApplyRollbackMissing,
    ApplyRollbackStageFailed,
    ApplyRollbackRestoreFailed,
    ApplyValidationTimeout,
    ApplyValidationRunFailed,
    ApplyCoreVerifyFailed,
    ApplyCoreVerifyWorkerFailed,
    SupervisorVerifyFailed,
    SupervisorVerifyWorkerFailed,
    SupervisorSpawnFailed,
    SupervisorChildExited,
    SupervisorJobCreateFailed,
    SupervisorJobAssignFailed,
    WfpMissingXrayPath,
    WfpMissingTunIfindex,
    WfpEngineOpenFailed,
    WfpSubLayerAddFailed,
    WfpAppIdReadFailed,
    WfpFilterAddFailed,
    CoreDlPayloadRewindFailed,
    CoreDlPayloadCreateFailed,
    CoreDlPayloadCopyFailed,
    CoreDlPayloadFlushFailed,
    CoreDlPayloadLockFailed,
    CoreDlPayloadProofFailed,
    CoreDlCorePathNotAbsolute,
    CoreDlSourceInspectFailed,
    CoreDlSourceNotDirectory,
    CoreDlSourceNotFile,
    CoreDlMetadataOpenFailed,
    CoreDlMetadataParseFailed,
    CoreDlMetadataMismatch,
    CoreDlPayloadOpenFailed,
    CoreDlPayloadVerifyFailed,
    CoreDlPayloadStillDrifted,
    CoreDlPayloadRestoreFailed,
    CoreDlVersionPrefixMissing,
    CoreDlVersionInvalid,
    CoreDlArchivePinInvalid,
    CoreDlArchiveMismatch,
    CoreDlStageDownload,
    CoreDlStageVerifyPin,
    CoreDlStageInstall,
    CoreDlHttpRequestFailed,
    CoreDlHttpStatusRejected,
    CoreDlDownloadTooLarge,
    CoreDlDownloadTimeout,
    CoreDlDownloadStreamFailed,
    CoreDlDownloadSizeOverflow,
    CoreDlDownloadLimitExceeded,
    CoreDlDownloadWriteFailed,
    CoreDlDownloadFlushFailed,
    CoreDlDirectoryCreateFailed,
    CoreDlFileOpenFailed,
    CoreDlFileCreateFailed,
    CoreDlFileWriteFailed,
    CoreDlFileFlushFailed,
    CoreDlFileRemoveFailed,
    CoreDlFileCopyFailed,
    CoreDlFileReplaceFailed,
    CoreDlHashingFailed,
    CoreDlMetadataSerializeFailed,
    CoreDlArchiveOpenFailed,
    CoreDlArchiveInvalid,
    CoreDlArchiveEntryUnreadable,
    CoreDlArchiveExtractFailed,
    CoreDlArchiveMissingXray,
    CoreDlArchivePayloadsMismatch,
    CoreDlPristineCopyFailed,
    CoreDlPristineMismatch,
    CoreDlRestoreUnavailable,
    CoreDlCoreNotDirectory,
    CoreDlBackupNotDirectory,
    CoreDlRecoverBackupFailed,
    CoreDlMarkerCorrupt,
    CoreDlRecoverInterruptedFailed,
    CoreDlInterruptedWithoutCore,
    CoreDlUpdatePendingHealth,
    CoreDlBackupRemoveFailed,
    CoreDlQuarantineFailed,
    CoreDlRestoreLastgoodFailed,
    CoreDlRestoreCandidateFailed,
    CoreDlStagingMissing,
    CoreDlBackupStagingFailed,
    CoreDlInstallFailed,
    CoreDlRestoreAfterValidationFailed,
    HelperLaunchDeclined,
    HelperShellExecuteFailed,
    HelperLaunchExePathFailed,
    HelperTokenFileOwnerFailed,
    HelperTokenFileCreateFailed,
    HelperTokenFileSecurityFailed,
    HelperTokenFileWriteFailed,
    GeodataErrorIo,
    GeodataErrorTooLarge,
    GeodataErrorMalformed,
    GeodataOperationOpen,
    GeodataOperationInspect,
    GeodataOperationRead,
    DashboardLatencyNoObservation,
}

/// Look up `key` in `language`'s locale table.
pub fn t(language: Language, key: Key) -> &'static str {
    match language {
        Language::En => en::table(key),
    }
}

/// Like [`t`], but substitutes each `{...}` placeholder in the locale string
/// (positional `{}`, `{:?}`, …) with the matching argument, in order.
///
/// Strict contract:
/// - Placeholders are positional only — the inner text (e.g. `{:?}`) is ignored
///   and never formats the argument. Callers that need Debug or alternate
///   formatting must pre-format the argument (e.g. `&format!("{:?}", x)`).
/// - The number of arguments MUST equal the number of `{` placeholders in the
///   template (asserted in debug builds). `{{`/`}}` escapes are not supported
///   and none exist in the locale table.
/// - Arguments beyond the placeholder count are ignored (the debug assertion
///   catches that as a bug anyway).
///
/// Templates with named placeholders that callers fill via `t().replace(…)`
/// never reach `t_fmt`.
pub fn t_fmt(language: Language, key: Key, args: &[&dyn std::fmt::Display]) -> String {
    let template = t(language, key);
    debug_assert_eq!(
        args.len(),
        template.matches('{').count(),
        "t_fmt({key:?}): argument count must equal placeholder count"
    );
    fill_placeholders(template, args)
}

/// Substitution core: replaces each `{...}` placeholder with the next
/// argument, in order. Placeholders without a matching argument stay literal;
/// extra arguments are ignored. Callers must pre-format arguments (e.g. Debug
/// via `format!("{:?}", x)`); the placeholder inner text is never used.
fn fill_placeholders(template: &str, args: &[&dyn std::fmt::Display]) -> String {
    let mut out = String::with_capacity(template.len() + args.len() * 8);
    let mut rest = template;
    let mut args = args.iter();
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else { break };
        let Some(arg) = args.next() else { break };
        out.push_str(&rest[..start]);
        out.push_str(&arg.to_string());
        rest = &rest[start + 1 + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Render one model-validation rule as its locale message. Exhaustive over
/// [`ValidationCode`], so a code forgotten here is a compile error. Where the
/// underlying text is unchanged it reuses the existing `Key` table entry;
/// parameterized rules (e.g. `FinalmaskPortListInvalid(..)`) return the
/// static template, which [`validation_issue_message`] fills with the
/// code-carried value.
pub fn validation_message(code: &ValidationCode, lang: Language) -> &'static str {
    use ValidationCode::*;
    match code {
        XhttpDepthExceeded => t(lang, Key::SrvDownloadNestingExceeds),
        TransportSettingsMissing(network) => match network {
            Network::Xhttp => t(lang, Key::SrvXhttpSettingsMissing),
            Network::Kcp => t(lang, Key::SrvKcpSettingsMissing),
            Network::Grpc => t(lang, Key::SrvGrpcSettingsMissing),
            Network::Ws => t(lang, Key::SrvWsSettingsMissing),
            Network::Httpupgrade => t(lang, Key::SrvHttpupgradeSettingsMissing),
            Network::Hysteria => t(lang, Key::SrvHysteriaTransportSettingsMissing),
            Network::Raw => {
                debug_assert!(false, "TransportSettingsMissing cannot name raw");
                t(lang, Key::SrvXhttpSettingsMissing)
            }
        },
        HysteriaTransportRequiresTls => t(lang, Key::SrvHysteriaTransportTls),
        HysteriaTransportVersion => t(lang, Key::SrvHysteriaVersion),
        RealityRequiresTransport => t(lang, Key::SrvRealityRequiresTransport),
        RealitySettingsMissing => t(lang, Key::SrvRealitySettingsMissing),
        TlsSettingsMissing => t(lang, Key::SrvTlsSettingsMissing),
        StreamOneNoDownload => t(lang, Key::SrvStreamOneNoDownload),
        MasterKeyLogNotSupported => t(lang, Key::SrvMasterKeyLogNotSupported),
        OutboundProxySettingsRemoved => t(lang, Key::SrvProxySettingsRemoved),
        TlsAllowInsecureRemoved => t(lang, Key::SrvAllowInsecureRemoved),
        ShadowsocksLevelRange => t(lang, Key::SrvShadowsocksLevelRangeShort),
        BlackholeResponseInvalid => t(lang, Key::SrvBlackholeResponseInvalidShort),
        VisionRequiresTlsOrReality => t(lang, Key::OutboundVisionRequiresTls),
        PublicVlessRequiresTlsOrEncryption => t(lang, Key::OutboundPublicVlessNeedsTls),
        PublicTrojanRequiresTlsOrReality => t(lang, Key::OutboundPublicTrojanNeedsTls),
        ListenAddressInvalid => t(lang, Key::ListenAddressInvalid),
        MuxWithVisionFlow => t(lang, Key::OutboundMuxWithVisionFlow),
        ServerNameImplausible => t(lang, Key::OutboundServerNameImplausible),
        VlessFlowUnsupported => t(lang, Key::OutboundVlessFlowUnsupported),
        VlessEncryptionUnsupported => t(lang, Key::OutboundVlessEncryptionUnsupported),
        ShadowsocksMethodUnsupported => t(lang, Key::OutboundShadowsocksMethodUnsupported),
        Shadowsocks2022KeyInvalid => t(lang, Key::OutboundShadowsocks2022KeyInvalid),
        TrojanSettingsIncomplete => t(lang, Key::OutboundTrojanSettingsIncomplete),
        ShadowsocksSettingsIncomplete => t(lang, Key::OutboundShadowsocksSettingsIncomplete),
        SettingsPortZero => t(lang, Key::OutboundSettingsPortZero),
        SettingsIdNotUuid => t(lang, Key::OutboundSettingsIdNotUuid),
        RealityPublicKeyInvalid => t(lang, Key::OutboundRealityPublicKeyInvalid),
        RealityShortIdInvalid => t(lang, Key::OutboundRealityShortIdInvalid),
        RealitySpiderXInvalid => t(lang, Key::OutboundRealitySpiderXInvalid),
        RealityMldsa65Invalid => t(lang, Key::OutboundRealityMldsa65Invalid),
        TlsFingerprintUnsupported => t(lang, Key::OutboundTlsFingerprintUnsupported),
        RealityFingerprintUnsupported => t(lang, Key::OutboundRealityFingerprintUnsupported),
        RealityFingerprintUntested(_) => t(lang, Key::OutboundRealityFingerprintUntested),
        PinnedPeerCertSha256Invalid => t(lang, Key::OutboundPinnedPeerCertSha256Invalid),
        TlsVersionRangeInvalid => t(lang, Key::OutboundTlsVersionRangeInvalid),
        TlsMinExceedsMax => t(lang, Key::SrvMinVersionExceedsMax),
        XhttpModeUnsupported => t(lang, Key::SrvXhttpModeUnsupported),
        XhttpPaddingBytesInvalid => t(lang, Key::SrvXhttpPaddingBytesInvalid),
        XhttpPaddingPlacementInvalid => t(lang, Key::SrvXhttpPaddingPlacementInvalid),
        XhttpPaddingMethodInvalid => t(lang, Key::SrvXhttpPaddingMethodInvalid),
        XhttpUplinkDataPlacementInvalid => t(lang, Key::SrvXhttpUplinkPlacementInvalid),
        XhttpUplinkDataPlacementRequiresPacketUp => t(lang, Key::SrvXhttpUplinkPlacementPacketUp),
        XhttpUplinkHttpMethodRequiresPacketUp => t(lang, Key::SrvXhttpUplinkMethodPacketUp),
        XhttpSessionIdPlacementInvalid => t(lang, Key::SrvXhttpSessionPlacementInvalid),
        XhttpSeqPlacementInvalid => t(lang, Key::SrvXhttpSeqPlacementInvalid),
        XhttpSessionIdLengthRequired => t(lang, Key::SrvXhttpSessionLengthRequired),
        XhttpSessionIdTableInvalid => t(lang, Key::SrvXhttpSessionTableInvalid),
        XhttpXmuxLimitsExclusive => t(lang, Key::SrvXhttpXmuxExclusive),
        XhttpExtraShadowsSettings(_) => t(lang, Key::XhttpExtraShadowsSettings),
        SniffingDestOverrideInvalid => t(lang, Key::SniffingDestOverrideInvalid),
        OutboundTargetStrategyInvalid => t(lang, Key::OutboundTargetStrategyInvalid),
        SockoptTproxySilentOff => t(lang, Key::SockoptTproxySilentOff),
        KcpRangeSoft => t(lang, Key::KcpRangeSoft),
        KcpRangeInvalid => t(lang, Key::KcpRangeInvalid),
        XhttpServerMaxHeaderBytesInvalid => t(lang, Key::XhttpServerMaxHeaderBytesInvalid),
        GrpcNegativeClamp => t(lang, Key::GrpcNegativeClamp),
        MuxXudpProxyUdp443Unsupported => t(lang, Key::OutboundMuxXudpProxyUdp443Unsupported),
        MuxConcurrencyReinterpreted => t(lang, Key::OutboundMuxConcurrencyReinterpreted),
        MuxXudpKnobsInert => t(lang, Key::OutboundMuxXudpKnobsInert),
        TrojanFlowRemoved => t(lang, Key::OutboundTrojanFlowRemoved),
        KcpSeedHeaderRemoved => t(lang, Key::KcpSeedHeaderRemoved),
        KcpHeaderTypeIgnored => t(lang, Key::KcpHeaderTypeIgnored),
        VmessAlterIdIgnored => t(lang, Key::OutboundVmessAlterIdIgnored),
        VlessSeedIgnored => t(lang, Key::OutboundVlessSeedIgnored),
        FreedomNoiseRemoved => t(lang, Key::OutboundFreedomNoiseRemoved),
        FreedomDomainStrategyUnsupported => t(lang, Key::OutboundFreedomDomainStrategyUnsupported),
        RealityServerFormKeysInert => t(lang, Key::OutboundRealityServerFormKeysInert),
        HysteriaQuicKnobsMoved => t(lang, Key::HysteriaQuicKnobsMoved),
        SockoptDomainStrategyInvalid => t(lang, Key::SockoptDomainStrategyInvalid),
        SockoptAddressPortStrategyInvalid => t(lang, Key::SockoptAddressPortStrategyInvalid),
        SockoptTcpFastOpenType => t(lang, Key::SockoptTcpFastOpenType),
        SockoptKeepaliveSigns => t(lang, Key::SockoptKeepaliveSigns),
        SockoptCustomOptRequired => t(lang, Key::SockoptCustomOptRequired),
        SockoptCustomTypeInvalid => t(lang, Key::SockoptCustomTypeInvalid),
        FinalmaskQuicCongestionInvalid => t(lang, Key::FinalmaskQuicCongestionInvalid),
        FinalmaskQuicBbrProfileInvalid => t(lang, Key::FinalmaskQuicBbrProfileInvalid),
        FinalmaskQuicBandwidthTooSmall => t(lang, Key::FinalmaskQuicBandwidthTooSmall),
        FinalmaskQuicBandwidthSyntax => t(lang, Key::FinalmaskQuicBandwidthSyntax),
        FinalmaskQuicBandwidthNonFinite => t(lang, Key::FinalmaskQuicBandwidthNonFinite),
        FinalmaskQuicBandwidthTooLarge => t(lang, Key::FinalmaskQuicBandwidthTooLarge),
        FinalmaskQuicBandwidthUnitInvalid(_) => t(lang, Key::FinalmaskQuicBandwidthUnitInvalid),
        FinalmaskQuicForceBrutalNeedsUp => t(lang, Key::FinalmaskQuicForceBrutalNeedsUp),
        FinalmaskQuicHopMoved => t(lang, Key::FinalmaskQuicHopMoved),
        FinalmaskUdpHopModeInvalid => t(lang, Key::FinalmaskUdpHopModeInvalid),
        FinalmaskUdpHopIntervalTooSmall => t(lang, Key::FinalmaskUdpHopIntervalTooSmall),
        FinalmaskUdpHopIpInvalid => t(lang, Key::FinalmaskUdpHopIpInvalid),
        FinalmaskUdpHopDialerProxyConflict => t(lang, Key::FinalmaskUdpHopDialerProxyConflict),
        FinalmaskQuicReceiveWindowTooSmall => t(lang, Key::FinalmaskQuicReceiveWindowTooSmall),
        FinalmaskQuicMaxIdleTimeoutInvalid => t(lang, Key::FinalmaskQuicMaxIdleTimeoutInvalid),
        FinalmaskQuicKeepAlivePeriodInvalid => t(lang, Key::FinalmaskQuicKeepAlivePeriodInvalid),
        FinalmaskQuicMaxIncomingStreamsInvalid => {
            t(lang, Key::FinalmaskQuicMaxIncomingStreamsInvalid)
        }
        FinalmaskPortNumberRange => t(lang, Key::FinalmaskPortNumberRange),
        FinalmaskPortEnvNameRequired => t(lang, Key::FinalmaskPortEnvNameRequired),
        FinalmaskPortListInvalid(_) => t(lang, Key::FinalmaskPortListInvalid),
        FinalmaskBytesValueRequired(_) => t(lang, Key::FinalmaskBytesValueRequired),
        FinalmaskArrayByteSyntax => t(lang, Key::FinalmaskArrayByteSyntax),
        FinalmaskStrByteSyntax => t(lang, Key::FinalmaskStrByteSyntax),
        FinalmaskHexByteSyntax => t(lang, Key::FinalmaskHexByteSyntax),
        FinalmaskBase64ByteSyntax => t(lang, Key::FinalmaskBase64ByteSyntax),
        FinalmaskUnknownByteSyntax(_) => t(lang, Key::FinalmaskUnknownByteSyntax),
        FinalmaskTransformOpRequired => t(lang, Key::FinalmaskTransformOpRequired),
        FinalmaskTransformArgRequired => t(lang, Key::FinalmaskTransformArgRequired),
        FinalmaskTransformArgExclusive => t(lang, Key::FinalmaskTransformArgExclusive),
        FinalmaskVarNameInvalid => t(lang, Key::FinalmaskVarNameInvalid),
        FinalmaskCustomItemExclusive => t(lang, Key::FinalmaskCustomItemExclusive),
        FinalmaskRandRangeInvalid => t(lang, Key::FinalmaskRandRangeInvalid),
        FinalmaskXmcProfilesRequired => t(lang, Key::FinalmaskXmcProfilesRequired),
        FinalmaskXmcPasswordRequired => t(lang, Key::FinalmaskXmcPasswordRequired),
        FinalmaskXmcUsernameInvalid => t(lang, Key::FinalmaskXmcUsernameInvalid),
        FinalmaskXmcUuidInvalid => t(lang, Key::FinalmaskXmcUuidInvalid),
        FinalmaskXmcTexturesRequired => t(lang, Key::FinalmaskXmcTexturesRequired),
        FinalmaskPacketsFirstNotZero => t(lang, Key::FinalmaskPacketsFirstNotZero),
        FinalmaskPacketsSyntax => t(lang, Key::FinalmaskPacketsSyntax),
        FinalmaskLengthsStartAboveZero => t(lang, Key::FinalmaskLengthsStartAboveZero),
        FinalmaskUnknownTcpMask(_) => t(lang, Key::FinalmaskUnknownTcpMask),
        FinalmaskUdpHeaderModeInvalid => t(lang, Key::FinalmaskUdpHeaderModeInvalid),
        FinalmaskMkcpHeaderInvalid => t(lang, Key::FinalmaskMkcpHeaderInvalid),
        FinalmaskNoisePacketExclusive => t(lang, Key::FinalmaskNoisePacketExclusive),
        FinalmaskSalamanderPacketSize => t(lang, Key::FinalmaskSalamanderPacketSize),
        FinalmaskXdnsDomainRemoved => t(lang, Key::FinalmaskXdnsDomainRemoved),
        FinalmaskXdnsEmpty => t(lang, Key::FinalmaskXdnsEmpty),
        FinalmaskXdnsResolverUdp => t(lang, Key::FinalmaskXdnsResolverUdp),
        FinalmaskXicmpIpInvalid => t(lang, Key::FinalmaskXicmpIpInvalid),
        FinalmaskRealmScheme => t(lang, Key::FinalmaskRealmScheme),
        FinalmaskRealmHostRequired => t(lang, Key::FinalmaskRealmHostRequired),
        FinalmaskRealmTokenBeforeAt => t(lang, Key::FinalmaskRealmTokenBeforeAt),
        FinalmaskRealmIdInPath => t(lang, Key::FinalmaskRealmIdInPath),
        FinalmaskRealmUrlSyntax(_) => t(lang, Key::FinalmaskRealmUrlSyntax),
        FinalmaskRealmStunRequired => t(lang, Key::FinalmaskRealmStunRequired),
        FinalmaskRealmStunFormat => t(lang, Key::FinalmaskRealmStunFormat),
        FinalmaskRealmAllowInsecureRemoved => t(lang, Key::FinalmaskRealmAllowInsecureRemoved),
        FinalmaskRealmFingerprintUnknown => t(lang, Key::FinalmaskRealmFingerprintUnknown),
        FinalmaskRealmAlpnFromMitm => t(lang, Key::FinalmaskRealmAlpnFromMitm),
        FinalmaskRealmCertRequired => t(lang, Key::FinalmaskRealmCertRequired),
        FinalmaskRealmEchKeysBase64 => t(lang, Key::FinalmaskRealmEchKeysBase64),
        FinalmaskUnknownUdpMask(_) => t(lang, Key::FinalmaskUnknownUdpMask),
        // Editor rules that moved into the model pass: the error-list text
        // keeps the existing key (its bytes are the editor's contract).
        SendThroughInvalid => t(lang, Key::SrvSendThroughInvalidShort),
        FreedomFinalRuleInvalid => t(lang, Key::SrvFreedomFinalRuleInvalid),
        DnsRuleActionInvalid => t(lang, Key::SrvDnsRuleActionInvalidShort),
        WireguardRemoteDnsInvalid => t(lang, Key::SrvWgRemoteDnsInvalid),
        // Settings-level verdict rules (validate_settings /
        // validate_profiles). Parameterized rules return the template that
        // validation_issue_message fills with the code-carried values.
        ActiveProfileMissing(_) => t(lang, Key::SettingsActiveProfileMissing),
        ActiveProfileAmbiguous(_, _) => t(lang, Key::SettingsActiveProfileAmbiguous),
        ProfilesRequired => t(lang, Key::SettingsProfilesRequired),
        ProfileIdEmpty(_) => t(lang, Key::SettingsProfileIdEmpty),
        ProfileIdDuplicated(_, _, _) => t(lang, Key::SettingsProfileIdDuplicated),
        ProfileTagEmpty(_, _) => t(lang, Key::SettingsProfileTagEmpty),
        ProfileTagInvalid(_, _, _) => t(lang, Key::SettingsProfileTagInvalid),
        ProfileTagReserved(_, _, _) => t(lang, Key::SettingsProfileTagReserved),
        ProfileTagDuplicated(_, _, _, _, _) => t(lang, Key::SettingsProfileTagDuplicated),
        OutboundChainMissing(_, _) => t(lang, Key::SettingsOutboundChainMissing),
        OutboundChainCycle(_) => t(lang, Key::SettingsOutboundChainCycle),
        BalancerTagMissing(_) => t(lang, Key::SettingsBalancerNoTag),
        BalancerSelectorMissing(_) => t(lang, Key::SettingsBalancerNoSelector),
        BalancerTagDuplicated(_) => t(lang, Key::SettingsBalancerTagDuplicated),
        BalancerFallbackMissing(_, _) => t(lang, Key::SettingsBalancerFallbackMissing),
        LocalInboundAuthRequiresAccounts => t(lang, Key::InboundsAuthRequiresAccounts),
        LocalInboundPortZero(_) => t(lang, Key::SettingsLocalInboundPortZero),
        InboundTagDuplicated(_) => t(lang, Key::SettingsInboundTagDuplicated),
        DokodemoTagMissing(_) => t(lang, Key::SettingsDokodemoTagMissing),
        DokodemoNetworkInvalid(_, _) => t(lang, Key::SettingsDokodemoNetworkInvalid),
        DokodemoUnixSocketRequired(_) => t(lang, Key::SettingsDokodemoUnixSocketRequired),
        DokodemoUnixSocketConflict(_, _, _) => t(lang, Key::SettingsDokodemoUnixSocketConflict),
        DokodemoPortZero(_) => t(lang, Key::SettingsDokodemoPortZero),
        TunIpv4GatewayRequired => t(lang, Key::SettingsTunIpv4GatewayRequired),
        ListenerConflict(_, _, _, _) => t(lang, Key::SettingsListenerConflict),
        RoutingRuleTarget(_, _) => t(lang, Key::SettingsRoutingRuleTarget),
        RoutingRuleOutboundMissing(_, _) => t(lang, Key::SettingsRoutingRuleOutboundMissing),
        RoutingRuleBalancerMissing(_, _) => t(lang, Key::SettingsRoutingRuleBalancerMissing),
        RoutingRuleInboundMissing(_, _) => t(lang, Key::SettingsRoutingRuleInboundMissing),
        DnsServerAddressMissing(_) => t(lang, Key::SettingsDnsServerAddressMissing),
        FakeDnsPoolCidrInvalid(_) => t(lang, Key::SettingsFakeDnsPoolCidrInvalid),
        FakeDnsPoolSizeInvalid(_) => t(lang, Key::SettingsFakeDnsPoolSizeInvalid),
        FakeDnsPoolCapacityExceeded(_, _, _) => t(lang, Key::SettingsFakeDnsPoolCapacityExceeded),
        GeodataUrlInvalid(_) => t(lang, Key::SettingsGeodataUrlInvalid),
        GeodataCronInvalid => t(lang, Key::SettingsGeodataCronInvalid),
    }
}

/// Render a validation finding as `"path: message"` (path omitted when the
/// finding is whole-model). Parameterized rules interpolate their code-carried
/// value into the locale template.
pub fn validation_issue_message(issue: &ValidationIssue, lang: Language) -> String {
    let message = match &issue.code {
        ValidationCode::FinalmaskPortListInvalid(arg)
        | ValidationCode::FinalmaskBytesValueRequired(arg)
        | ValidationCode::FinalmaskUnknownByteSyntax(arg)
        | ValidationCode::FinalmaskRealmUrlSyntax(arg)
        | ValidationCode::FinalmaskQuicBandwidthUnitInvalid(arg)
        | ValidationCode::XhttpExtraShadowsSettings(arg)
        | ValidationCode::RealityFingerprintUntested(arg) => {
            fill_placeholders(validation_message(&issue.code, lang), &[arg])
        }
        ValidationCode::FinalmaskUnknownTcpMask(arg)
        | ValidationCode::FinalmaskUnknownUdpMask(arg) => {
            let rendered = arg
                .as_deref()
                .map(|value| format!("Some({value:?})"))
                .unwrap_or_else(|| "None".into());
            validation_message(&issue.code, lang).replace("{:?}", &rendered)
        }
        // Settings-level verdicts: fill each template with the code-carried
        // values, Debug-quoted exactly where the pre-pass generator used
        // `{:?}`. The inner messages carried by the sniffing/listen codes are
        // their own rules' messages — one text per rule, never re-derived.
        ValidationCode::ActiveProfileMissing(id) => {
            fill_placeholders(validation_message(&issue.code, lang), &[&format!("{id:?}")])
        }
        ValidationCode::ActiveProfileAmbiguous(id, count) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[&format!("{id:?}"), count],
        ),
        ValidationCode::ProfileIdEmpty(index) | ValidationCode::DokodemoTagMissing(index) => {
            fill_placeholders(validation_message(&issue.code, lang), &[index])
        }
        ValidationCode::ProfileIdDuplicated(first, second, id) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[first, second, &format!("{id:?}")],
        ),
        ValidationCode::ProfileTagEmpty(index, id) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[index, &format!("{id:?}")],
        ),
        ValidationCode::ProfileTagInvalid(index, id, tag)
        | ValidationCode::ProfileTagReserved(index, id, tag) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[index, &format!("{id:?}"), &format!("{tag:?}")],
        ),
        ValidationCode::ProfileTagDuplicated(first, first_id, second, second_id, tag) => {
            fill_placeholders(
                validation_message(&issue.code, lang),
                &[
                    first,
                    &format!("{first_id:?}"),
                    second,
                    &format!("{second_id:?}"),
                    &format!("{tag:?}"),
                ],
            )
        }
        ValidationCode::OutboundChainMissing(source, target) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[&format!("{source:?}"), &format!("{target:?}")],
        ),
        ValidationCode::OutboundChainCycle(path) => {
            fill_placeholders(validation_message(&issue.code, lang), &[path])
        }
        ValidationCode::BalancerTagMissing(index)
        | ValidationCode::DnsServerAddressMissing(index)
        | ValidationCode::FakeDnsPoolCidrInvalid(index)
        | ValidationCode::FakeDnsPoolSizeInvalid(index) => {
            fill_placeholders(validation_message(&issue.code, lang), &[index])
        }
        ValidationCode::BalancerSelectorMissing(tag)
        | ValidationCode::BalancerTagDuplicated(tag)
        | ValidationCode::LocalInboundPortZero(tag)
        | ValidationCode::DokodemoUnixSocketRequired(tag)
        | ValidationCode::DokodemoPortZero(tag) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[&format!("{tag:?}")],
        ),
        ValidationCode::BalancerFallbackMissing(tag, fallback) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[&format!("{tag:?}"), &format!("{fallback:?}")],
        ),
        ValidationCode::InboundTagDuplicated(tag) => {
            fill_placeholders(validation_message(&issue.code, lang), &[tag])
        }
        ValidationCode::DokodemoNetworkInvalid(tag, error) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[&format!("{tag:?}"), error],
        ),
        ValidationCode::DokodemoUnixSocketConflict(tag, other, path) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[
                &format!("{tag:?}"),
                &format!("{other:?}"),
                &format!("{path:?}"),
            ],
        ),
        ValidationCode::ListenerConflict(current, other, address, port) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[current, other, address, port],
        ),
        ValidationCode::RoutingRuleTarget(index, error) => {
            fill_placeholders(validation_message(&issue.code, lang), &[index, error])
        }
        ValidationCode::RoutingRuleOutboundMissing(index, tag)
        | ValidationCode::RoutingRuleBalancerMissing(index, tag)
        | ValidationCode::RoutingRuleInboundMissing(index, tag) => fill_placeholders(
            validation_message(&issue.code, lang),
            &[index, &format!("{tag:?}")],
        ),
        ValidationCode::FakeDnsPoolCapacityExceeded(index, size, pool) => {
            fill_placeholders(validation_message(&issue.code, lang), &[index, size, pool])
        }
        ValidationCode::GeodataUrlInvalid(file) => {
            let not_https = t(lang, Key::GeodataUrlNotHttps);
            let args: [&dyn std::fmt::Display; 2] = [file, &not_https];
            fill_placeholders(validation_message(&issue.code, lang), &args)
        }
        ValidationCode::GeodataCronInvalid => {
            let not_five_fields = t(lang, Key::GeodataCronNotFiveFields);
            let args: [&dyn std::fmt::Display; 1] = [&not_five_fields];
            fill_placeholders(validation_message(&issue.code, lang), &args)
        }
        code => validation_message(code, lang).to_string(),
    };
    match &issue.path {
        Some(path) if !path.is_empty() => format!("{path}: {message}"),
        _ => message,
    }
}

/// Message template for one safety hazard; payload-carrying codes return the
/// static template that [`safety_finding_message`] fills with the
/// code-carried value.
pub fn safety_message(code: &SafetyCode, lang: Language) -> &'static str {
    use SafetyCode::*;
    match code {
        SocksListenerExposed(_) => t(lang, Key::SafetySocksListenerExposed),
        HttpListenerExposed(_) => t(lang, Key::SafetyHttpListenerExposed),
        DokodemoListenerExposed(_) => t(lang, Key::SafetyDokodemoListenerExposed),
        TunDnsUnprotected => t(lang, Key::SafetyTunDnsUnprotected),
        BalancerSelectorNoMatch(_) => t(lang, Key::SafetyBalancerSelectorNoMatch),
    }
}

/// Fully rendered message for one safety finding: the template with the
/// code-carried value (the exposed listen address) interpolated. The finding
/// path is deliberately NOT prefixed — callers render the field context
/// themselves (inline placement or dialog rows).
pub fn safety_finding_message(finding: &SafetyFinding, lang: Language) -> String {
    let payload = match &finding.code {
        SafetyCode::SocksListenerExposed(listen)
        | SafetyCode::HttpListenerExposed(listen)
        | SafetyCode::DokodemoListenerExposed(listen) => listen,
        SafetyCode::BalancerSelectorNoMatch(tag) => tag,
        SafetyCode::TunDnsUnprotected => {
            return safety_message(&finding.code, lang).to_string();
        }
    };
    fill_placeholders(safety_message(&finding.code, lang), &[payload])
}

/// Render the first finding whose wire path matches `path` (None when
/// absent) — the shared inline-warning seam consumed by every warning
/// surface; the caller places the message next to the offending field.
pub fn safety_message_for_path(
    findings: &[SafetyFinding],
    path: &str,
    lang: Language,
) -> Option<String> {
    findings
        .iter()
        .find(|finding| finding.path == path)
        .map(|finding| safety_finding_message(finding, lang))
}

/// Hazard class label for dialog and inline summaries.
pub fn hazard_class_label(class: HazardClass, lang: Language) -> &'static str {
    match class {
        HazardClass::Exposure => t(lang, Key::HazardClassExposure),
        HazardClass::Privacy => t(lang, Key::HazardClassPrivacy),
        HazardClass::Breakage => t(lang, Key::HazardClassBreakage),
    }
}

/// English locale table — the fallback locale, and the only one shipping now.
mod en {
    use super::Key;

    pub(super) fn table(key: Key) -> &'static str {
        match key {
            Key::Language => "Language",
            Key::LanguageEnglish => "English",
            Key::Theme => "Theme",
            Key::ThemeSystem => "System",
            Key::ThemeSystemHint => "Follows the Windows light/dark setting",
            Key::ThemeDark => "Dark",
            Key::ThemeDarkHint => "Dark background, light text",
            Key::ThemeLight => "Light",
            Key::ThemeLightHint => "Light background, dark text",
            Key::AccentColor => "Accent color",
            Key::AccentColorReset => "Reset",
            Key::AccentColorResetHint => "Restore egui's stock accent for both themes",
            Key::AccentColorHint => "Applies to both dark and light themes, including System mode.",
            // Shared copy used by several screens.
            Key::Servers => "Servers",
            Key::Preview => "Preview",
            Key::Tun => "TUN",
            Key::Off => "Off",
            Key::Close => "Close",
            Key::Cancel => "Cancel",
            Key::Delete => "Delete",
            Key::DeleteServer => "Delete server",
            Key::CopyLink => "Copy link",
            Key::Generate => "Generate",
            Key::Remove => "Remove",
            Key::Enabled => "enabled",
            Key::UserLevel => "user level",
            Key::PortLower => "port",
            Key::AddressLower => "address",
            Key::Ips => "IPs",
            Key::ValueLower => "value",
            Key::HeaderHint => "Header",
            Key::ValueHint => "value",
            Key::EmDash => "—",
            Key::DeleteRow => "🗑",
            Key::ProbeRow => "⚡",
            Key::AddRow => "+ Add",
            Key::AddKvRow => "+ Add row",
            Key::InvalidJson => "invalid JSON: {}",
            Key::RuntimeChannelClosed => "The runtime command channel is closed.",
            Key::WorkerExitedWithoutResult => "background worker exited without a result",
            Key::InvalidGoDuration => "invalid Go duration (for example 10s, 500ms)",
            Key::InvalidGoDurationShort => "invalid Go duration",
            Key::WaitingForXray => "Waiting for Xray",
            Key::WaitingForXrayEllipsis => "Waiting for Xray…",
            Key::OperationInProgress => "A lifecycle/update operation is running.",
            Key::LatencyMs => "{} ms",
            Key::Dead => "dead",
            Key::LatencyTimeout => "timeout",
            Key::NotInstalled => "not installed",
            // Screen labels (nav sidebar + headings).
            Key::ScreenDashboard => "Dashboard",
            Key::ScreenServers => "Servers",
            Key::ScreenProfilePreview => "Preview",
            Key::ScreenRouting => "Routing",
            Key::ScreenDns => "DNS",
            Key::ScreenInbounds => "Inbounds",
            Key::ScreenLogs => "Logs",
            Key::ScreenSettings => "Settings",
            Key::ScreenAbout => "About",
            Key::ScreenTun => "TUN",
            // Phase action labels (top bar, dashboard, tray).
            Key::PhaseConnect => "Connect",
            Key::PhaseDisconnect => "Disconnect",
            Key::PhaseCancelRetry => "Cancel retry",
            // Core-setup shared surface (Settings → Updates, first-run wizard).
            Key::CoreSetupDownloading => "Downloading…",
            Key::CoreSetupFailed => "Setup failed",
            Key::CoreSetupInstalled => "Installed",
            Key::CoreSetupNotInstalled => "Not installed",
            Key::CoreSetupFirstUseHint => "The Xray core downloads on first use.",
            Key::CoreSetupXrayCore => "Xray core",
            Key::CoreSetupPinnedRelease => "Pinned release:",
            Key::CoreSetupOpenReleaseHint => {
                "Opens the official Xray core release download in your browser"
            }
            Key::CoreSetupArchiveSep => "· {}",
            Key::CoreSetupCopyLink => "Copy link",
            Key::CoreSetupStopFirst => "Stop the core before replacing managed Xray files.",
            Key::CoreSetupBusy => "Another lifecycle or core operation is already running.",
            Key::CoreSetupDownloadButton => "Download pinned release",
            Key::CoreSetupImportZip => "Import ZIP…",
            Key::CoreSetupHint => {
                "Download the exact pinned release above, or import the ZIP from another \
                 device when GitHub is unreachable."
            }
            Key::CoreSetupProgress => "{} — {}/{} bytes",
            Key::CoreSetupInstalledVersion => "Xray core {} installed",
            Key::CoreSetupHealthCheck => "health check…",
            Key::CoreSetupContinue => "Continue",
            Key::CoreSetupContinueDisabled => {
                "The installed core has not finished its health check"
            }
            Key::CoreSetupFailedError => "Xray core setup failed: {}",
            Key::CoreSetupSetUpLater => "Set up later",
            Key::CoreSetupLaterDisabled => "You cannot cancel the active core operation here",
            Key::LatencyRequiresProfile => "Latency test requires at least one server",
            Key::LatencyCoreUnavailable => "Latency test failed: core runtime is unavailable",
            Key::LatencyFeedbackComplete => "Latency test complete for {} outbound(s).",
            Key::LatencyFeedbackPartial => {
                "Latency test complete: received {} of {} requested outbound status(es)."
            }
            Key::LatencyFeedbackFailed => "Latency test failed: {}",
            Key::LatencyProbeOneResponded => "Server '{}' responded in {} ms.",
            Key::LatencyProbeOneDead => "Server '{}' did not respond.",
            Key::LatencyProbeOneFailed => "Latency test of '{}' failed: {}.",
            Key::LatencyProbeOneDeadReason => "Server '{}' did not respond: {}.",
            Key::LatencyProbeOneDeadAt => "Server '{}' ({}) did not respond.",
            Key::LatencyProbeOneDeadAtReason => "Server '{}' ({}) did not respond: {}.",
            Key::LatencyFeedbackPartialWarn => "{} of {} outbounds responded.",
            // App shell: phase badge, mode label, top-bar status strip, tray.
            Key::AppPhaseStopped => "Stopped",
            Key::AppPhaseNoConfig => "No config yet",
            Key::AppPhaseStarting => "Starting…",
            Key::AppPhaseRunning => "Running",
            Key::AppPhaseRetrying => "Retrying (attempt {})",
            Key::AppPhaseError => "Error: {}",
            Key::ModeOff => "off",
            Key::ModeTun => "TUN",
            Key::TrayShow => "Show broccoli",
            Key::TrayConnectDisconnect => "Connect / Disconnect",
            Key::TrayQuit => "Quit",
            Key::TrayTooltipStopped => "broccoli — Stopped",
            Key::TopbarMode => "mode: {}",
            Key::TopbarActiveServer => "server: {}",
            Key::TopbarCoreNotInstalled => "Xray core not installed",
            Key::TopbarChangesPending => "changes pending",
            Key::TopbarServerEditsUnsaved => "Server edits not saved",
            Key::TopbarApplyNow => "Apply now",
            Key::ApplyResultOk => "Configuration applied",
            Key::ApplyResultFailed => "Configuration apply failed",
            Key::TopbarConfigInvalid => "configuration invalid",
            Key::TopbarSettingsNotSaved => "settings not saved",
            Key::TopbarRetrySave => "Retry save",
            Key::TopbarOpenStateFolder => "Open state folder",
            // Topbar right edge: xray core + broccoli app versions.
            Key::TopbarXrayAppVersions => "Xray core {} · app {}",
            Key::TopbarAppVersion => "app {}",
            Key::TopbarStateLoadFailed => "the app could not load the state file",
            Key::AppOperationInProgress => "{} operation in progress",
            Key::LogCoreError => "[broccoli] core error: {}",
            Key::LogConnectBlocked => "[broccoli] connect blocked: {}",
            Key::LogDisconnectBlocked => "[broccoli] disconnect blocked: {}",
            Key::LogBroccoliMessage => "[broccoli] {}",
            Key::LogOpenStateFolderFailed => "[broccoli] failed to open state folder: {}",
            Key::CreateProfileDirsFailed => "failed to create profile directories: {}",
            Key::SaveServersFailed => "failed to save servers.json: {}",
            Key::SaveSettingsFailed => "failed to save settings.json: {}",
            Key::ApplyResultUnsaved => "Runtime result cannot settle unsaved settings: {}\n{}",
            Key::ApplyResultOlder => {
                "An older runtime apply succeeded, but newer changes remain \
                 pending\n{}"
            }
            Key::RollbackRestored => {
                "Candidate failed. The app restored the last-good configuration: {}"
            }
            Key::RollbackFailed => "Candidate and rollback failed: {}",
            Key::ConnectBlockedSave => "Save pending settings before connecting: {}",
            Key::ConnectBlockedRawMode => {
                "Raw Override can run only in Off mode. Disable TUN before connecting."
            }
            Key::ConnectBlockedInstallCore => "Install the managed Xray core before connecting",
            Key::ConnectBlockedOperation => "Wait for the current {} operation to finish",
            Key::GenerationFailed => "Configuration generation failed: {}",
            Key::CoreRuntimeUnavailable => "Core runtime is unavailable",
            Key::StateFileLoadFailed => "Could not load {}: {}",
            Key::ApplyBlockedNotSaved => "Settings are not saved: {}",
            Key::ApplyBlockedOperation => "Runtime {} operation is running",
            Key::RawOverrideOffMode => {
                "Raw Override can run only in Off mode. Disable TUN before applying."
            }
            Key::RawOverrideDefineApi => {
                "Raw Override must define api.listen as a loopback address with StatsService enabled"
            }
            Key::RawOverrideStatsService => {
                "Raw Override api.services must include StatsService so the app can verify readiness"
            }
            Key::RawOverrideNoTun => {
                "Raw Override may not define a TUN inbound. The app manages the elevated TUN \
                 lifecycle."
            }
            // Tray tooltip (icon presentation).
            Key::IconTooltipError => "broccoli — Error. Open broccoli for details.",
            Key::IconTooltipCoreRunning => "broccoli — Xray core running",
            Key::IconTooltipTun => "broccoli — TUN active",
            // First-run wizard.
            Key::WizardWelcome => "Welcome to broccoli",
            Key::WizardCoreMissing => "The Xray core (xray.exe) is not installed yet.",
            // About screen.
            Key::AboutBroccoliVersion => "broccoli {}",
            Key::AboutTagline => "A Windows GUI client for Xray core.",
            Key::AboutCoreVersion => "Xray core: {}",
            Key::AboutCoreNotInstalled => {
                "Xray core: not installed. Use Settings → Updates to download it."
            }
            Key::AboutUpstreamLink => "Xray core upstream — github.com/XTLS/Xray-core",
            Key::AboutRepoLink => "broccoli repository and releases",
            Key::AboutLicenses => "Licenses",
            Key::AboutLicenseXray => {
                "• Xray core is licensed under the Mozilla Public License 2.0 (MPL-2.0)."
            }
            Key::AboutLicenseWintun => {
                "• wintun.dll is © WireGuard LLC and distributed under its own license."
            }
            Key::AboutLicenseTexts => {
                "License texts (LICENSE, LICENSE-Wintun) ship in the core directory: {}"
            }
            Key::AboutBuiltWith => {
                "Built with eframe/egui, tokio, tonic, and many other open-source crates."
            }
            // TUN screen.
            Key::TunBadgeElevated => "running as administrator",
            Key::TunBadgeNotElevated => {
                "not elevated. TUN starts through the helper (one UAC prompt)."
            }
            Key::TunBadgeHelperActive => "TUN runs in the elevated helper.",
            Key::TunExplain => {
                "TUN creates a virtual adapter (wintun) and routes all system traffic through the \
                 core. It requires wintun.dll next to xray.exe."
            }
            Key::TunDnsListenerNote => {
                "With a DNS module, the adapter's DNS points at the first IPv4 gateway. The app adds \
                 the in-tun DNS listener that answers those queries to the running core once the \
                 adapter is up. That happens a moment after the core starts. It is not part of the \
                 generated configuration."
            }
            Key::TunEnableCheckbox => "enable TUN inbound",
            Key::TunRestartHint => "the core restarts through the elevated helper when you apply",
            Key::TunSectionIdentity => "Identity",
            Key::TunIfaceNameLabel => "interface name",
            Key::TunDescLabel => "description",
            Key::TunMtuLabel => "MTU",
            Key::TunSectionGateways => "Gateways",
            Key::TunGatewaysLabel => "gateways",
            Key::TunSectionAutoRoutes => "Auto routes",
            Key::TunAutoRoutingTableLabel => "auto system routing table",
            Key::TunAutoOutboundsLabel => "auto outbounds interface",
            Key::TunAutoOutboundsHint => {
                "Not recommended on machines with multiple network adapters: 'auto' may pick an \
                 adapter without internet access. Prefer the adapter your network actually uses."
            }
            Key::TunSectionIfaces => "Current network interfaces",
            Key::TunAutoOutboundsDown => {
                "'{0}' is down, so no traffic can leave it. Pick an active interface or 'auto'."
            }
            Key::TunAutoOutboundsMissing => {
                "'{0}' no longer exists. Pick an active interface or 'auto'."
            }
            // Dashboard screen.
            Key::DashboardNetworkMode => "Network mode:",
            Key::DashboardLocalEndpoints => "Local endpoints",
            Key::DashboardEndpointHint => {
                "Local loopback listeners. Point other applications at these."
            }
            Key::LocalStatusUp => "up",
            Key::LocalStatusDown => "down",
            Key::LocalStatusDisabled => "disabled",
            Key::LocalStatusStarting => "starting",
            Key::TunStatusActive => "active",
            Key::TunStatusElevation => "elevation needed",
            Key::TunStatusOff => "off",
            Key::EndpointRow => "{} {} {}",
            Key::TunStatus => "TUN: {}",
            Key::DashboardTunHoverElevated => "Routes all traffic through the core",
            Key::DashboardTunHoverNotElevated => {
                "Routes all traffic. Starts the elevated helper (one UAC prompt)."
            }
            Key::DashboardActiveServer => "Active server:",
            Key::NoneSelected => "(none)",
            Key::DashboardRateUp => "↑ {}/s",
            Key::DashboardRateDown => "↓ {}/s",
            Key::DashboardUptime => "uptime {}",
            Key::DashboardGoroutines => "goroutines {}",
            Key::DashboardNoStatsStarting => "core is starting. Waiting for the first sample.",
            Key::DashboardNoStatsRunning => "core is running. No sample received yet.",
            Key::DashboardNoStatsStopped => "core stopped",
            Key::DashboardNoStatsNoConfig => {
                "no configuration yet. Connect generates the initial configuration."
            }
            Key::DashboardNoStatsBackoff => "core restart pending. No live sample.",
            Key::DashboardNoStatsError => "core error. No live sample.",
            Key::DashboardPlotSecondsAgo => "seconds ago",
            Key::DashboardPlotBytesPerSec => "B/s",
            Key::PlotUp => "up",
            Key::PlotDown => "down",
            Key::DashboardNoServers => "No servers yet. Add one on the Servers screen.",
            Key::GridName => "name",
            Key::GridTag => "tag",
            Key::GridLatency => "latency",
            Key::GridDetail => "detail",
            Key::HealthPingSummary => {
                "burst avg {} ms · min {} · max {} · ±{} · {} of {} pings failed"
            }
            Key::DashboardDownloadProgress => "{} ({}/{}) B",
            Key::DashboardDownloadFailed => "download failed: {}",
            Key::ConnectUnavailable => "Connect is temporarily unavailable",
            Key::DashboardPhaseStopped => "Stopped",
            Key::DashboardPhaseNoConfig => "No config yet",
            Key::DashboardPhaseStarting => "Starting",
            Key::DashboardPhaseRunning => "Running",
            Key::DashboardPhaseRetry => "Retry #{}",
            Key::DashboardPhaseError => "Error: {}",
            // Logs screen.
            Key::LogsLevelAll => "All",
            Key::LogsLevelInfoPlus => "Info+",
            Key::LogsLevelWarningPlus => "Warning+",
            Key::LogsLevelErrorPlus => "Error+",
            Key::LogsLevelLabel => "Level:",
            Key::LogsFilterLabel => "Filter:",
            Key::LogsFilterHint => "contains",
            Key::LogsAutoscroll => "Autoscroll",
            Key::LogsCopyAll => "Copy all",
            Key::LogsCopySelection => "Copy selection",
            Key::LogsClearView => "Clear view",
            Key::LogsClearViewHint => {
                "Hides current lines in this view. The log buffer keeps them."
            }
            Key::LogsOpenFolder => "Open logs folder",
            Key::LogsOpenFolderFailed => "failed to open logs folder: {}",
            Key::LogsRestartLogger => "Restart Xray logger",
            Key::LogsRestartLoggerHint => {
                "Closes and reopens Xray's configured log outputs. It does not clear logs."
            }
            Key::LogsRestartDisabledNotRunning => "Start the core before restarting its logger",
            Key::LogsRestartDisabledBusy => "Wait for the lifecycle/update operation to finish",
            Key::LogsRestarting => "Restarting Xray logger…",
            Key::LogsLineCount => "{} of {} lines",
            Key::LogsRestartFeedbackOk => {
                "Xray restarted its logger and reopened the configured log outputs."
            }
            // Profile preview screen.
            Key::PreviewNoLaunch => {
                "The app has not started an Xray configuration in this session."
            }
            Key::PreviewCredentialsWarning => {
                "This is the exact Xray config and may contain credentials."
            }
            Key::PreviewActiveConfig => "Active Xray configuration",
            Key::PreviewLoadFailed => {
                "The core started, but the app could not load the active configuration: {}"
            }
            Key::PreviewPhaseStarting => "Configuration launched. Waiting for core readiness.",
            Key::PreviewPhaseRunning => "The running core uses this configuration.",
            Key::PreviewPhaseBackoff => {
                "Configuration from the current core session. Restart pending."
            }
            Key::PreviewPhaseNoConfig => {
                "No configuration yet. Connect generates the initial configuration."
            }
            Key::PreviewPhaseStopped => "The most recent core start used this configuration.",
            // DNS screen.
            Key::DnsSectionServers => "DNS servers (queried in order)",
            Key::DnsPriorityHint => "DNS priority (lower is queried first)",
            Key::DnsMoveUp => "Move up (query earlier)",
            Key::DnsMoveDown => "Move down (query later)",
            Key::DnsNoAddress => "(no address)",
            Key::DnsDomainsCount => "domains: {} +",
            Key::DnsEditServer => "Edit server",
            Key::DnsAddServer => "+ Add DNS server",
            Key::DnsSectionHosts => "Hosts (static DNS overrides)",
            Key::DnsHostsKeyHint => "domain (full:example.com)",
            Key::DnsHostsValueHint => "one or more IPs or another domain",
            Key::DnsSectionGlobal => "Global",
            Key::DnsClientIp => "Client IP (EDNS)",
            Key::DnsClientIpHint => "203.0.113.1 — the address upstream servers see",
            Key::DnsBootstrapLabel => "Proxy-server resolver (local DNS)",
            Key::DnsBootstrapHint => {
                "The app resolves the server domains of the direct-dial outbounds with this \
                 endpoint. The app dials this endpoint directly, outside the tunnel. Enter an \
                 endpoint with an IP address, for example https://223.5.5.5/dns-query or \
                 223.5.5.5, or 'localhost' for the OS resolver. Leave it empty to derive the \
                 endpoint from the first DNS server."
            }
            Key::DnsTag => "Tag",
            Key::DnsTagHint => "route DNS traffic through routing rules",
            Key::DnsQueryStrategy => "Query strategy",
            Key::DnsDisableCache => "Disable cache",
            Key::DnsDisableFallback => "Disable fallback",
            Key::DnsDisableFallbackIfMatched => "Disable fallback if matched",
            Key::DnsSkipFallbackHint => "Skip fallback for queries matched by a server's domains",
            Key::DnsServeStale => "Serve stale",
            Key::DnsServeStaleHint => "Reply with expired cache entries while refreshing",
            Key::DnsParallelQueries => "Parallel queries",
            Key::DnsUseSystemHosts => "Use system hosts file",
            Key::DnsServeExpiredTtl => "Serve expired TTL (s)",
            Key::DnsSectionFakedns => "FakeDNS",
            Key::DnsEnableFakedns => "Enable fakeDNS",
            Key::DnsFakednsExplain => {
                "When enabled, the generator adds the fakeDNS pool(s), a fakedns DNS server entry, \
                 and 'fakedns' in every sniffing destOverride to the generated config."
            }
            Key::DnsPoolTitle => "Pool {}",
            Key::DnsIpPool => "IP pool",
            Key::DnsPoolCidrRequired => "pool CIDR is required",
            Key::DnsPoolCidrInvalid => {
                "must be an IP CIDR range, for example 198.18.0.0/15 or fc00::/18"
            }
            Key::DnsPoolSize => "Pool size",
            Key::DnsAddPool => "+ Add pool",
            Key::DnsAddress => "Address",
            Key::DnsAddressHint => {
                "1.1.1.1, https://dns.google/dns-query, quic+local://, tcp://, hosts path, fakedns"
            }
            Key::DnsAddressRequired => "DNS server address is required",
            Key::DnsPort => "Port",
            Key::DnsDomains => "Domains",
            Key::DnsDomainsHint => "route matching domains to this server",
            Key::DnsExpectedIps => "Expected IPs",
            Key::DnsExpectedIpsHint => "geoip:cn, 1.2.3.0/24 — * = priority mode",
            Key::DnsUnexpectedIps => "Unexpected IPs",
            Key::DnsUnexpectedIpsHint => "The core rejects answers with these.",
            Key::DnsClientIpOverride => "override per server",
            Key::DnsTagOutbound => "outbound tag for queries",
            Key::DnsSkipFallback => "Skip fallback",
            Key::DnsFinalQuery => "Final query",
            Key::DnsTimeoutRequired => "Timeout is required.",
            Key::DnsTimeoutInteger => "Timeout must be a decimal integer.",
            Key::DnsTimeoutRange => "Timeout must not exceed 18446744073709551615.",
            Key::DnsTimeoutMs => "Timeout (ms)",
            Key::DnsTimeoutHint => "0..=18446744073709551615 (default 8000)",
            Key::DnsTimeoutDefault => "default 8000",
            Key::DnsSchemeDefault => "(scheme default)",
            Key::Inherit => "(inherit)",
            Key::BoolFalse => "false",
            Key::BoolTrue => "true",
            // Inbounds screen.
            Key::InboundsPostureWarn => {
                "SOCKS/HTTP are unencrypted. Keep non-loopback listeners off the public internet. \
                 Windows may prompt about firewall rules on first LAN bind."
            }
            Key::InboundsListenAddress => "listen address",
            Key::InboundsUdpSupport => "UDP support",
            Key::InboundsUdpRelayIp => "UDP relay IP",
            Key::InboundsUdpRelayIpHint => "blank = core default",
            Key::InboundsUdpWildcardHint => {
                "UDP on a wildcard listen may answer from the wrong source address on multi-IP \
                 hosts. Set a specific listen address or a UDP relay IP."
            }
            Key::InboundsRequireAuth => "require authentication",
            Key::InboundsAuthRequiresAccounts => {
                "HTTP inbound requires authentication but has no accounts. Add an account or turn \
                 off require authentication."
            }
            Key::InboundsSectionDokodemo => "Dokodemo-door (transparent forwarding)",
            Key::InboundsStableTagHint => "Stable inbound tag",
            Key::InboundsDeleteDokodemo => "Remove dokodemo inbound",
            Key::InboundsUsedByRules => {
                "{reference_count} routing rule(s) use this inbound tag. Remove those references \
                 first."
            }
            Key::InboundsDeleteBlocked => {
                "Remove blocked: {reference_count} routing rule(s) use the stable tag."
            }
            Key::InboundsUnixPath => "UNIX socket path",
            Key::InboundsUnixHint => {
                "Xray's receiver accepts either one UNIX path or an IP/port envelope, so you cannot \
                 mix UNIX with TCP or UDP in one inbound."
            }
            Key::InboundsListenPort => "listen port",
            Key::InboundsImportedHint => {
                "The app preserves the imported mode. Both endpoint values remain editable until you \
                 select a supported listener mode."
            }
            Key::InboundsTargetAddress => "target address",
            Key::InboundsTargetAddressHint => "8.8.8.8 or example.com",
            Key::InboundsTargetPort => "target port",
            Key::SafetySocksListenerExposed => {
                "SOCKS listener on {} requires no authentication and accepts connections \
                 beyond loopback."
            }
            Key::SafetyHttpListenerExposed => {
                "HTTP listener on {} requires no authentication and accepts connections \
                 beyond loopback."
            }
            Key::SafetyDokodemoListenerExposed => {
                "dokodemo-door listener on {} is open beyond loopback (it has no \
                 authentication)."
            }
            Key::SafetyTunDnsUnprotected => {
                "TUN mode has no DNS configuration. The adapter falls back to plaintext \
                 1.1.1.1/8.8.8.8 and DNS is not intercepted."
            }
            Key::SafetyBalancerSelectorNoMatch => {
                "Balancer {} has no selector that matches any outbound tag. The balancer cannot \
                 carry traffic."
            }
            Key::HazardClassExposure => "Exposure",
            Key::HazardClassPrivacy => "Privacy",
            Key::HazardClassBreakage => "Breakage",
            // Apply-gate hazard acknowledgment dialog.
            Key::SafetyAckTitle => "Safety hazards found",
            Key::SafetyAckExplanation => {
                "The app starts the listeners below as-is when you apply, so they accept connections \
                 beyond this PC. The app asks you to confirm on every apply while these hazards \
                 remain."
            }
            Key::SafetyAckApplyAnyway => "Apply anyway",
            Key::InboundsPortMap => "port map (source port → target host:port):",
            Key::InboundsAddPortMapping => "+ port mapping",
            Key::InboundsAddDokodemo => "+ Add dokodemo-door",
            Key::InboundsListener => "listener:",
            Key::InboundsModeTcp => "TCP",
            Key::InboundsModeUdp => "UDP",
            Key::InboundsModeTcpUdp => "TCP + UDP",
            Key::InboundsPreserveImported => "Preserve imported {:?}",
            Key::InboundsPreserveImportedHint => "Leave the imported network string unchanged",
            Key::InboundsImportedUnsupported => {
                "Imported network {:?} is unsupported: {}. The app preserves it until you select a \
                 supported mode."
            }
            Key::ListenerLabelSocks => "SOCKS",
            Key::ListenerLabelHttp => "HTTP",
            Key::ListenerLabelDokodemo => "dokodemo {}",
            // Local listeners list: user-managed SOCKS/HTTP endpoints.
            Key::LocalListeners => "Local listeners",
            Key::AddSocks => "Add SOCKS",
            Key::AddHttp => "Add HTTP",
            Key::RemoveEndpoint => "Remove",
            Key::EndpointProtocolSocks => "SOCKS",
            Key::EndpointProtocolHttp => "HTTP",
            Key::EmptyLocalListeners => "No local listeners configured",
            Key::CollisionInvalidNetwork => "{} has an invalid listener network: {}",
            Key::CollisionNeedsPort => "{} needs a non-zero listen port",
            Key::CollisionNeedsUnix => "{} needs a UNIX socket path",
            Key::CollisionEndpoint => "UNIX socket {path:?}",
            Key::CollisionConflict => "{} conflicts with {} on {}",
            Key::DokodemoTagMissing => "stable inbound tag is missing",
            Key::DokodemoTagBuiltin => "inbound tag {tag:?} conflicts with a built-in listener",
            Key::DokodemoTagDuplicate => "duplicate inbound tag {tag:?}",
            Key::Accounts => "accounts:",
            Key::AccountUserHint => "user",
            Key::AccountPasswordHint => "password",
            Key::AddAccount => "+ account",
            Key::SniffingSection => "sniffing",
            Key::SniffingDestOverride => "destOverride:",
            Key::SniffingFakednsHint => "the generator injects this while fakeDns is on",
            Key::SniffingDomainsExcluded => "domains excluded",
            Key::SniffingIpsExcluded => "IPs excluded",
            Key::SniffingMetadataOnly => "metadata only",
            Key::SniffingRouteOnly => "route only (sniffed name used for routing, not dialing)",
            // Routing screen.
            Key::GeodataAddGeosite => "Add geosite…",
            Key::GeodataAddGeoip => "Add geoip…",
            Key::RoutingRulesSection => "Rules (first match wins)",
            Key::RoutingMoveUp => "Move up (rules match in order)",
            Key::RoutingMoveDown => "Move down",
            Key::RoutingDeleteRule => "Remove rule",
            Key::RoutingEditRule => "Edit rule",
            Key::RoutingNoTarget => "→ (no target)",
            Key::RoutingTargetArrow => "→ {}",
            Key::RoutingNoRules => "No rules. Everything goes to the active server.",
            Key::RoutingAddRule => "+ Add rule",
            Key::RuleTag => "Rule tag",
            Key::RuleTagHint => "Auto-id used by runtime AddRule/RemoveRule",
            Key::Network => "Network",
            Key::Domains => "Domains",
            Key::DomainsHint => "geosite:cn, domain:example.com, full:, regexp:, keyword:",
            Key::IpsHint => "geoip:cn, 1.2.3.0/24",
            Key::Port => "Port",
            Key::PortHint => "53, 1000-2000",
            Key::SourcePort => "Source port",
            Key::SourcePortHint => "PortList",
            Key::LocalPort => "Local port",
            Key::LocalPortHint => "PortList (TUN inbound)",
            Key::RoutingPortListInvalid => {
                "must be comma-separated ports or port ranges (each 0-65535), for example \
                 80,443,1000-2000"
            }
            Key::RoutingIpListInvalid => {
                "must be IP addresses, CIDR ranges, or geoip: tags, for example 1.2.3.4, \
                 10.0.0.0/24, geoip:cn"
            }
            Key::InboundTags => "Inbound tags",
            Key::InboundTagsHint => "in-socks, in-http, in-doko-0, in-tun",
            Key::SourceIps => "Source IPs",
            Key::SourceIpsHint => "geoip:cn, 1.2.3.0/24 (source side)",
            Key::LocalIps => "Local IPs",
            Key::LocalIpsHint => "geoip / CIDR (interface IPs)",
            Key::Protocols => "Protocols",
            Key::ProtocolsHint => "http, tls, quic, bittorrent, fakedns",
            Key::Processes => "Processes",
            Key::ProcessesHint => "chrome.exe — xray/ = self path, self/ = self PID",
            Key::LocalOs => "Local OS",
            Key::LocalOsHint => {
                "windows, darwin, linux — matches the machine's OS, case-insensitive"
            }
            Key::VlessRoute => "VLESS route",
            Key::VlessRouteHint => "PortList — VLESS routing marker",
            Key::Attrs => "Attrs (HTTP sniff header regexps)",
            Key::AttrsKeyHint => "header (for example :path)",
            Key::AttrsValueHint => "regexp",
            Key::WebhookOnMatch => "Webhook on match",
            Key::WebhookOnMatchHint => "POST a notification when this rule matches",
            Key::Url => "URL",
            Key::UrlHint => "https://example.com",
            Key::Deduplication => "Deduplication (s)",
            Key::Headers => "Headers",
            Key::HeadersKeyHint => "header",
            Key::HeadersValueHint => "value",
            Key::Target => "Target",
            Key::Outbound => "Outbound",
            Key::Balancer => "Balancer",
            Key::BalancerNeededHint => "Add a valid balancer before targeting one",
            Key::NoBalancers => "No balancers defined. Add one below.",
            Key::UseDirect => "Use direct",
            Key::GeodataLoaderFailed => "Could not start geodata loader: {}",
            Key::GeodataLoaderStopped => "Geodata loader stopped before returning a result.",
            Key::GeodataLoading => "Loading…",
            Key::GeodataRefresh => "Refresh",
            Key::GeodataRefreshBusy => "A geodata refresh is already running",
            Key::GeodataReading => "Reading managed geodata files…",
            Key::GeodataCodesBytes => "{} codes · {} bytes",
            Key::GeodataModified => "{}\nModified: {}",
            Key::GeodataModifiedUnavailable => "unavailable",
            Key::GeodataSearch => "Search codes…",
            Key::GeodataNoMatches => "No matching codes.",
            Key::RuntimeStateRefreshed => "Runtime state refreshed.",
            Key::RuntimeOverrideTitle => "Runtime override",
            Key::RuntimeOverrideEphemeral => {
                "Ephemeral Xray state: any core or configuration restart resets this override."
            }
            Key::RuntimeOverrideScopeHint => {
                "The core knows only the balancers of the configuration it runs. Apply the \
                 configuration after you change a balancer."
            }
            Key::CurrentOverride => "Current override: {}",
            Key::CurrentOverrideNone => {
                "Current override: none. The configured strategy is active."
            }
            Key::PrincipleTargets => "Principle targets: {}",
            Key::PrincipleTargetsNone => "Principle targets: none reported",
            Key::PrincipleTargetsHidden => "Principle targets: not exposed by this strategy",
            Key::RuntimeStateNotRefreshed => "The app has not refreshed the runtime state.",
            Key::CoreNotRunningControls => "Core is not running. Runtime controls are unavailable.",
            Key::RefreshRuntimeState => "Refresh runtime state",
            Key::KnownOutbound => "Known outbound",
            Key::CustomExactTag => "Custom exact tag",
            Key::ExactOutboundTag => "exact outbound tag",
            Key::ApplyTarget => "Apply target",
            Key::ApplyTargetDisabledEmpty => {
                "Choose or enter a non-empty exact target. Clear override handles the empty value."
            }
            Key::ApplyTargetDisabledBusy => "Start the core and wait for current work to finish",
            Key::ClearOverride => "Clear override",
            Key::BalancersSection => "Balancers",
            Key::Untagged => "(untagged)",
            Key::BalancerStrategy => "strategy: {}",
            Key::BalancerSelector => "selector: {}",
            Key::DeleteBalancer => "Remove balancer",
            Key::BalancerUsedBy => {
                "{} routing rule(s) use this balancer. Retarget those rules first."
            }
            Key::EditBalancer => "Edit balancer",
            Key::BalancerDeleteBlocked => {
                "Remove blocked: {} routing rule(s) reference this balancer."
            }
            Key::AddBalancer => "+ Add balancer",
            Key::AddBalancerDisabled => "Add a server before creating a balancer",
            Key::Tag => "Tag",
            Key::BalancerNameHint => "balancer name",
            Key::TagRequired => "tag is required",
            Key::TagDuplicate => "tag is already used by another balancer",
            Key::SetTag => "Set tag",
            Key::RenameUpdateRules => "Rename and update rules",
            Key::TagUniqueHint => "Enter a unique tag different from the current balancer tag",
            Key::Selectors => "Selectors",
            Key::SelectorsHint => "srv- matches outbound tags by prefix",
            Key::SelectorRequired => "at least one outbound selector is required",
            Key::SelectAllServers => "Select all servers",
            Key::StrategyLabel => "Strategy",
            Key::RequiresObservatory => {
                "Requires the observatory (below). The app emits it automatically."
            }
            Key::Fallback => "Fallback",
            Key::Costs => "Costs (per-outbound weights)",
            Key::MatchRegexpHint => "match is a regexp",
            Key::Match => "Match",
            Key::MatchHint => "outbound tag (prefix)",
            Key::Weight => "Weight",
            Key::AddCost => "+ Add cost",
            Key::Baselines => "Baselines",
            Key::BaselinesHint => "1s, 500ms — RTT baselines per cost",
            Key::MaxRtt => "Max RTT",
            Key::InvalidGoDurationExample => "invalid Go duration (for example 1s, 500ms)",
            Key::ExpectedNodes => "Expected nodes",
            Key::ExpectedSpeedMode => "Expected ≤ 0 = speed-priority mode",
            Key::Tolerance => "Tolerance",
            Key::Auto => "(auto)",
            Key::ObservabilitySection => "Observability",
            Key::DomainStrategy => "Domain strategy",
            Key::ObservatoryLatencyProbing => "Observatory (latency probing)",
            Key::ObservatoryEmitted => {
                "The app emits the observatory while it is enabled, and automatically when a \
                 balancer needs live health data."
            }
            Key::ObservatoryForcedByBalancer => {
                "A balancer that needs live health data emits this for every server, so there is no \
                 subject selector to set."
            }
            Key::BurstObservatoryHint => {
                "Alternative health engine with windowed ping statistics instead of the \
                 last-probe result. One engine per core: enabling it turns the \
                 Observatory off."
            }
            Key::BurstObservatoryGated => {
                "A balancer that needs live health data keeps the Observatory on. Change its \
                 strategy or clear its fallback tag to choose the burst health ping."
            }
            Key::HealthEngineConflict => {
                "Both health engines are on: the core serves the Observatory first, so \
                 the burst health ping reports nothing."
            }
            Key::ProbeInterval => "Probe interval",
            Key::ProbeIntervalHint => {
                "Time between Observatory measurements. Changes apply on Apply now or Connect."
            }
            Key::ProbeIntervalHint2 => {
                "Xray's own probe cadence. The app reads the status every five seconds."
            }
            Key::SubjectSelectors => "Subject selectors",
            Key::SubjectSelectorsHint => "srv- prefix or exact outbound tag",
            Key::ProbeUrl => "Probe URL",
            Key::EnableConcurrency => "Enable concurrency",
            Key::BurstObservatory => "Burst observatory (health ping)",
            Key::Destination => "Destination",
            Key::ConnectivityCheck => "Connectivity check",
            Key::ConnectivityCheckHint => "local connectivity URL (optional)",
            Key::Interval => "Interval",
            Key::IntervalHint => "5s (optional)",
            Key::Sampling => "Sampling",
            Key::Timeout => "Timeout",
            Key::TimeoutHint => "3s (optional)",
            Key::HttpMethod => "HTTP method",
            Key::TestRoute => "Test route…",
            Key::TestRouteWindow => "Test route",
            Key::TestRouteExplain => {
                "Ask the running core which outbound the complete connection context would take."
            }
            Key::TestTargetHeading => "Target",
            Key::TestDomain => "Domain",
            Key::TestDomainHint => "example.com (optional when IP is set)",
            Key::TestTargetIps => "Target IPs",
            Key::TestTargetIpsHint => "203.0.113.10 or 2001:db8::10",
            Key::TestTargetPort => "Target port",
            Key::TestSourceHeading => "Source, local endpoint, and inbound",
            Key::TestSourceIps => "Source IPs",
            Key::TestSourceIpsHint => "192.0.2.10 or 2001:db8::20",
            Key::TestSourcePort => "Source port",
            Key::TestLocalIps => "Local IPs",
            Key::TestLocalIpsHint => "127.0.0.1 or ::1",
            Key::TestLocalPort => "Local port",
            Key::TestInboundTag => "Inbound tag",
            Key::TestVlessRoute => "VLESS route",
            Key::TestProcessNote => {
                "The route test cannot check process predicates: the official RoutingContext RPC \
                 message has no process field."
            }
            Key::TestDetectedProtocol => "Detected protocol",
            Key::TestNetwork => "Network",
            Key::TestProtocol => "Protocol",
            Key::TestProtocolHint => "for example http, tls, quic, bittorrent (optional)",
            Key::TestAttributes => "Attributes",
            Key::TestAttrKeyHint => "attribute key",
            Key::TestAttrValueHint => "attribute value",
            Key::TestCoreNotRunning => "Core is not running. Start it to test routes.",
            Key::TestExactContext => "Test exact context",
            Key::TestDisabledNotRunning => "Start the core before testing",
            Key::TestDisabledBusy => "Wait for the current lifecycle/update operation",
            Key::TestDisabledPending => "Wait for the current route test",
            Key::TestDisabledIncomplete => "Complete the route context",
            Key::AttributeKeyRequired => "attribute key is required",
            Key::DuplicateAttributeKey => "duplicate attribute key {key:?}",
            Key::Any => "(any)",
            Key::RuleSummaryDomain => "domain: {}",
            Key::RuleSummaryIp => "ip: {}",
            Key::RuleSummaryPort => "port: {}",
            Key::RuleSummaryProto => "proto: {}",
            Key::RuleSummaryIn => "in: {}",
            Key::RuleSummaryProc => "proc: {}",
            Key::RuleSummaryMatchAll => "match all",
            Key::RuleTargetBalancer => "⚖ {}",
            // Settings screen.
            Key::SettingsAppearance => "Appearance",
            Key::SettingsUiScale => "UI scale",
            Key::SettingsScaleHint => {
                "Scales the whole interface in addition to Windows display scaling. The app saves \
                 this value automatically."
            }
            Key::SettingsCore => "Core",
            Key::SettingsLogLevel => "Log level:",
            Key::SettingsAccessLog => "Log accepted connections (xray access log):",
            Key::SettingsAccessLogHint => {
                "Requires a log level above \"none\". Xray disables all logging at \"none\"."
            }
            Key::SettingsEnvVars => "Environment variables for the core process:",
            Key::SettingsPolicyLevels => "Policy by user level:",
            Key::SettingsUserLevel => "User level {}",
            Key::SettingsRemoveLevel => "Remove level",
            Key::SettingsAddUserLevel => "+ Add user level",
            Key::SettingsUpdates => "Updates",
            Key::SettingsCheckForUpdates => "Check for updates",
            Key::SettingsCheckForUpdatesHint => {
                "Compares the repository's version against this build. The app makes no request \
                 until you press this button."
            }
            Key::SettingsUpdateChecking => "Checking…",
            Key::SettingsUpdateDetected => "Update detected — v{}",
            Key::SettingsUpdateUpToDate => "Up to date (v{})",
            Key::SettingsUpdateFailed => "Update check failed",
            Key::SettingsUpdateReleasesLink => "Open the releases page",
            // Settings → Cleanup: exit-time footprint removal.
            Key::SettingsCleanup => "Cleanup",
            Key::SettingsCleanupHint => {
                "Maintenance: reset to a fresh install's defaults, or remove broccoli \
                 from this PC entirely."
            }
            Key::SettingsCleanUpAndExit => "Clean Up and Exit…",
            Key::SettingsCleanUpAndExitHint => {
                "The app deletes the entire app-data folder and exits. The next launch starts as a \
                 fresh install."
            }
            Key::SettingsCleanupTitle => "Clean Up and Exit",
            Key::SettingsCleanupBody => {
                "The app removes everything: configuration, servers, core, and logs. First, the app \
                 exits normally and stops the core."
            }
            Key::SettingsCleanupFull => "Full cleanup",
            Key::SettingsCleanupFullHint => {
                "Deletes the entire app-data folder (configuration, servers, core, logs). The next \
                 launch starts as a fresh install."
            }
            // Settings → Reset to default.
            Key::SettingsResetToDefault => "Reset to default…",
            Key::SettingsResetToDefaultHint => {
                "Restore a fresh install's defaults. The app keeps your server list and exits to \
                 finish the reset."
            }
            Key::SettingsResetTitle => "Reset to default",
            Key::SettingsResetBody => {
                "All settings return to a fresh install's defaults: mode, local endpoints, DNS, \
                 latency, theme. The app exits to finish the reset and clears the generated \
                 configurations and logs. The app keeps your server list. The next launch starts as \
                 a fresh install with your servers."
            }
            Key::SettingsResetConfirm => "Reset to default",
            Key::SettingsAdvanced => "Advanced",
            Key::SettingsPingTest => "Ping test",
            Key::SettingsPingTestHint => {
                "URL that the isolated Test latency one-shot probe fetches. An empty value falls \
                 back to the Observatory probe URL, then to the built-in default."
            }
            Key::SettingsRawOverrideActive => {
                "⚠ RAW OVERRIDE ACTIVE. The app ignores all other settings on every screen."
            }
            Key::SettingsRawOverrideHeader => "Raw Override (danger)",
            Key::SettingsRawOverrideExplain => {
                "The app hands a complete config.json to the core verbatim. It replaces the \
                 generated configuration."
            }
            Key::SettingsRawOverridePasteHint => {
                "Paste a full config.json to enable the buttons below."
            }
            Key::SettingsRawOverrideParsing => "Parsing the raw override…",
            Key::SettingsRawOverrideTooLarge => "Raw Override too large ({} bytes, limit {} bytes)",
            Key::SettingsRawOverrideWorkerFailed => "failed to start the Raw Override parser: {}",
            Key::SettingsValidateWithCore => "Validate with core",
            Key::SettingsValidateHint => {
                "Runs 'xray run -test' on this JSON. The verdict appears below."
            }
            Key::SettingsEnableOverride => "Enable override",
            Key::SettingsEnableOverrideHint => {
                "Store this JSON as the only configuration. The app ignores everything else until \
                 you disable the override."
            }
            Key::SettingsDisableOverride => "Disable override",
            Key::SettingsCoreAccepts => "The core accepts this configuration.",
            Key::SettingsCoreRejects => "The core rejects this configuration:",
            Key::SettingsTimeoutsHeader => "Timeouts in seconds (unset means the core default)",
            Key::SettingsHandshake => "Handshake",
            Key::SettingsConnIdle => "Connection idle",
            Key::SettingsUplinkOnly => "Uplink only",
            Key::SettingsDownlinkOnly => "Downlink only",
            Key::SettingsBufferSize => "Buffer size in KB (-1 means unlimited)",
            Key::SettingsStatsUserUplink => "Stats: user uplink",
            Key::SettingsStatsUserDownlink => "Stats: user downlink",
            Key::SettingsStatsUserOnline => "Stats: user online",
            Key::ProbeIntervalPositive => "probe interval must be greater than 0",
            Key::SettingsGeodata => "Geodata",
            Key::SettingsGeodataCronLabel => "Update schedule (cron):",
            Key::SettingsGeodataCronHint => {
                "5-field cron: minute hour day-of-month month day-of-week. Leave empty for the \
                 default 0 4 * * *"
            }
            Key::SettingsGeodataEmptyHint => {
                "Leave a file URL empty to keep the built-in dat file shipped with \
                 the pinned core."
            }
            Key::SettingsGeodataScheduleHint => {
                "The core downloads and reloads the configured files on this schedule \
                 without a restart."
            }
            Key::SettingsGeodataProvenanceRelease => {
                "Release-managed: the geo data matches the pinned release."
            }
            Key::SettingsGeodataProvenanceUserOn => {
                "User-managed: the geo data differs from the pinned release \
                 (last modified {})."
            }
            Key::SettingsGeodataProvenanceUserUnknown => {
                "User-managed: the geo data differs from the pinned release."
            }
            Key::SettingsGeodataRestore => "Restore built-in geo data",
            Key::SettingsGeodataRestoreHint => {
                "Replaces the managed geo data with the pin-verified copies \
                 shipped with the pinned core release."
            }
            Key::SettingsGeodataRestoreBusy => "Restoring the built-in geo data…",
            Key::SettingsGeodataRestoreDone => "Restored the built-in geo data.",
            Key::SettingsGeodataRestoreFailed => "Restore failed: {}.",
            Key::SettingsGeodataRestoreWorkerFailed => "failed to start the restore worker: {}",
            Key::GeodataUrlNotHttps => "URL must be HTTPS (https://…)",
            Key::GeodataCronNotFiveFields => {
                "Cron must have exactly 5 fields: minute hour day-of-month month day-of-week"
            }
            // Servers screen: validators + tool errors.
            Key::SrvRequired => "required by Xray",
            Key::SrvUuidRequired => "UUID is required by Xray",
            Key::SrvMustBeUuid => "must be a UUID",
            Key::SrvWgKey => {
                "required: 64 hex digits or a 32-byte standard/URL-safe base64 key \
                 with at most one trailing '='"
            }
            Key::SrvCertPinHex => "each certificate pin must be exactly 32 bytes of hex",
            Key::SrvVlessEncryptionRequired => {
                "required by Xray. Use \"none\" when encryption is disabled"
            }
            Key::SrvVlessEncryptionFormat => {
                "\"none\" or mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<keys>"
            }
            Key::SrvAddressRequired => "server address is required",
            Key::SrvPortRequired => "server port is required",
            Key::SrvManagedCoreVerificationFailed => "managed core verification failed: {}",
            Key::SrvLaunchXrayFailed => "failed to launch xray.exe: {}",
            Key::SrvCollectOutputFailed => "failed to collect xray helper output: {}",
            Key::SrvXrayExited => "xray {} exited {}{}",
            Key::SrvReapTimedOutFailed => "failed to reap timed-out xray helper: {}",
            Key::SrvXrayDeadline => "xray {} exceeded the {} second deadline{}",
            Key::SrvWaitXrayFailed => "failed while waiting for xray {}: {}",
            Key::SrvValidationAlreadyRunning => "another profile validation is already running",
            Key::SrvNoProfilesToValidate => "there are no profiles to validate",
            Key::SrvDraftValidationRequiresIdentity => "draft validation requires a draft identity",
            Key::SrvScratchConfigDirFailed => "failed to create scratch config directory: {}",
            Key::SrvScratchConfigSerializeFailed => "failed to serialize scratch config: {}",
            Key::SrvScratchConfigWriteFailed => "failed to write scratch config: {}",
            Key::SrvXrayTestSilent => "xray run -test failed without diagnostic output",
            Key::SrvDuplicateAcceptedId => {
                "another accepted profile in this import already uses ID {:?}"
            }
            Key::SrvWorkerExitedWithoutResult => {
                "profile validation worker exited without a result"
            }
            Key::SrvDiscardedMismatchedResult => "discarded a mismatched profile validation result",
            Key::SrvDiscardedStaleImport => {
                "Discarded stale import validation because the source text changed."
            }
            Key::SrvDraftValidationWithoutIdentity => {
                "discarded draft validation without a draft identity"
            }
            Key::SrvXrayRejectedServer => "Xray rejected the server. See validation details.",
            Key::SrvServerValidatedAndAdded => "Server validated by Xray and added.",
            Key::SrvServerDeletedWhileValidating => {
                "selected server was deleted while validation was running"
            }
            Key::SrvServerValidatedAndSaved => "Server validated by Xray and saved.",
            Key::SrvImportedCount => "{} server(s) validated by Xray and imported.",
            Key::SrvImportOutcome => "{} imported. {} rejected by Xray. See Import details.",
            Key::SrvAnotherToolRunning => "another Xray helper is already running",
            Key::SrvSpawnToolFailed => "failed to start Xray helper: {}",
            Key::SrvStartValidationFailed => "failed to start the profile validation: {}",
            Key::SrvToolStoppedWithoutResult => "Xray helper stopped without returning a result",
            Key::SrvUuidInvalid => "xray uuid returned an invalid UUID",
            Key::SrvUuidTargetNoId => "UUID target no longer accepts an ID",
            Key::SrvUuidGenerated => "UUID generated.",
            Key::SrvToolTargetFieldNotFound => "tool target field not found",
            Key::SrvVlessencInvalid => "xray vlessenc returned an invalid client encryption value",
            Key::SrvVlessencTargetFieldNotFound => "VLESS encryption target field not found",
            Key::SrvClientEncryptionGenerated => "Client encryption generated.",
            Key::SrvVlessencNoValue => "xray vlessenc returned no client encryption value",
            Key::SrvWgInvalidPrivateKey => "xray wg returned an invalid private key",
            Key::SrvWgCouldNotParse => "could not parse xray wg private key",
            Key::SrvWgSecretGenerated => "WireGuard secret key generated.",
            Key::SrvWgTargetFieldNotFound => "WireGuard secret-key target field not found",
            Key::SrvMldsa65InvalidKey => "xray mldsa65 returned an invalid verification key",
            Key::SrvMldsa65CouldNotParse => "could not parse xray mldsa65 verification key",
            Key::SrvMldsa65Generated => "ML-DSA-65 verification key generated.",
            Key::SrvMldsa65TargetFieldNotFound => "ML-DSA-65 target field not found",
            Key::SrvTlsPinMalformed => "xray tls hash returned a malformed leaf hash",
            Key::SrvTlsPinNoHash => "xray tls hash returned no leaf certificate hash",
            Key::SrvTlsPinComputedLeaf => "Computed leaf SHA-256 pin: {}",
            Key::SrvTlsPinComputed => "Certificate pin computed.",
            Key::SrvTlsPinTargetFieldNotFound => "TLS pin target field not found",
            Key::SrvTlsHandshakeSucceeded => "TLS handshake succeeded.",
            Key::SrvTlsProbeNoHandshake => {
                "TLS probe completed without a successful handshake:\n{}"
            }
            Key::SrvRealityPubKeyDerived => "REALITY public key derived.",
            Key::SrvRealityTargetFieldNotFound => "REALITY public-key target field not found",
            Key::SrvX25519InvalidPublicKey => "xray x25519 returned an invalid public key",
            Key::SrvX25519CouldNotParse => "could not parse xray x25519 output",
            // Servers screen: list + editor chrome.
            Key::SrvAddServer => "+ Add server",
            Key::SrvImportLinks => "Import links",
            Key::SrvTestLatencyHint => {
                "Run one temporary isolated Xray core once. This does not save settings or restart \
                 the main core."
            }
            Key::SrvLatencyTestAlreadyRunning => "A latency test is already running",
            Key::SrvAnotherOperationWorking => {
                "Another lifecycle, update, or latency operation is already working"
            }
            Key::SrvProbeServerLatencyHint => "Test this server's latency",
            Key::SrvAddServerBeforeLatency => "Add a server before testing latency",
            Key::SrvTestingLatencyIsolated => "Testing latency in isolated core…",
            Key::SrvSortByLatency => "Sort by latency",
            Key::SrvDragToReorder => "Drag to reorder",
            Key::SrvSetActive => "Set active",
            Key::SrvDuplicate => "Duplicate",
            Key::SrvExportLinkQr => "Export link / QR",
            Key::SrvDeleteEllipsis => "Delete…",
            Key::SrvCopySuffix => "{} copy",
            Key::SrvLinkCopiedToClipboard => "Link copied to clipboard.",
            Key::SrvExportFailed => "export failed: {}",
            Key::SrvUnnamed => "(unnamed)",
            Key::SrvSelectServerOrAdd => "Select a server or add one from the list.",
            Key::SrvPrepareDraftFailed => "could not prepare server draft: {}",
            Key::SrvFixBeforeValidate => {
                "Fix these values before broccoli validates and saves this profile:"
            }
            Key::SrvConfigurationWarningsHeader => {
                "Configuration warnings. The profile can still be validated and saved:"
            }
            Key::SrvValidateAndSave => "Validate and save",
            Key::SrvValidateAndSaveHint => {
                "Runs xray run -test on an isolated candidate before saving"
            }
            Key::SrvDiscardChanges => "Discard changes",
            Key::SrvUnsavedChanges => "Unsaved changes",
            Key::SrvUnsavedLeaveBody => "You have unsaved changes. Save, discard, or keep editing.",
            Key::SrvUnsavedLeaveSave => "Save",
            Key::SrvValidatingXrayTest => "Validating with xray run -test…",
            Key::SrvValidationFailedColon => "Xray validation failed:",
            Key::SrvCompleteRequired => "Complete these required values:",
            Key::SrvWaitCoreOperation => {
                "Wait for the current core operation before validating this server."
            }
            Key::SrvValidateAndAdd => "Validate and add",
            Key::SrvValidateAndAddHint => {
                "Generates a request-local scratch config and runs xray run -test"
            }
            Key::SrvKeygenDraftOnly => {
                "Key generation is available only for an unsaved server draft."
            }
            Key::SrvDeleteCannotUndone => "Delete \"{}\"? This cannot be undone.",
            Key::SrvCannotDeleteReferences => {
                "Cannot delete \"{}\": {} reference(s) must be changed first."
            }
            Key::SrvDerive => "Derive",
            Key::SrvDerivingXray => "Deriving with xray x25519…",
            Key::SrvPrivateKeyRequired => "a private key is required",
            Key::SrvPrivateKeyLabel => "Private key:",
            Key::SrvPrivateKeyHint => "base64url X25519 private key",
            Key::SrvShareTitle => "Share — {}",
            Key::SrvQrTooLong => "link too long for QR. Clipboard copy still works",
            Key::SrvImportShareLinks => "Import share links",
            Key::SrvImportHint => {
                "One link per line (vless:// vmess:// trojan:// ss://). # comments ignored."
            }
            Key::SrvImportPasteHint => "vless://…\nvmess://…",
            Key::SrvParse => "Parse",
            Key::SrvPasteCtrlV => "(paste with Ctrl+V)",
            Key::SrvOkTotal => "{} ok / {} total",
            Key::SrvValidateAndAddServers => "Validate and add {} servers",
            Key::SrvValidateAndAddServersHint => {
                "Each profile is staged in a unique scratch config and tested by Xray"
            }
            Key::SrvValidatingProfiles => "Validating {} profile(s) with xray run -test…",
            Key::SrvParsingLinks => "Parsing share links…",
            Key::SrvImportTooLarge => {
                "input too large: {} bytes (limit {} bytes). Nothing was parsed"
            }
            Key::SrvParseWorkerFailed => "failed to start the link parser: {}",
            Key::SrvRejectedProfileDetails => "Rejected profile details:",
            Key::SrvWaitCoreOperationImports => {
                "Wait for the current core operation before validating imports."
            }
            Key::SrvImportOkMark => "✓ {} — {}",
            Key::SrvImportErrMark => "✗ {}",
            Key::SrvInvalidJson => "invalid JSON: {}",
            // Servers screen: editor sub-forms + finalmask + transports.
            Key::SrvShadowsocksMethodRequired => "Shadowsocks method is required.",
            Key::SrvShadowsocksLevelRange => "Shadowsocks level must be between 0 and 255.",
            Key::SrvAtLeastOneWgPeer => "At least one WireGuard peer is required.",
            Key::SrvWgPeerPublicKeyNote => {
                "The remote peer provides it. It must not be derived from this client's secret key."
            }
            Key::SrvReservedBytesFound => "Xray requires exactly 3 reserved bytes. Found {}.",
            Key::SrvResetThreeZeroBytes => "Reset to three zero bytes",
            Key::SrvRemovePeer => "remove peer",
            Key::SrvAddPeer => "+ peer",
            Key::SrvRemove => "remove",
            Key::SrvFragmentationInvalid => {
                "fragmentation requires valid packets plus non-empty length and interval"
            }
            Key::SrvBlackholeResponseInvalid => "Blackhole response type must be none or http.",
            Key::SrvDnsRuleActionRequired => "A valid DNS rule action is required.",
            Key::SrvAddDnsRule => "+ DNS rule",
            Key::SrvSniffing => "sniffing",
            Key::SrvHysteriaNote => {
                "auth and congestion live under Transport (hysteriaSettings / finalmask.quicParams)"
            }
            Key::SrvReverseProxy => "reverse proxy (VLESS reverse)",
            Key::SrvReverseSniffing => "reverse sniffing",
            Key::SrvReservedBytes => "reserved bytes (exactly 3)",
            Key::SrvPeersColon => "peers:",
            Key::SrvTcpFragmentation => "TCP fragmentation",
            Key::SrvCustomResponse => "custom response",
            Key::SrvHttpCamouflageHeader => "HTTP camouflage header",
            Key::SrvRequestCamouflage => "request camouflage",
            Key::SrvResponseCamouflage => "response camouflage",
            Key::SrvEnableXmux => "enable xmux",
            Key::SrvSeparateDownlinkStream => "separate downlink stream",
            Key::SrvConnectionLimit => "connection limit:",
            Key::SrvCoreDefaults => "core defaults",
            Key::SrvMaxConcurrency => "max concurrency",
            Key::SrvMaxConnections => "max connections",
            Key::SrvMutuallyExclusive => {
                "maxConcurrency and maxConnections are mutually exclusive. Choose one."
            }
            Key::SrvDownloadNotAllowed => "downloadSettings is not allowed in stream-one mode.",
            Key::SrvRemoveSplitDownload => "Remove split download",
            Key::SrvDownloadDepth => "downloadSettings (split downlink, depth {})",
            Key::SrvUnavailableStreamOne => "Unavailable in stream-one mode.",
            Key::SrvDepthExceeded => {
                "downloadSettings exceeds broccoli's safety depth of {}. The imported value is \
                 preserved, but it cannot be committed."
            }
            Key::SrvSerializationError => "serialization error: {}",
            Key::SrvPreservedOverLimit => "Preserved over-limit downloadSettings JSON",
            Key::SrvSwitchAwayReality => "Switch away from REALITY before choosing this transport",
            Key::SrvHysteriaSelectsTls => "Hysteria2 requires TLS. Selecting it switches to TLS",
            Key::SrvHysteriaRequiresTls => "Hysteria2 requires TLS.",
            Key::SrvSwitchToTls => "Switch to TLS",
            Key::SrvUseVersion2 => "Use version 2",
            Key::SrvRewriteHost => "rewrite Host",
            Key::SrvSkipTlsVerify => "skip TLS verify",
            Key::SrvCongestionNote => {
                "congestion/brutal rates live under Advanced → finalmask.quicParams"
            }
            Key::SrvGrpcDeprecated => "gRPC is deprecated upstream. Prefer XHTTP stream-up.",
            Key::SrvWsDeprecated => "WebSocket is deprecated upstream. Prefer XHTTP H2 and H3.",
            Key::SrvHttpupgradeDeprecated => "HTTPUpgrade is deprecated upstream. Prefer XHTTP.",
            Key::SrvMinVersionExceedsMax => {
                "TLS minimum version must not exceed the maximum version."
            }
            Key::SrvComputePinFromCert => "Compute pin from certificate…",
            Key::SrvComputePinHint => "Runs: xray tls hash --cert <cert.pem>",
            Key::SrvProbeTlsCertificate => "Probe TLS certificate",
            Key::SrvProbeTlsHandshake => "Probe TLS handshake",
            Key::SrvProbeTlsHint => "Runs xray tls ping only after this button is clicked",
            Key::SrvProbeQuicHandshake => "Probe QUIC handshake",
            Key::SrvProbeQuicHint => {
                "In-app QUIC (UDP) handshake for servers that do not answer TCP, for example \
                 Hysteria2. The pin comes from the certificate the server presents"
            }
            Key::SrvTlsProbeDomainRequired => "TLS probe domain is required",
            Key::SrvTlsProbeIpInvalid => "TLS probe IP override is invalid",
            Key::SrvTlsProbeRunning => "TLS probe is running…",
            Key::SrvQuicProbeDomainInvalid => "QUIC probe domain is invalid: {0}",
            Key::SrvQuicProbeResolveFailed => "Failed to resolve QUIC probe address: {0}",
            Key::SrvQuicProbeHandshakeFailed => "QUIC handshake failed: {0}",
            Key::SrvQuicProbeTimeout => "QUIC handshake timed out",
            Key::SrvQuicProbeNoCert => "The server presented no certificate",
            Key::SrvLeafPin => "Leaf pin",
            Key::SrvCaPins => "CA pins",
            Key::SrvCopyPin => "Copy",
            Key::SrvApplyPin => "Apply to server",
            Key::SrvPinApplied => "Pin applied.",
            Key::SrvPinCaution => {
                "Pinning trusts the server certificate exactly as presented now \
                 (trust-on-first-use). Use it only for self-signed or otherwise untrusted \
                 certificates. If the server certificate changes, the server stops working until the \
                 pin is updated."
            }
            Key::SrvProbeNoPin => "No certificate pin found in the probe output.",
            Key::SrvShowProbeOutput => "Show original output",
            Key::SrvProbeOutputTitle => "TLS probe output",
            Key::SrvUseServerAddress => "Use server address:port",
            Key::SrvUseServerName => "Use serverName",
            Key::SrvFromMitmOnlyAlpn => "fromMitm must be the only ALPN value when it is used.",
            Key::SrvCustomCertificate => "custom certificate",
            Key::SrvCertificateN => "certificate {}",
            Key::SrvCertificateFileRequired => {
                "certificate file or inline certificate is required."
            }
            Key::SrvAddCertificate => "+ certificate",
            Key::SrvPlaintextNote => {
                "plaintext: the core accepts only private-IP/domain servers for vless/trojan"
            }
            Key::SrvPublicKeyDerivationDraftOnly => {
                "Public-key derivation is available only for an unsaved server draft."
            }
            Key::SrvEnvelope => "Envelope",
            Key::SrvFinalmask => "finalmask",
            Key::SrvTcpMasks => "TCP masks",
            Key::SrvUdpMasks => "UDP masks",
            Key::SrvUnknownType => "Unknown ({})",
            Key::SrvMissingType => "missing type",
            Key::SrvTcpN => "TCP {}",
            Key::SrvUdpN => "UDP {}",
            Key::SrvAddTcpMask => "+ TCP mask",
            Key::SrvAddUdpMask => "+ UDP mask",
            Key::SrvSockopt => "sockopt",
            Key::SrvAddServerWindow => "Add server",
            Key::SrvProtocol => "protocol",
            Key::SrvBasics => "Basics",
            Key::SrvPadding => "Padding",
            Key::SrvUpload => "Upload",
            Key::SrvSession => "Session",
            Key::SrvLimits => "Limits",
            Key::SrvXmux => "xmux",
            Key::SrvAddRow => "+ Add row",
            Key::SrvArgumentN => "argument {}",
            Key::SrvSequenceN => "sequence {}",
            Key::SrvItemN => "item {}",
            Key::SrvRemoveSequence => "remove sequence",
            Key::SrvRemoveItem => "remove item",
            Key::SrvAddItem => "+ item",
            Key::SrvAddSequence => "+ sequence",
            Key::SrvAddRange => "+ range",
            Key::SrvNoiseN => "noise {}",
            Key::SrvAddNoise => "+ noise",
            Key::SrvMinecraftProfileN => "Minecraft profile {}",
            Key::SrvAddMinecraftProfile => "+ Minecraft profile",
            Key::SrvCertificatePem => "certificate (PEM)",
            Key::SrvKeyPem => "key (PEM)",
            Key::SrvAddRealmTlsCertificate => "+ Realm TLS certificate",
            Key::SrvRealmTlsWireNote => {
                "Realm TLS certificates use the same exact wire model as top-level TLS. Imported \
                 entries are preserved."
            }
            Key::SrvAllowInsecureRemoved => {
                "allowInsecure was removed by Xray. Use pinnedPeerCertSha256 or \
                 verifyPeerCertByName."
            }
            Key::SrvUnknownFutureFinalmask => {
                "Unknown future finalmask type {:?}. broccoli preserves this complete raw object."
            }
            Key::SrvPreservedRawValue => "Preserved raw value",
            Key::SrvSetLabel => "set {}",
            Key::SrvLabelSyntax => "{} syntax",
            Key::SrvUp => "up",
            Key::SrvDown => "down",
            Key::SrvCustomSockoptN => "custom sockopt {}",
            Key::SrvUnknownFutureFields => {
                "{} unknown future customSockopt field(s) are preserved unchanged."
            }
            Key::SrvUnknownFutureFieldsSockopt => {
                "{} unknown future SocketConfig field(s) are preserved unchanged."
            }
            Key::SrvUnknownFutureFieldsCustom => {
                "{} unknown future happyEyeballs field(s) are preserved unchanged."
            }
            Key::SrvNonWindowsSockopt => "Non-Windows outbound socket options",
            Key::SrvNonWindowsSockoptNote => {
                "Xray's Windows outbound socket path does not consume these values. Imported values \
                 are preserved."
            }
            Key::SrvKeepAliveNote => {
                "tcpKeepAliveInterval is edited above because Xray's Go dialer uses it \
                 on every supported platform."
            }
            Key::SrvTcpMptcpNote => {
                "tcpMptcp is passed to Go's network dialer on supported operating systems."
            }
            Key::SrvListenerOnlySockopt => "Listener/server-only (no outbound effect)",
            Key::SrvListenerOnlySockoptNote => {
                "ECH uses DialSystem. Listeners consume v6only and acceptProxyProtocol. Inbound \
                 HTTP/gRPC transports consume trustedXForwardedFor."
            }
            Key::SrvPenetrateNote => "penetrate is consulted only when XHTTP has downloadSettings.",
            Key::SrvPenetrateEchNote => {
                "penetrate only copies stream sockopt into XHTTP downloadSettings. The ECH DNS query \
                 calls DialSystem directly."
            }
            Key::SrvEchDnsQuerySockopt => "ECH DNS-query socket options",
            Key::SrvEchSockoptNote => {
                "Used only when echConfigList requests DNS (https://, h2c://, or udp://). \
                 TCP-only fields do not affect udp:// queries."
            }
            Key::SrvHappyEyeballs => "happy eyeballs (RFC 8305)",
            Key::SrvAddCustomSockopt => "+ custom sockopt",
            Key::SrvUseDefault => "Use default",
            Key::SrvHostReserved => "Host is reserved. Edit the transport host field instead.",
            Key::SrvWsHostDeprecated => {
                "WebSocket headers.Host is deprecated. Move it to the host field."
            }
            Key::SrvMoveHostToHost => "Move Host to host field",
            Key::SrvRemoveLegacyHost => "Remove legacy Host header",
            Key::SrvUnset => "(unset)",
            Key::SrvDefault => "(default)",
            Key::SrvTrueEnable => "true (enable)",
            Key::SrvFalseDisable => "false (disable)",
            Key::SrvNumericWindow => "numeric window",
            Key::SrvInvalidImportedValue => "invalid imported value",
            Key::SrvPreserved => "preserved: {}",
            Key::SrvWindow => "window",
            Key::SrvBrowse => "Browse…",
            Key::SrvRemoveObsoleteDomain => "Remove obsolete domain field",
            Key::SrvImportedDomainRemoved => {
                "Imported domain is a removed upstream field. It remains preserved until \
                 removed."
            }
            Key::SrvTabBasic => "Basic",
            Key::SrvTabTransport => "Transport",
            Key::SrvTabSecurity => "Security",
            Key::SrvTabMux => "Mux",
            Key::SrvTabAdvanced => "Advanced",
            Key::CoreSetupVersionLink => "Xray core {}",
            Key::RoutingOverrideApplied => "Runtime override applied to {}.",
            Key::RoutingOverrideCleared => {
                "Runtime override cleared. The configured strategy is active."
            }
            Key::SrvNewDraftName => "New {}",
            Key::SrvTcpMptcpEditedAbove => {
                "tcpMptcp is edited above because it is not Windows-specific."
            }
            Key::SrvAddTransformArgument => "+ transform argument",
            Key::SrvProtocolSettingsMismatch => "protocol and settings type do not match",
            Key::SrvVlessIdUuid => "VLESS id must be a UUID",
            Key::SrvVlessEncryptionInvalid => "VLESS encryption is invalid",
            Key::SrvVlessReverseTagRequired => "VLESS reverse tag is required",
            Key::SrvVmessIdUuid => "VMess id must be a UUID",
            Key::SrvVmessSecurityUnsupported => "VMess security is unsupported",
            Key::SrvShadowsocksLevelRangeShort => "Shadowsocks level must be between 0 and 255",
            Key::SrvWgSecretInvalid => "WireGuard secret key is invalid",
            Key::SrvWgReservedThreeBytes => "WireGuard reserved must contain exactly three bytes",
            Key::SrvWgAtLeastOnePeer => "WireGuard requires at least one peer",
            Key::SrvWgPeerPublicKeyRequired => "every WireGuard peer requires a valid public key",
            Key::SrvWgPeerEndpointRequired => "every WireGuard peer requires an endpoint",
            Key::SrvWgPresharedInvalid => "a WireGuard pre-shared key is invalid",
            Key::SrvWgRemoteDnsInvalid => {
                "Every WireGuard remote DNS entry must be an IP address. The local entry must \
                 be the only entry."
            }
            Key::SrvWgRemoteDnsEntryInvalid => "Enter an IP address or the word local.",
            Key::SrvWgRemoteDnsLocalOnly => "The local entry must be the only entry.",
            Key::SrvFreedomFragmentInvalid => {
                "Freedom fragmentation requires valid packets, length, and interval"
            }
            Key::SrvFreedomNoiseInvalid => {
                "every Freedom noise requires a valid type, packet, and applyTo"
            }
            Key::SrvFreedomFinalRuleInvalid => "every Freedom final rule requires allow or block",
            Key::SrvBlackholeResponseInvalidShort => "Blackhole response type must be none or http",
            Key::SrvDnsRuleActionInvalidShort => "every DNS outbound rule requires a valid action",
            Key::SrvLoopbackTagRequired => "Loopback inbound tag is required",
            Key::SrvHysteriaVersion => "Hysteria version must be 2",
            Key::SrvRealityRequiresTransport => "REALITY requires raw, XHTTP, or gRPC transport",
            Key::SrvHysteriaTransportTls => "Hysteria transport requires TLS",
            Key::SrvXhttpSettingsMissing => "XHTTP settings are missing",
            Key::SrvKcpSettingsMissing => "mKCP settings are missing",
            Key::SrvGrpcSettingsMissing => "gRPC settings are missing",
            Key::SrvWsSettingsMissing => "WebSocket settings are missing",
            Key::SrvHttpupgradeSettingsMissing => "HTTPUpgrade settings are missing",
            Key::SrvHysteriaTransportSettingsMissing => "Hysteria transport settings are missing",
            Key::SrvStreamOneNoDownload => "stream-one cannot use downloadSettings",
            Key::SrvXhttpHeaderValueString => "every XHTTP header value must be a string",
            Key::SrvDownloadNestingExceeds => {
                "XHTTP downloadSettings nesting exceeds the safety depth"
            }
            Key::SrvMasterKeyLogNotSupported => {
                "masterKeyLog is not supported (TLS session key file writes are refused)"
            }
            Key::SrvProxySettingsRemoved => {
                "Xray removed the proxySettings key from outbounds. Set \
                 streamSettings.sockopt.dialerProxy to the outbound tag this server dials through."
            }
            Key::SrvRemoveProxySettingsKey => "Remove the proxySettings key",
            Key::SrvRemoveProxySettingsKeyNote => {
                "The app removes the retired key. The server dials directly."
            }
            Key::SrvRemoveUdpHopKey => "Remove the udpHop key",
            Key::SrvRemoveUdpHopKeyNote => {
                "The app removes the retired key. The hop stops working."
            }
            Key::SrvMaskSockoptNote => {
                "The hop socket takes these values. TCP-only fields do not affect it"
            }
            Key::SrvPenetrateMaskNote => {
                "penetrate only copies the stream sockopt into XHTTP downloadSettings. The hop \
                 socket calls DialSystem directly"
            }
            Key::SrvWsHeaderValueString => "every WebSocket header value must be a string",
            Key::SrvHttpupgradeHeaderValueString => {
                "every HTTPUpgrade header value must be a string"
            }
            Key::SrvFromMitmOnlyAlpnShort => "fromMitm must be the only ALPN value",
            Key::SrvTlsCertFileOrPem => "every TLS certificate needs a file or inline PEM",
            Key::SrvRealitySettingsMissing => "REALITY settings are missing",
            Key::SrvTlsSettingsMissing => "TLS settings are missing",
            Key::SrvSendThroughInvalidShort => {
                "sendThrough must be an IP address, CIDR, origin, or srcip"
            }
            Key::SrvNetwork => "network",
            Key::SrvSecurity => "security",
            Key::SrvName => "name",
            Key::SrvGenerateUuidHint => "Runs xray uuid in the background.",
            Key::SrvGenerateVlessencHint => "Runs xray vlessenc in the background.",
            Key::SrvGenerateWgHint => "Runs xray wg in the background.",
            Key::SrvGenerateMldsa65Hint => "Runs xray mldsa65 in the background.",
            Key::SrvRandomHexHint => "random hex",
            Key::SrvHysteria2RequiresTls => "Hysteria2 requires TLS",
            Key::SrvHysteria2RequiresTlsSelectBelow => "Hysteria2 requires TLS. Select TLS below.",
            Key::SrvOnlyHysteria2 => "Xray supports only Hysteria version 2.",
            Key::SrvMasquerade => "masquerade",
            Key::SrvUseAuto => "Use auto",
            Key::SrvCookieHeaderNeedsPacketUp => {
                "cookie/header upload placement requires packet-up mode."
            }
            Key::SrvSendThroughInvalid => {
                "sendThrough must be an IP address, CIDR, origin, or srcip."
            }
            Key::SrvMuxDeprecatedHint => {
                "Mux is deprecated for XHTTP. Use xmux instead. Keep concurrency 8 for TCP-era \
                 configs."
            }
            Key::SrvRulesColon => "rules:",
            Key::SrvNoisesUdpObfuscation => "noises (UDP obfuscation):",
            Key::SrvNoiseInvalid => "noise type/packet/applyTo is invalid",
            Key::SrvRemoveNoise => "remove noise",
            Key::SrvFinalRulesPostFragment => "finalRules (post-fragment filtering):",
            Key::SrvFinalRuleActionInvalid => "final rule action must be allow or block",
            Key::SrvRemoveRule => "remove rule",
            Key::SrvAddFinalRule => "+ final rule",
            Key::SrvDerivePublicKey => "Derive public key",
            Key::TestLatency => "Test latency",
            Key::NoServersYet => "No servers yet.",
            // Servers screen: descriptive labels (decorated/humanized;
            // wire-key names stay literal).
            Key::SrvInterfaceBindNic => "interface (bind NIC)",
            Key::SrvRandLength => "rand length",
            Key::SrvPaddingMinLegacy => "padding_min (legacy)",
            Key::SrvPaddingMaxLegacy => "padding_max (legacy)",
            Key::SrvCustomTableLegacy => "custom_table (legacy)",
            Key::SrvAllowInsecureRemovedLabel => "allowInsecure (removed)",
            Key::SrvAlpn => "ALPN",
            Key::SrvIdUuid => "id (uuid)",
            Key::SrvLocalAddresses => "local addresses",
            Key::SrvWgRemoteDns => "in-network DNS",
            Key::SrvWgRemoteDnsHint => "1.1.1.1 or local",
            Key::SrvWgRemoteDnsNote => {
                "An empty list uses the core's built-in resolvers. The single entry local uses \
                 the core's DNS client."
            }
            Key::SrvDomainStrategy => "domain strategy",
            Key::SrvReservedColon => "reserved:",
            Key::SrvKeepaliveS => "keepalive (s)",
            Key::SrvIntervalMs => "interval (ms)",
            Key::SrvMaxSplit => "max split",
            Key::SrvProxyProtocol => "proxy protocol",
            Key::SrvRewritePort => "rewrite port",
            Key::SrvTtiMs => "tti (ms)",
            Key::SrvUplinkCapacity => "uplink capacity (MB/s)",
            Key::SrvCwndMultiplier => "cwnd multiplier",
            Key::SrvMaxSendingWindow => "max sending window",
            Key::SrvIdleTimeoutS => "idle_timeout (s)",
            Key::SrvHealthCheckTimeoutS => "health_check_timeout (s)",
            Key::SrvHeartbeatPeriodS => "heartbeatPeriod (s)",
            Key::SrvAuthPassword => "auth (password)",
            Key::SrvUdpIdleTimeoutS => "udpIdleTimeout (s)",
            Key::SrvStatusCode => "status code",
            Key::SrvServerNameSni => "serverName (SNI)",
            Key::SrvMinVersion => "min version",
            Key::SrvMaxVersion => "max version",
            Key::SrvShowDebug => "show (debug)",
            Key::SrvOfficialSourceToken => "official source token",
            Key::SrvConcurrencyLegacy => "concurrency (-1 = legacy single-stream)",
            Key::SrvDelayMs => "delay (ms)",
            Key::SrvBlockDelayMs => "blockDelay (ms)",
            Key::SrvIntervalS => "interval (s)",
            Key::SrvReverseTag => "reverse tag",
            Key::SrvSecretKey => "secret key",
            Key::SrvPublicKey => "public key",
            Key::SrvPreSharedKey => "pre-shared key",
            Key::SrvTargetStrategy => "target strategy",
            Key::SrvResponseType => "response type",
            Key::SrvRewriteNetwork => "rewrite network",
            Key::SrvInboundTag => "inbound tag",
            Key::SrvCertificateFile => "certificate file",
            Key::SrvKeyFile => "key file",
            Key::SrvPublicKeyPassword => "publicKey (password)",
            Key::SrvTcpKeepAliveIdleS => "tcpKeepAliveIdle (s, negative disables)",
            Key::SrvTcpKeepAliveIntervalS => "tcpKeepAliveInterval (s, negative disables)",
            Key::SrvTcpUserTimeoutMs => "tcpUserTimeout (ms)",
            Key::SrvPenetrateInherit => "penetrate (inherit into XHTTP downloadSettings)",
            Key::SrvPenetrateDownloadOnly => "penetrate (XHTTP downloadSettings only)",
            Key::SrvCustomTablesLegacy => "custom_tables (legacy)",
            Key::SrvLengthsPrecedence => "lengths (takes precedence over length)",
            Key::SrvDelaysPrecedence => "delays (takes precedence over delay)",
            Key::SrvOcspStaplingS => "OCSP stapling (s)",
            Key::SrvDomainsServer => "domains (server)",
            Key::SrvResolversClient => "resolvers (client)",
            Key::SrvMaxIdleTimeoutS => "maxIdleTimeout (s)",
            Key::SrvKeepAlivePeriodS => "keepAlivePeriod (s)",
            Key::SrvRewriteAddress => "rewrite address",
            Key::SrvHKeepAlivePeriodS => "hKeepAlivePeriod (s)",
            Key::SrvDownlinkCapacity => "downlink capacity (MB/s)",
            Key::SrvCipherSuites => "cipher suites",
            Key::SrvCurvePreferences => "curve preferences",
            Key::SrvServerNameTarget => "serverName (target)",
            // Informational hint copy (option semantics — UI copy only,
            // no validation codes).
            Key::SrvTlsServerNameEmptyHint => "empty = the server address is sent as the SNI",
            Key::SrvRealityServerNameEmptyHint => {
                "empty = the server address is sent as the SNI. The handshake succeeds only when \
                 that SNI is one of the server's serverNames"
            }
            Key::SrvTlsFingerprintHint => {
                "empty (the default) = the uTLS Chrome_Auto preset, an imitation like the browser \
                 names. unsafe = native Go TLS, no imitation"
            }
            Key::SrvRealityFingerprintHint => {
                "empty (the default) = the uTLS Chrome_Auto preset, an imitation like the browser \
                 names. The list offers only the browser names the Xray project tests: chrome, \
                 firefox, safari. A saved server keeps any other fingerprint Xray accepts"
            }
            Key::SrvVisionUdp443Hint => {
                "xtls-rprx-vision alone intercepts UDP/443 (QUIC) client-side. Xray then logs \"XTLS \
                 rejected UDP/443 traffic\". The -udp443 variant lifts that interception. Otherwise \
                 the two variants write identical bytes on the wire"
            }
            Key::SrvXudpProxyUdp443Hint => {
                "(unset) or empty = reject, Xray's default: UDP/443 (QUIC) through mux is refused. \
                 QUIC clients then fall back to TCP (HTTP/2)"
            }
            Key::SrvGrpcMuxHint => {
                "gRPC (HTTP/2) has built-in multiplexing. Combining it with mux is not recommended"
            }
            Key::SrvGrpcMultiModeHint => {
                "multiMode is experimental (BETA): Xray may drop it or change it across \
                 versions"
            }
            Key::ErrorBullet => "• {}",
            // Model-layer validation errors, translated at the source.
            Key::SockoptDomainStrategyInvalid => {
                "domainStrategy is not supported by Xray SocketConfig"
            }
            Key::SockoptAddressPortStrategyInvalid => {
                "addressPortStrategy is not supported by Xray SocketConfig"
            }
            Key::SockoptTcpFastOpenType => "tcpFastOpen must be a boolean or number",
            Key::SockoptKeepaliveSigns => {
                "tcpKeepAliveIdle and tcpKeepAliveInterval cannot have opposite signs"
            }
            Key::SockoptCustomOptRequired => "customSockopt opt is required",
            Key::SockoptCustomTypeInvalid => "customSockopt type must be int or str",
            Key::OutboundVisionRequiresTls => "VLESS Vision flow requires TLS or REALITY",
            Key::OutboundPublicVlessNeedsTls => {
                "public VLESS endpoints require TLS/REALITY or non-none VLESS encryption"
            }
            Key::OutboundPublicTrojanNeedsTls => "public Trojan endpoints require TLS or REALITY",
            Key::ListenAddressInvalid => {
                "listen address must be an IP address, for example 127.0.0.1, 0.0.0.0, or ::1"
            }
            // Configuration warnings (Severity::Warning): advisory messages
            // name the incompatibility, the fix, and the XUDP exception /
            // per-block plausible-value guidance.
            Key::OutboundMuxWithVisionFlow => {
                "VLESS Vision flow rejects TCP carried over mux. The server tears the whole mux \
                 connection down on the first TCP frame, so traffic dies with an EOF. Disable mux, \
                 or set concurrency to -1 to keep TCP direct. The XUDP options \
                 (xudpConcurrency/xudpProxyUDP443) remain compatible."
            }
            Key::OutboundServerNameImplausible => {
                "serverName cannot be a real DNS name or IP. UUID-shaped values and characters like \
                 spaces, '/', or '?' can never match an SNI. For TLS use the server's own domain, \
                 for example www.example.com. For REALITY use one of the server's serverNames, \
                 typically the camouflage site's domain."
            }
            // Outbound `settings` rules. Error messages name the accepted
            // vocabulary / format; the Shadowsocks-2022 key rule is advisory
            // — Xray accepts the config, the session fails at dial time
            // instead.
            Key::OutboundVlessFlowUnsupported => {
                "VLESS flow must be empty, xtls-rprx-vision, or xtls-rprx-vision-udp443"
            }
            Key::OutboundVlessEncryptionUnsupported => {
                "VLESS encryption must be empty, none, or the canonical \
                 mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<keys> form"
            }
            Key::OutboundShadowsocksMethodUnsupported => {
                "Shadowsocks method must be one of the AEAD methods (aes-128-gcm, aes-256-gcm, \
                 chacha20-poly1305, xchacha20-poly1305) or a 2022-blake3-* method. Xray core does \
                 not support legacy stream ciphers."
            }
            Key::OutboundShadowsocks2022KeyInvalid => {
                "Shadowsocks-2022 key must be base64 of exactly the method's key length: 16 bytes \
                 for 2022-blake3-aes-128-gcm, 32 bytes for 2022-blake3-aes-256-gcm and \
                 2022-blake3-chacha20-poly1305. The ChaCha20 method has no multi-key form. Xray \
                 accepts this config, but every dial fails authentication."
            }
            Key::OutboundTrojanSettingsIncomplete => {
                "Trojan requires a server address, a non-zero port, and a password"
            }
            Key::OutboundShadowsocksSettingsIncomplete => {
                "Shadowsocks requires a server address, a non-zero port, and a password"
            }
            Key::OutboundSettingsPortZero => {
                "server port must be non-zero. Dialing port 0 can never connect"
            }
            Key::OutboundSettingsIdNotUuid => {
                "id must be a canonical UUID (8-4-4-4-12 hexadecimal). Xray silently maps other ids \
                 to a different account, so they are refused"
            }
            // Transport-security format rules (stream TLS/REALITY blocks).
            // Error messages name the accepted format/vocabulary — mirroring
            // the share-link grammar texts; the TLS-version rule is a
            // configuration warning: Xray accepts the config and silently
            // drops the string, so it never gates.
            Key::OutboundRealityPublicKeyInvalid => {
                "REALITY publicKey must be a 32-byte unpadded base64url X25519 public key \
                 (stored as the profile's password field)"
            }
            Key::OutboundRealityShortIdInvalid => {
                "REALITY shortId must be an even-length hexadecimal value of at most 16 \
                 characters"
            }
            Key::OutboundRealitySpiderXInvalid => {
                "REALITY spiderX must be a valid URL path beginning with '/'. An empty value is \
                 allowed, and Xray defaults it to '/'"
            }
            Key::OutboundRealityMldsa65Invalid => {
                "REALITY mldsa65Verify must be a 1952-byte unpadded base64url ML-DSA-65 public key. \
                 An empty value is allowed and means no post-quantum key"
            }
            Key::OutboundTlsFingerprintUnsupported => {
                "TLS fingerprint must be one of the uTLS fingerprints Xray accepts, for example \
                 chrome, firefox, ios, randomizednoalpn, or unsafe (native Go TLS)"
            }
            Key::OutboundRealityFingerprintUnsupported => {
                "REALITY fingerprint must be one of the uTLS fingerprints Xray accepts for REALITY. \
                 Xray rejects unsafe and hellogolang there"
            }
            Key::OutboundRealityFingerprintUntested => {
                "REALITY fingerprint {} is not one of the browser names the Xray project exercises. \
                 The Xray project exercises chrome, firefox, and safari for REALITY. The core still \
                 accepts this value"
            }
            Key::OutboundPinnedPeerCertSha256Invalid => {
                "each pinnedPeerCertSha256 pin must be a 32-byte SHA-256 fingerprint in hex \
                 (colons optional), comma-separated"
            }
            Key::OutboundTlsVersionRangeInvalid => {
                "TLS version must be one of 1.0, 1.1, 1.2, or 1.3. Xray accepts other strings but \
                 silently ignores them and uses its defaults"
            }
            // The xhttp texts mirror the share-link xhttp grammar refusals
            // and Xray's SplitHTTPConfig.Build vocabulary; the kcp / tproxy /
            // gRPC rules are configuration warnings — Xray loads these
            // configs, the message must not claim they cannot work.
            Key::SrvXhttpModeUnsupported => {
                "mode must be auto, packet-up, stream-up, or stream-one (empty defaults to auto)"
            }
            Key::SrvXhttpPaddingBytesInvalid => {
                "xPaddingBytes bounds must both be positive (0 or empty disables padding)"
            }
            Key::SrvXhttpPaddingPlacementInvalid => {
                "xPaddingPlacement must be cookie, header, query, or queryInHeader"
            }
            Key::SrvXhttpPaddingMethodInvalid => "xPaddingMethod must be repeat-x or tokenish",
            Key::SrvXhttpUplinkPlacementInvalid => {
                "uplinkDataPlacement must be auto, body, cookie, or header"
            }
            Key::SrvXhttpUplinkPlacementPacketUp => {
                "cookie/header uplinkDataPlacement requires packet-up mode"
            }
            Key::SrvXhttpUplinkMethodPacketUp => "uplinkHTTPMethod GET requires packet-up mode",
            Key::SrvXhttpSessionPlacementInvalid => {
                "sessionIDPlacement must be path, cookie, header, or query"
            }
            Key::SrvXhttpSeqPlacementInvalid => {
                "seqPlacement must be path, cookie, header, or query"
            }
            Key::SrvXhttpSessionLengthRequired => {
                "sessionIDLength is required when sessionIDTable is set"
            }
            Key::SrvXhttpSessionTableInvalid => {
                "sessionIDTable must be ASCII and, together with sessionIDLength (from at \
                 least 1), provide at least 2^31 key combinations"
            }
            Key::SrvXhttpXmuxExclusive => {
                "maxConnections and maxConcurrency are mutually exclusive. Choose one"
            }
            Key::XhttpExtraShadowsSettings => {
                "xhttpSettings.extra key {} overrides this setting of the same name. The edited \
                 value never reaches Xray"
            }
            Key::SniffingDestOverrideInvalid => {
                "every destOverride item must be http, tls (or https/ssl), quic, or fakedns \
                 (+others). Xray refuses unknown sniffing protocols"
            }
            Key::OutboundTargetStrategyInvalid => {
                "targetStrategy must be empty or one of asis, useip, useipv4, useipv6, \
                 useipv4v6, useipv6v4, forceip, forceipv4, forceipv6, forceipv4v6, \
                 forceipv6v4 (case-insensitive)"
            }
            Key::SockoptTproxySilentOff => {
                "tproxy must be off, tproxy, or redirect. Xray silently treats every other value as \
                 off, so a typo runs without transparency"
            }
            Key::KcpRangeSoft => {
                "outside the documented mKCP range: mtu 576-1460 and tti 10-100 ms. Xray still \
                 accepts the value and the connection works. Only Xray's documentation recommends \
                 staying in range"
            }
            Key::KcpRangeInvalid => {
                "outside the values the core accepts: mtu must be at least 21 and tti must be \
                 between 10 and 1000 ms. The core refuses to start"
            }
            Key::XhttpServerMaxHeaderBytesInvalid => {
                "serverMaxHeaderBytes cannot be negative. Xray refuses the config at load"
            }
            Key::GrpcNegativeClamp => {
                "must not be negative. Xray silently clamps negative values to zero. Zero itself \
                 disables the timeout or keeps the default window"
            }
            Key::OutboundMuxXudpProxyUdp443Unsupported => {
                "xudpProxyUDP443 must be empty, reject, allow, or skip. Xray refuses every other \
                 value when it builds the mux block. Empty goes out as reject"
            }
            Key::OutboundMuxConcurrencyReinterpreted => {
                "Xray silently reinterprets concurrency. A value of 0 runs as 8. Values above 128 \
                 clamp to 128. Any negative other than the documented -1 disables mux (TCP direct). \
                 Use -1 or a value from 1 through 128"
            }
            Key::OutboundMuxXudpKnobsInert => {
                "Xray reads xudpConcurrency and xudpProxyUDP443 only while mux.enabled is on. With \
                 mux off, UDP still works, but mux does not multiplex it. A Vision flow always \
                 frames UDP as XUDP. To use the two options, enable mux and set xudpConcurrency to \
                 1-128. Keep concurrency at -1 so TCP stays direct. A Vision-flow server rejects mux \
                 connections that carry TCP. xudpProxyUDP443 defaults to reject, which refuses \
                 UDP/443 (QUIC) over mux. Set it to allow if you use QUIC"
            }
            Key::FinalmaskQuicCongestionInvalid => "choose reno, bbr, brutal, or force-brutal",
            Key::FinalmaskQuicBbrProfileInvalid => "choose conservative, standard, or aggressive",
            Key::FinalmaskQuicBandwidthTooSmall => {
                "use 0/empty or at least 524288 bps (65536 bytes/s)"
            }
            Key::FinalmaskQuicBandwidthSyntax => {
                "expected a non-negative decimal number followed by a bandwidth unit"
            }
            Key::FinalmaskQuicBandwidthNonFinite => {
                "bandwidth must be a finite non-negative number"
            }
            Key::FinalmaskQuicBandwidthTooLarge => "bandwidth is too large",
            Key::FinalmaskQuicBandwidthUnitInvalid => {
                "unsupported unit {:?}. Use bps, kbps, mbps, gbps, or tbps"
            }
            Key::FinalmaskQuicForceBrutalNeedsUp => {
                "force-brutal requires a non-zero upload bandwidth"
            }
            Key::FinalmaskQuicHopMoved => {
                "Xray moved the udpHop key to the udphop UDP mask. Add a udphop mask in the UDP \
                 mask list. The old hop behaves like intervalLocal and intervalRemote combined"
            }
            Key::FinalmaskUdpHopModeInvalid => {
                "choose intervalLocal, intervalRemote, or perConnRemote"
            }
            Key::FinalmaskUdpHopIntervalTooSmall => {
                "set each interval endpoint to at least 5 seconds"
            }
            Key::FinalmaskUdpHopIpInvalid => "enter an IP address or a CIDR prefix",
            Key::FinalmaskUdpHopDialerProxyConflict => {
                "The udphop mask cannot run with sockopt.dialerProxy. Remove the mask or the \
                 chain"
            }
            Key::FinalmaskQuicReceiveWindowTooSmall => {
                "use 0 or a receive window of at least 16384 bytes"
            }
            Key::FinalmaskQuicMaxIdleTimeoutInvalid => {
                "use 0 or a value from 4 through 120 seconds"
            }
            Key::FinalmaskQuicKeepAlivePeriodInvalid => {
                "use 0 or a value from 2 through 60 seconds"
            }
            Key::FinalmaskQuicMaxIncomingStreamsInvalid => "use 0 or at least 8 streams",
            Key::FinalmaskPortNumberRange => "port must be from 0 through 65535",
            Key::FinalmaskPortEnvNameRequired => "env: must name an environment variable",
            Key::FinalmaskPortListInvalid => "{} is not a port, port range, or env:NAME entry",
            Key::FinalmaskBytesValueRequired => "{} byte syntax requires a packet/bytes value",
            Key::FinalmaskArrayByteSyntax => {
                "array byte syntax must be a JSON array of integers from 0 through 255"
            }
            Key::FinalmaskStrByteSyntax => "str byte syntax requires a string",
            Key::FinalmaskHexByteSyntax => {
                "hex byte syntax requires an even number of hexadecimal digits"
            }
            Key::FinalmaskBase64ByteSyntax => "base64 byte syntax requires standard padded base64",
            Key::FinalmaskUnknownByteSyntax => {
                "unknown byte syntax {:?}. Choose array, str, hex, or base64"
            }
            Key::FinalmaskTransformOpRequired => "transform operation is required",
            Key::FinalmaskTransformArgRequired => "at least one transform argument is required",
            Key::FinalmaskTransformArgExclusive => {
                "set exactly one of bytes, u64, reuse, metadata, or transform"
            }
            Key::FinalmaskVarNameInvalid => {
                "use a letter or underscore first, then letters, digits, or underscores"
            }
            Key::FinalmaskCustomItemExclusive => {
                "set exactly one of packet, positive rand, reuse, or transform when capture is \
                 used"
            }
            Key::FinalmaskRandRangeInvalid => "both endpoints must be between 0 and 255",
            Key::FinalmaskXmcProfilesRequired => "at least one Minecraft profile is required",
            Key::FinalmaskXmcPasswordRequired => "a Minecraft RSA derivation password is required",
            Key::FinalmaskXmcUsernameInvalid => "use 3–16 ASCII letters, digits, or underscores",
            Key::FinalmaskXmcUuidInvalid => "enter a valid Minecraft profile UUID",
            Key::FinalmaskXmcTexturesRequired => {
                "both texturesValue and texturesSignature are required"
            }
            Key::FinalmaskPacketsFirstNotZero => "the first packet number cannot be 0",
            Key::FinalmaskPacketsSyntax => "use tlshello, one packet number, or from-to",
            Key::FinalmaskLengthsStartAboveZero => "the final length range must start above 0",
            Key::FinalmaskUnknownTcpMask => {
                "unsupported future TCP mask discriminator {:?}. The raw value is preserved"
            }
            Key::FinalmaskUdpHeaderModeInvalid => "choose prefix or standalone",
            Key::FinalmaskMkcpHeaderInvalid => "choose dns, dtls, srtp, utp, wechat, or wireguard",
            Key::FinalmaskNoisePacketExclusive => {
                "packet bytes and a positive random-length range are mutually exclusive"
            }
            Key::FinalmaskSalamanderPacketSize => {
                "use 0 for normal Salamander, or a Gecko range from 1 through 2048"
            }
            Key::FinalmaskXdnsDomainRemoved => {
                "removed by Xray. Remove it and use domains/resolvers"
            }
            Key::FinalmaskXdnsEmpty => "add at least one server domain or client resolver",
            Key::FinalmaskXdnsResolverUdp => "resolver must contain +udp://",
            Key::FinalmaskXicmpIpInvalid => "enter a literal IPv4 or IPv6 address",
            Key::FinalmaskRealmScheme => "scheme must be realm or realm+http",
            Key::FinalmaskRealmHostRequired => "host is required",
            Key::FinalmaskRealmTokenBeforeAt => "put the Realm token before @",
            Key::FinalmaskRealmIdInPath => "put the Realm id in the URL path",
            Key::FinalmaskRealmUrlSyntax => "enter realm://token@host/id ({})",
            Key::FinalmaskRealmStunRequired => "add at least one host:port",
            Key::FinalmaskRealmStunFormat => "use host:port or [IPv6]:port",
            Key::FinalmaskRealmAllowInsecureRemoved => {
                "removed by Xray. Use pinnedPeerCertSha256 or verifyPeerCertByName"
            }
            Key::FinalmaskRealmFingerprintUnknown => "unknown Xray TLS fingerprint",
            Key::FinalmaskRealmAlpnFromMitm => "fromMitm must be the only ALPN value",
            Key::FinalmaskRealmCertRequired => "certificate file or inline certificate is required",
            Key::FinalmaskRealmEchKeysBase64 => "enter standard padded base64",
            Key::FinalmaskUnknownUdpMask => {
                "unsupported future UDP mask discriminator {:?}. The raw value is preserved"
            }
            Key::DashboardMemory => "mem {} · sys {} · {} live objs · GC {}",
            Key::DashboardInboundTraffic => "Inbound traffic",
            Key::GridUp => "Up",
            Key::GridDown => "Down",
            Key::GridType => "Type",
            Key::PreviewConfigTab => "Config",
            Key::PreviewRuntimeTab => "Runtime state",
            Key::RuntimeInbounds => "Inbounds",
            Key::RuntimeOutbounds => "Outbounds",
            Key::RuntimeRefresh => "Refresh",
            Key::RuntimeNotRunning => "core is not running",
            Key::RuntimeLoadFailed => "failed to read runtime state: {}",
            Key::RuntimeEmpty => "(none)",
            Key::TrialRulesSection => "Trial rules",
            Key::TrialRulesExplain => {
                "Inject rules into the running core. They are never persisted and are lost on \
                 restart or a config commit."
            }
            Key::TrialRulesAdd => "New trial rule…",
            Key::TrialRulesWindow => "New trial rule",
            Key::TrialRuleTag => "Rule tag",
            Key::TrialRuleTagHint => "required, and must be unique among the live rules",
            Key::TrialRuleTarget => "Target",
            Key::TrialRulesOutbound => "Outbound",
            Key::TrialRulesBalancer => "Balancer",
            Key::TrialRulesOrderHint => {
                "The core checks a trial rule after every configured rule. A configured rule \
                 that matches first wins."
            }
            Key::TrialRuleDomains => "Domains (one per line)",
            Key::TrialRuleDomainsHint => {
                "plain (substring), domain:, full:, regexp:, keyword:, geosite:CODE"
            }
            Key::TrialRuleIps => "IPs / CIDR (one per line)",
            Key::TrialRuleIpsHint => "IPv4/IPv6, CIDR ranges, geoip:CODE. A leading ! negates",
            Key::TrialRuleProcesses => "Processes (one per line)",
            Key::TrialRulesInject => "Inject",
            Key::TrialRulesRemove => "Remove",
            Key::TrialRulesClearAll => "Clear all",
            Key::TrialRulesEmpty => "no trial rules active",
            Key::TrialRulesNotRunning => "the core must be running to use trial rules",
            Key::TrialRuleTagTaken => "rule tag is already in use",
            Key::TrialRuleTagRequired => "rule tag is required",
            Key::TrialRuleTargetRequired => "choose an outbound or balancer target",
            Key::TrialRuleNeedsCondition => "Enter at least one domain, IP address, or process.",
            Key::TrialRuleTargetNotLive => {
                "The running core has no outbound named {}. Choose another target, or apply the \
                 configuration."
            }
            Key::TrialRuleAddedUnlisted => {
                "The app added the trial rule. The app could not read the live rule list."
            }
            Key::TrialRuleCodeUnknown => "The app found no code {} in the geo data.",
            Key::TrialRulesPending => "applying…",
            Key::TrialRulesRefresh => "Refresh",
            Key::TopbarTrialRules => "trial rules: {} active",
            // Dashboard: traffic units + session totals.
            Key::DashboardTrafficUnits => "Units",
            Key::TrafficUnitAuto => "Auto",
            Key::TrafficUnitBps => "B/s",
            Key::TrafficUnitKiBps => "KiB/s",
            Key::TrafficUnitMiBps => "MiB/s",
            Key::TrafficUnitGiBps => "GiB/s",
            Key::GridUpTotal => "↑ total",
            Key::GridDownTotal => "↓ total",
            // Top-bar speed readout: both rate args carry their own `/s`
            // suffix (the dashboard's rate labels fold it into the
            // template) — "↑ 1.0 MiB/s · ↓ 2.0 MiB/s".
            Key::TopbarSpeed => "↑ {}/s · ↓ {}/s",
            Key::OutboundTrojanFlowRemoved => {
                "flow was removed from Xray's Trojan. The outbound is refused at load. Use VLESS and \
                 set the vision flow there"
            }
            Key::KcpSeedHeaderRemoved => {
                "seed and header were removed from Xray's mKCP. The config is refused at load. \
                 Recreate the camouflage as a finalmask.udp mkcp-legacy or header-custom mask"
            }
            Key::KcpHeaderTypeIgnored => {
                "headerType exists only in share links and is never an Xray JSON setting. Xray \
                 silently ignores it. Remove it"
            }
            Key::OutboundVmessAlterIdIgnored => {
                "Xray's VMess no longer reads alterId and aid. AEAD is the only mode, and the legacy \
                 field is gone. Xray silently ignores the two fields. Remove them"
            }
            Key::OutboundVlessSeedIgnored => {
                "Xray's VLESS parses seed but never applies it, because the upstream assignment is \
                 disabled. The value does nothing. Remove it"
            }
            Key::OutboundFreedomNoiseRemoved => {
                "noise was removed from Xray's freedom. The outbound is refused at load. Use noises, \
                 the array form"
            }
            Key::OutboundFreedomDomainStrategyUnsupported => {
                "domainStrategy must be empty or one of asis, useip, useipv4, useipv6, useipv4v6, \
                 useipv6v4, forceip, forceipv4, forceipv6, forceipv4v6, forceipv6v4 \
                 (case-insensitive). Xray refuses the outbound at load"
            }
            Key::OutboundRealityServerFormKeysInert => {
                "dest, target, privateKey, serverNames, shortIds, and mldsa65Seed are REALITY \
                 server-form keys. A client outbound carries them verbatim and never uses them. dest \
                 or target makes Xray build the server branch instead, so the outbound cannot behave \
                 as a client. Remove them"
            }
            Key::HysteriaQuicKnobsMoved => {
                "congestion, up, down, and udphop were moved from hysteriaSettings to \
                 finalmask.quicParams (congestion, brutalUp, brutalDown, udpHop). Xray accepts them \
                 only to log a warning and drop them. Move the values"
            }
            // Settings-level verdict templates. Parameterized entries keep
            // the `{}`/`{:?}` placeholders that `validation_issue_message`
            // fills; the bytes match the generator's pre-pass strings.
            Key::SettingsActiveProfileMissing => {
                "active server profile ID {} does not match any profile"
            }
            Key::SettingsActiveProfileAmbiguous => {
                "active server profile ID {} is ambiguous: {} profiles use that duplicate ID"
            }
            Key::SettingsProfilesRequired => "Latency test requires at least one server.",
            Key::SettingsProfileIdEmpty => "server profile {} has an empty or whitespace-only ID",
            Key::SettingsProfileIdDuplicated => "server profiles {} and {} have duplicate ID {}",
            Key::SettingsProfileTagEmpty => {
                "server profile {} ({}) generates an empty outbound tag"
            }
            Key::SettingsProfileTagInvalid => {
                "server profile {} ({}) generates invalid outbound tag {}"
            }
            Key::SettingsProfileTagReserved => {
                "server profile {} ({}) generates reserved outbound tag {}"
            }
            Key::SettingsProfileTagDuplicated => {
                "server profiles {} ({}) and {} ({}) generate duplicate outbound tag {}. IDs must \
                 differ within their first 8 characters"
            }
            Key::SettingsOutboundChainMissing => {
                "outbound {} references missing chained outbound {}"
            }
            Key::SettingsOutboundChainCycle => "outbound chain cycle: {}",
            Key::SettingsBalancerNoTag => "balancer {} has no tag",
            Key::SettingsBalancerNoSelector => "balancer {} has no outbound selector",
            Key::SettingsBalancerTagDuplicated => "balancer tag {} is duplicated",
            Key::SettingsBalancerFallbackMissing => {
                "balancer {} references missing fallback outbound {}"
            }
            Key::SettingsLocalInboundPortZero => "local inbound {} needs a non-zero port",
            Key::SettingsInboundTagDuplicated => "inbound tag \"{}\" is duplicated",
            Key::SettingsDokodemoTagMissing => "dokodemo inbound {} has no stable tag",
            Key::SettingsDokodemoNetworkInvalid => "dokodemo inbound {}: {}",
            Key::SettingsDokodemoUnixSocketRequired => {
                "dokodemo inbound {} needs a UNIX socket path"
            }
            Key::SettingsDokodemoUnixSocketConflict => {
                "dokodemo inbound {} conflicts with {} on UNIX socket {}"
            }
            Key::SettingsDokodemoPortZero => "dokodemo inbound {} needs a non-zero listen port",
            Key::SettingsTunIpv4GatewayRequired => {
                "TUN mode needs at least one IPv4 gateway (the in-tun DNS address is derived \
                 from it)"
            }
            Key::SettingsListenerConflict => "{} conflicts with {} on {}:{}",
            Key::SettingsRoutingRuleTarget => "routing rule {}: {}",
            Key::SettingsRoutingRuleOutboundMissing => {
                "routing rule {} references missing outbound {}"
            }
            Key::SettingsRoutingRuleBalancerMissing => {
                "routing rule {} references missing balancer {}"
            }
            Key::SettingsRoutingRuleInboundMissing => {
                "routing rule {} references missing inbound {}"
            }
            Key::SettingsDnsServerAddressMissing => "DNS server {} has no address",
            Key::SettingsFakeDnsPoolCidrInvalid => {
                "fakeDNS pool {}: ipPool must be an IP CIDR range"
            }
            Key::SettingsFakeDnsPoolSizeInvalid => "fakeDNS pool {}: poolSize must be positive",
            Key::SettingsFakeDnsPoolCapacityExceeded => {
                "fakeDNS pool {}: poolSize {} exceeds the {} subnet capacity"
            }
            Key::SettingsGeodataUrlInvalid => "geodata {}: {}",
            Key::SettingsGeodataCronInvalid => "geodata: {}",
            // Runtime diagnostics and file dialogs, rendered at the display boundary.
            Key::RtLogHelperDisconnected => "The elevated helper disconnected.",
            Key::RtLogConnectRejectedStopping => {
                "The app rejected the connect because a core stop is still in progress."
            }
            Key::RtLogConnectIgnoredRunning => {
                "The app ignored the connect because the core is already running."
            }
            Key::RtLogTransportChangeRestart => "The transport changed. The app restarts the core.",
            Key::RtLogTunModeOn => "The app enabled TUN. The core will run elevated.",
            Key::RtLogTunModeOff => "The app disabled TUN. The core will run as a direct child.",
            Key::RtLogCoreStartedHelper => "The elevated helper started the core.",
            Key::RtLogConfigApplied => "The app applied the config.",
            Key::RtLogInternalStartRejected => {
                "The app rejected an internal start because the previous core process is still \
                 alive."
            }
            Key::RtLogNoConfigConnect => {
                "No config.json exists yet. Connect generates the initial configuration."
            }
            Key::RtLogHelperLaunchWait => {
                "The app starts the elevated helper and waits for the authenticated pipe."
            }
            Key::RtLogTunInboundClosed => "The TUN inbound closed cleanly.",
            Key::RtLogTunCloseTimeout => {
                "The TUN graceful close timed out. The app uses the process fallback."
            }
            Key::RtLogTunCoreExited => {
                "The TUN core exited on its own during the wintun create window."
            }
            Key::RtLogTunCoreAlive => {
                "The TUN core is still alive after the wintun create window. The app stops the \
                 core now."
            }
            Key::RtLogDnsFlushExit => {
                "ipconfig exited with a non-zero status during the DNS cache flush."
            }
            Key::RtLogStartupConfigRetry => {
                "The startup config has an error. The app retries once with the last known-good \
                 config."
            }
            Key::RtLogCoreReady => "The core is ready.",
            Key::RtLogExitNotReported => {
                "The core did not report its exit in time. The app forces the final termination."
            }
            Key::RtLogSuppressedOne => "The app suppressed 1 log line.",
            Key::RtLogSuppressedMany => "The app suppressed {} log lines.",
            Key::RtPhaseHelperUnavailable => "The elevated helper is unavailable",
            Key::RtPhaseHelperConfigLost => {
                "The app cannot start the helper because the validated config bytes are gone."
            }
            Key::RtPhaseHelperStartFailed => "The elevated helper did not start",
            Key::RtPhaseBackendReplacementCancelled => {
                "The app cancelled the backend replacement because TUN ownership was unresolved."
            }
            Key::RtPhaseUpdateRecoveryFailed => "The app could not recover the core update",
            Key::RtPhaseApiListenerReadFailed => {
                "The app cannot read the API listener from the active config"
            }
            Key::RtPhaseConfigReadFailed => {
                "The app cannot read the active config for the elevated start"
            }
            Key::RtPhaseCoreSpawnFailed => "The app could not create the core process",
            Key::RtPhaseHelperExitUnconfirmed => {
                "The elevated helper disconnected before the app confirmed the Xray exit."
            }
            Key::RtPhaseConfigError => "The core exited with code 23 after a config error.",
            Key::RtPhaseReadinessTimeout => "The core did not report readiness within {} s.",
            Key::RtPhaseRestartCancelled => {
                "The app cancelled the restart because it could not confirm the old core exit."
            }
            Key::RtFrameCandidateExited => {
                "The applied candidate exited before readiness (code {}): {}"
            }
            Key::RtFrameUpdatedCoreExited => {
                "The updated core exited before readiness (code {}): {}"
            }
            Key::RtFrameNoCoreOutput => "no core output was captured",
            Key::RtFrameCandidateReadyTimeout => {
                "The applied candidate did not become ready within {} s."
            }
            Key::RtFrameUpdatedCoreReadyTimeout => {
                "The updated core did not become ready within {} s."
            }
            Key::RtFrameCommandRejectedBusy => {
                "The app rejected the command because a {} operation is already in progress."
            }
            Key::RtFrameBackgroundFailed => "A background operation failed: {}",
            Key::ProbeExitStatus => "The probe core exited with status {}",
            Key::ProbeExitNoStatus => "The probe core exited without a status code.",
            Key::ProbeWaitFailed => "The app could not wait for the probe core: {}",
            Key::ProbeInterfaceTunSelf => {
                "The probe interface '{}' is the TUN adapter itself. Choose a physical uplink \
                 adapter."
            }
            Key::ProbeInterfaceDown => {
                "The probe interface '{}' is down, so it cannot carry the probe dial. Choose an \
                 active interface or 'auto'."
            }
            Key::ProbeInterfaceMissing => {
                "The probe interface '{}' was not found. Check the TUN outbound-interface setting."
            }
            Key::ProbeHostBlocked => {
                "The latency test URL host is a {} address. The app rejects loopback, link-local, \
                 or cloud-metadata hosts."
            }
            Key::ProbePortAllocateFailed => {
                "The latency test could not allocate a loopback API port: {}"
            }
            Key::ProbePortReadFailed => "The latency test could not read its loopback API port: {}",
            Key::ProbeConfigRejected => "The app rejected the latency test config: {}",
            Key::ProbeTempDirFailed => {
                "The latency test could not create its temporary directory: {}"
            }
            Key::ProbeConfigSerializeFailed => {
                "The app could not serialize the latency test config: {}"
            }
            Key::ProbeConfigWriteFailed => "The app could not write the latency test config: {}",
            Key::ProbeChildLaunchFailed => "The app could not start the probe core: {}",
            Key::ProbeNoProfiles => "The latency test needs at least one server profile.",
            Key::ProbeCancelled => "The app cancelled the latency test: {}",
            Key::ProbeTimedOut => "The latency test timed out after {} s.",
            Key::ProbeTimedOutMissing => {
                "The latency test timed out after {} s. It was waiting for outbound status: {}."
            }
            Key::ProbeTimedOutApiError => {
                "The latency test timed out after {} s. Last API error: {}."
            }
            Key::ProbeTimedOutMissingApiError => {
                "The latency test timed out after {} s. It was waiting for outbound status: {}. \
                 Last API error: {}."
            }
            Key::ProbeDiagnosticsWall => "Xray diagnostics:",
            Key::ShellXrayArchiveFilter => "Xray archive",
            Key::ShellMasterKeyLogFileName => "tls.keys.log",
            Key::ShellCertificateFilter => "Certificate",
            Key::LinkPercentTruncated => "The share link has truncated percent-encoding in {}.",
            Key::LinkPercentEscape => "The share link has a bad percent escape in {}.",
            Key::LinkPercentUtf8 => "The share link has invalid UTF-8 in percent-encoded {}.",
            Key::LinkQueryDuplicate => "The share link repeats the query field {}.",
            Key::LinkNameTooLong => "The profile name exceeds {} bytes.",
            Key::LinkHostMissing => "The host is missing in {}.",
            Key::LinkHostIdn => "IDN hosts in {} must use ASCII punycode.",
            Key::LinkHostInvalid => "The host {} is invalid in {}.",
            Key::LinkHostIpv4 => "The IPv4 host {} is invalid in {}.",
            Key::LinkHostIpv6 => "The IPv6 host {} is malformed in {}.",
            Key::LinkHostIpv6Brackets => "The brackets in {} may wrap only an IPv6 literal.",
            Key::LinkHostBracketed => "The bracketed host in {} is malformed.",
            Key::LinkHostIpv6Unbracketed => "The IPv6 literal in {} must be enclosed in brackets.",
            Key::LinkPortMissing => "The port is missing in {}.",
            Key::LinkPortInvalid => "The port {} is invalid in {}.",
            Key::LinkPortZero => "Port 0 is not valid in {}.",
            Key::LinkUuidInvalid => "The UUID {} is invalid in {}.",
            Key::LinkUuidMissing => "The UUID is missing in {}.",
            Key::LinkNumericParam => "The numeric parameter {} in the share link is invalid: {}.",
            Key::LinkQueryEmpty => "The query field {} must not be empty.",
            Key::LinkTransportUnknown => "The share link names the unknown transport type {}.",
            Key::LinkSecurityUnknown => "The share link names the unknown security value {}.",
            Key::LinkRealityMldsaDuplicate => {
                "The share link carries both pqv and mldsa65Verify. Keep only one REALITY ML-DSA \
                 field."
            }
            Key::LinkGrpcModeUnknown => "The share link names the unknown gRPC mode {}.",
            Key::LinkXhttpModeUnknown => "The share link names the unknown XHTTP mode {}.",
            Key::LinkXhttpExtraJson => "The XHTTP extra value is not valid JSON: {}.",
            Key::LinkXhttpExtraObject => "The XHTTP extra value must be a JSON object.",
            Key::LinkXhttpExtraReserved => {
                "The XHTTP extra value must not contain the reserved field {}."
            }
            Key::LinkFinalmaskJson => "The finalmask value is not valid JSON: {}.",
            Key::LinkUserinfoMissing => "The {} link has no userinfo@host part.",
            Key::LinkUserinfoAt => "The userinfo in the {} link must percent-encode '@' as %40.",
            Key::LinkVmessBase64 => "The vmess link does not carry valid Base64 data.",
            Key::LinkVmessJson => "The vmess link does not carry valid JSON: {}.",
            Key::LinkVmessObject => "The vmess link JSON must be an object.",
            Key::LinkLegacyFieldType => "The legacy vmess JSON field {} has the wrong value type.",
            Key::LinkVmessAdd => "The vmess link is missing the add field.",
            Key::LinkVmessPort => "The vmess link has the invalid port {}.",
            Key::LinkVmessTcpType => "The vmess link names the unknown TCP type {}.",
            Key::LinkVmessNet => "The vmess link names the unknown net value {}.",
            Key::LinkTrojanPasswordEmpty => "The trojan link has an empty password.",
            Key::LinkSsUserinfoAt => "The ss link userinfo must percent-encode '@' as %40.",
            Key::LinkSsBase64 => {
                "The ss link has no userinfo@host part, and its payload is not valid Base64."
            }
            Key::LinkSsUtf8 => "The ss link Base64 payload is not valid UTF-8.",
            Key::LinkSsUserinfoFormat => "The ss link userinfo must be method:password.",
            Key::LinkSsMethodEmpty => "The ss link has an empty method.",
            Key::LinkSsPasswordEmpty => "The ss link has an empty password.",
            Key::LinkRealityServerNameEmpty => "The REALITY server name must not be empty.",
            Key::LinkRealityFingerprint => "The REALITY fingerprint {} is unknown or unsafe.",
            Key::LinkRealityPbk => "REALITY pbk must hold a 32-byte base64url key.",
            Key::LinkRealitySid => {
                "REALITY sid must hold an even-length hexadecimal value of up to 16 digits."
            }
            Key::LinkRealityPqv => "REALITY pqv must hold a 1952-byte base64url ML-DSA-65 key.",
            Key::LinkRealitySpx => "REALITY spx must hold a URL path that begins with '/'.",
            Key::LinkTlsFingerprint => "The TLS fingerprint {} is unknown.",
            Key::LinkTlsAlpnFromMitm => "TLS alpn accepts only one element when it uses fromMitm.",
            Key::LinkTlsPcs => {
                "TLS pcs entries must be 32-byte hexadecimal SHA-256 fingerprints, comma-separated."
            }
            Key::LinkXhttpMode => "The XHTTP mode {} is not supported.",
            Key::LinkXhttpHeaderValues => "Every XHTTP header value must be a string.",
            Key::LinkXhttpHostHeader => "XHTTP headers cannot contain Host. Use the host field.",
            Key::LinkXhttpPaddingBytes => "XHTTP xPaddingBytes values must be positive.",
            Key::LinkXhttpPaddingPlacement => "The XHTTP xPaddingPlacement value is not supported.",
            Key::LinkXhttpPaddingMethod => "The XHTTP xPaddingMethod value is not supported.",
            Key::LinkXhttpUplinkPlacement => {
                "The XHTTP uplinkDataPlacement value is not supported."
            }
            Key::LinkXhttpUplinkMode => {
                "The XHTTP cookie and header uplinkDataPlacement values need packet-up mode."
            }
            Key::LinkXhttpUplinkMethod => "The XHTTP uplinkHTTPMethod GET needs packet-up mode.",
            Key::LinkXhttpSessionPlacement => {
                "The XHTTP sessionIDPlacement value is not supported."
            }
            Key::LinkXhttpSeqPlacement => "The XHTTP seqPlacement value is not supported.",
            Key::LinkXhttpSessionLength => "The XHTTP sessionIDTable needs a sessionIDLength.",
            Key::LinkXhttpSessionSpace => {
                "The XHTTP sessionIDTable and sessionIDLength leave too little ASCII key space."
            }
            Key::LinkXhttpServerMaxHeader => "The XHTTP serverMaxHeaderBytes cannot be negative.",
            Key::LinkXhttpXmux => {
                "The XHTTP maxConnections and maxConcurrency cannot be set together."
            }
            Key::LinkXhttpStreamOne => "The XHTTP stream-one mode cannot contain downloadSettings.",
            Key::LinkRawHeaderType => "The raw transport header type {} is not supported.",
            Key::LinkRawCamouflage => "The raw request and response camouflage needs type=http.",
            Key::LinkRawHeaderValues => {
                "The raw HTTP camouflage headers must be strings or string arrays."
            }
            Key::LinkKcpMtu => "The mKCP mtu must be at least 21.",
            Key::LinkKcpTti => "The mKCP tti must be between 10 and 1000.",
            Key::LinkKcpCwnd => "The mKCP cwndMultiplier must be at least 1.",
            Key::LinkKcpWindow => "The mKCP maxSendingWindow must be at least mtu.",
            Key::LinkWsHeaderValues => "Every ws header value must be a string.",
            Key::LinkGrpcServiceName => "The gRPC serviceName must not be empty.",
            Key::LinkHttpupgradeHeaderValues => "Every httpupgrade header value must be a string.",
            Key::LinkProtocolMismatch => "The outbound protocol {} does not match the {} settings.",
            Key::LinkVlessFlow => "The vless flow {} is not supported.",
            Key::LinkVlessEncryption => "The vless encryption {} is not supported.",
            Key::LinkTrojanIncomplete => "The trojan link needs a host, a port, and a password.",
            Key::LinkSsIncomplete => "The ss link needs a host, a port, and a password.",
            Key::LinkSsMethod => "Xray core does not support the ss method {}.",
            Key::LinkSsKeyMaterial => "The Shadowsocks 2022 key material is not valid.",
            Key::LinkTooLong => "The share link is too long: {} bytes. The limit is {} bytes.",
            Key::LinkNoScheme => "The share link has no scheme prefix: {}.",
            Key::LinkBadScheme => "The share link has an invalid scheme: {}.",
            Key::LinkSubscriptionTooLarge => {
                "The pasted text is too large: {} bytes. The limit is {} bytes."
            }
            Key::LinkFinalmaskInvalid => "The finalmask settings are invalid: {}",
            Key::LinkUnsupportedTypeHttp => {
                "Xray core removed the type=http/h2/h3 transport. Use xhttp."
            }
            Key::LinkUnsupportedTypeQuic => "Xray core removed the type=quic transport.",
            Key::LinkUnsupportedXtls => "Xray core removed XTLS. Use reality or tls.",
            Key::LinkUnsupportedTrojanEncryption => "Trojan share links have no encryption field.",
            Key::LinkUnsupportedFlow => "The flow parameter is defined only for VLESS links.",
            Key::LinkUnsupportedGrpcGuna => {
                "The gRPC mode guna uses a custom codec, which Xray cannot configure."
            }
            Key::LinkUnsupportedTransportMode => {
                "The mode parameter is not defined for the transport type {}."
            }
            Key::LinkUnsupportedAllowInsecure => {
                "Xray core removed allowInsecure. Use certificate pinning."
            }
            Key::LinkUnsupportedField => {
                "The field {} is not part of the current #716 grammar. Xray core removed it."
            }
            Key::LinkUnsupportedVmessAlterId => {
                "VMess alterId is not part of the AEAD share-link format."
            }
            Key::LinkUnsupportedQueryField => "The query field {} is not defined for this link.",
            Key::LinkUnsupportedHysteria => "The hysteria transport has no share-link mapping.",
            Key::LinkUnsupportedLegacyField => {
                "The legacy vmess JSON field {} cannot be represented by the #716 URL format."
            }
            Key::LinkUnsupportedLegacyVersion => {
                "The legacy vmess JSON version {} is not supported."
            }
            Key::LinkUnsupportedVmessAlterIdValue => {
                "The vmess link sets alterId={}. Xray core removed VMess-MD5, so links use AEAD \
                 only."
            }
            Key::LinkUnsupportedVmessTls => "The legacy vmess JSON cannot express tls={}.",
            Key::LinkUnsupportedVmessTcpHostPath => {
                "The legacy vmess TCP host and path have no meaning without type=http."
            }
            Key::LinkUnsupportedVmessKcp => {
                "Xray core removed the legacy vmess mKCP seed and header camouflage."
            }
            Key::LinkUnsupportedVmessWebsocket => {
                "The legacy vmess WebSocket type={} is not representable."
            }
            Key::LinkUnsupportedVmessHttpupgrade => {
                "The legacy vmess HTTPUpgrade type={} is not representable."
            }
            Key::LinkUnsupportedVmessXhttp => {
                "The legacy vmess XHTTP type={} is not representable."
            }
            Key::LinkUnsupportedVmessNetHttp => {
                "Xray core removed the vmess net=http/h2/h3 transport. Use xhttp."
            }
            Key::LinkUnsupportedVmessNetQuic => "Xray core removed the vmess net=quic transport.",
            Key::LinkUnsupportedSsPlugin => {
                "Xray core share profiles do not support SIP002 plugins."
            }
            Key::LinkUnsupportedSsQueryField => {
                "The ss link carries the query field {}, which SIP002 does not support."
            }
            Key::LinkUnsupportedVmessEncryption => {
                "This Xray core does not implement the vmess encryption {}."
            }
            Key::LinkUnsupportedProtocol => "The {} protocol has no share-link format.",
            Key::LinkUnsupportedScheme => "The share link uses the unsupported scheme {}.",
            Key::LinkLossyPolicyLevel => "The share-link grammar has no policy level for {}.",
            Key::LinkLossyEmail => "The share-link grammar has no email field for {}.",
            Key::LinkLossyVlessReverse => "The VLESS reverse setting {} has no share-link field.",
            Key::LinkLossyVlessExtra => {
                "The VLESS settings field {} is not representable in a share link."
            }
            Key::LinkLossyVmessExtra => {
                "The VMess settings field {} is not representable in a share link."
            }
            Key::LinkLossyTrojanExtra => {
                "The Trojan settings field {} is not representable in a share link."
            }
            Key::LinkLossySsExtra => {
                "The Shadowsocks settings field {} is not representable in a share link."
            }
            Key::LinkLossyVmessExperiments => {
                "The VMess experiments field {} holds local Xray state."
            }
            Key::LinkLossyTlsAdvanced => {
                "The {} block carries advanced TLS options: versions, ciphers, curves, certificates, \
                 session and root stores, key log, ECH sockopt, and unknown fields. The #716 grammar \
                 has no field for them."
            }
            Key::LinkLossyRealityAdvanced => {
                "The {} block carries show, masterKeyLog, and unknown REALITY fields. The #716 \
                 grammar has no field for them."
            }
            Key::LinkLossySockopt => {
                "The {} block carries socket options, which are local connection policy."
            }
            Key::LinkLossyStreamExtra => {
                "The {} block carries unknown settings that the #716 grammar has no field for."
            }
            Key::LinkLossyTlsMissing => {
                "The {} block has no TLS settings. The export would use the #716 TLS defaults."
            }
            Key::LinkLossyRealityMissing => "The {} block needs REALITY settings.",
            Key::LinkLossyTlsUnselected => {
                "The {} block holds TLS settings while TLS is not selected."
            }
            Key::LinkLossyRealityUnselected => {
                "The {} block holds REALITY settings while REALITY is not selected."
            }
            Key::LinkLossyRawCamouflage => {
                "The {} block holds raw HTTP camouflage data that the #716 grammar does not define."
            }
            Key::LinkLossyKcp => {
                "The {} block holds mKCP options. The #716 grammar carries only mtu and tti."
            }
            Key::LinkLossyWs => {
                "The {} block holds WebSocket options. The #716 grammar carries only host and path."
            }
            Key::LinkLossyGrpc => {
                "The {} block holds gRPC options. The #716 grammar carries only serviceName, \
                 authority, and the gun or multi mode."
            }
            Key::LinkLossyHttpupgrade => {
                "The {} block holds HTTPUpgrade options. The #716 grammar carries only host and \
                 path."
            }
            Key::LinkLossyTransportUnselected => {
                "The {} block holds settings for a transport that the profile does not select."
            }
            Key::LinkLossySsStream => {
                "The {} block holds transport, security, sockopt, or finalmask state. SIP002 share \
                 links cannot carry it."
            }
            Key::LinkLossyProfileExtra => "The profile metadata field {} has no share-link field.",
            Key::LinkLossyDialerProxy => {
                "The profile dials through another server in {}, which is local configuration."
            }
            Key::LinkLossySendThrough => {
                "The profile binds a local source address in {}, which is not shareable."
            }
            Key::LinkLossyTargetStrategy => {
                "The profile sets the local resolution policy in {}, which is not shareable."
            }
            Key::LinkLossyMux => {
                "The profile sets mux policy in {}, which has no share-link mapping."
            }
            Key::LinkLossyOutboundExtra => "The outbound field {} has no share-link mapping.",
            Key::LinkLossyProfileName => {
                "The descriptive fragment cannot reproduce the profile name in {}."
            }
            Key::LinkLossyProfileRoundtrip => {
                "The share-link grammar cannot reproduce every outbound field in {}."
            }
            Key::LinkLossyXhttpSerialize => {
                "The app cannot serialize the XHTTP extra JSON in {}: {}."
            }
            Key::LinkLossyXhttpEncode => "The app cannot encode the XHTTP extra JSON in {}: {}.",
            Key::LinkLossyFinalmaskEncode => "The app cannot encode the finalmask JSON in {}: {}.",
            Key::GenRawOverride => "The raw override is not valid JSON: {}",
            Key::GenApiListenerPortZero => "The API listener needs a non-zero port.",
            Key::GenProbePortZero => "The latency probe API listener needs a non-zero port.",
            Key::GenProbeUrlInvalid => "The latency probe URL must be an absolute HTTP(S) URL: {}.",
            Key::GenProbeUrlNotAbsolute => "The latency probe URL must be an absolute HTTP(S) URL.",
            Key::GenObservatoryProbeHostBlocked => {
                "The observatory probe URL host is a {} address. Probing loopback, link-local, or \
                 cloud-metadata hosts is not allowed."
            }
            Key::GenProbeHostBlocked => {
                "The latency probe URL host is a {} address. Probing loopback, link-local, or \
                 cloud-metadata hosts is not allowed."
            }
            Key::GenApiPort => "The app cannot allocate a loopback API port: {}",
            Key::IntegrityBalancerMissing => "The balancer at index {} does not exist.",
            Key::IntegrityBalancerTagEmpty => "The balancer tag is required.",
            Key::IntegrityBalancerTagDuplicate => "The balancer tag {} is already in use.",
            Key::IntegrityBalancerReferenced => "The balancer {} is used by {} routing rule(s).",
            Key::IntegrityRuleTargetRequired => "Choose an outbound or balancer target.",
            Key::IntegrityRuleTargetExclusive => {
                "A rule cannot target both an outbound and a balancer."
            }
            Key::IntegrityRouteTargetRequired => "Enter a target domain or at least one target IP.",
            Key::IntegrityRouteTargetPort => "The target port must be between 1 and 65535.",
            Key::IntegrityRoutePort => "The {} must be between 1 and 65535, or 0 for unknown.",
            Key::IntegrityRouteIp => "The {} IP address {} is not valid.",
            Key::IntegrityRouteNetwork => "The route test does not support the network {}.",
            Key::IntegrityRouteAttributeKey => "The attribute key {} is empty.",
            Key::RtLogOperationCancelled => "The app cancelled the {} operation: {}",
            Key::RtLogUpdateFinishedAfterStop => {
                "The core update finished after the stop request. The updated core is on disk and \
                 the app health-checks it on the next start."
            }
            Key::RtLogApiEndpointCommitted => "The app committed the API endpoint as 127.0.0.1:{}.",
            Key::RtLogApiEndpointRecovered => {
                "The app recovered the API endpoint from the active config as 127.0.0.1:{}."
            }
            Key::RtLogCoreStartedDirect => "The app started the core as a direct child (pid {}).",
            Key::RtLogTunGracefulCloseFailed => {
                "The TUN graceful close failed. The app uses the process fallback: {}"
            }
            Key::RtLogTunCoreStopWindow => {
                "The TUN core did not answer the graceful close. The app waits out the wintun create \
                 window before the stop to prevent a PnP wedge."
            }
            Key::RtLogHelperStopFailed => "The app could not stop the elevated helper",
            Key::RtLogDnsFlushFailed => "The app could not flush the DNS cache: {}",
            Key::RtLogCoreExitBackoff => {
                "The core exited unexpectedly (code {}). The app restarts the core as attempt {} in \
                 {} ms."
            }
            Key::RtLogDnsInListenerAdded => "The app added the in-tun DNS listener on {}:{}.",
            Key::RtLogDnsInListenerNotAdded => {
                "The app did not add the in-tun DNS listener: {}. The listener is best-effort."
            }
            Key::RtLogUpdateCancelRequested => {
                "The app requested the cancellation of the core update: {}. The in-flight install \
                 finishes before the app releases the update slot."
            }
            Key::RtLogValidationCancelRequested => {
                "The app requested the cancellation of the profile validation: {}. The in-flight \
                 validation finishes before the app releases the busy window."
            }
            Key::RtLogUpdateAckFailed => {
                "The core is ready. The app could not acknowledge the core update"
            }
            Key::RtFramePreviewReadFailed => {
                "The app could not read the active config for the preview"
            }
            Key::RtPhaseHelperLaunchFailed => {
                "The app could not start the elevated helper because TUN needs administrator \
                 approval"
            }
            Key::RtFrameApplyRejected => "The app rejected the config apply",
            Key::RtFrameCandidateWriteFailed => "The app could not write the candidate config",
            Key::RtFrameApplyCaptureFailed => {
                "The config passed validation. The app could not capture its bytes"
            }
            Key::RtFrameApplyCommitFailed => {
                "The config passed validation. The app could not commit it"
            }
            Key::RtFrameUpdatedCoreSpawnRestored => {
                "The app restored the retained last-good core because the updated core did not start"
            }
            Key::RtFrameUpdatedCoreSpawnNoLastGood => {
                "No retained last-good core was available after the updated core did not start"
            }
            Key::RtFrameUpdatedCoreSpawnRollbackFailed => {
                "The core rollback failed after the updated core did not start: {}"
            }
            Key::RtFrameRolledBackLastGood => {
                "{} The app rolled back to the last known-good config."
            }
            Key::RtFrameRollbackFailed => "{} The rollback failed",
            Key::RtFrameCoreRestored => "{} The app restored the retained last-good core.",
            Key::RtFrameCoreNoLastGood => "{} No retained last-good core was available.",
            Key::RtFrameCoreRollbackFailed => "{} The core rollback failed",
            Key::RtFrameStartupRollbackFailed => "The app could not roll back the startup config",
            Key::RtFrameApplyCancelled => "The app cancelled the apply: {}",
            Key::RtFrameConfigTestCancelled => "The app cancelled the config test: {}",
            Key::RtFrameProfileValidationCancelled => {
                "The app cancelled the profile validation: {}"
            }
            Key::RtFrameConfigRollbackCancelled => {
                "{} The app cancelled the rollback because the old backend exit was not confirmed."
            }
            Key::RtFrameCoreRollbackCancelled => {
                "{} The app cancelled the core rollback because the old backend exit was not \
                 confirmed."
            }
            Key::RtFrameCandidateRetryBindRace => {
                "{} The app retries the candidate because of the dns-in bind race. This is attempt \
                 {} of {}."
            }
            Key::RtFrameCandidateRetryTeardownRace => {
                "{} The app retries the candidate because of the adapter teardown race. This is \
                 attempt {} of {}."
            }
            Key::RtFrameUpdateRetryBindRace => {
                "{} The app retries the core update because of the dns-in bind race. This is attempt \
                 {} of {}."
            }
            Key::RtFrameUpdateStopCoreFirst => "Stop the core first.",
            Key::RtFrameUpdateHealthCheckPending => {
                "Start the updated core once to complete its health check before another update."
            }
            Key::RtFrameUpdatedCoreReadyTimeoutApi => {
                "The updated core did not become ready within {} s. The last API error was: {}"
            }
            Key::RtFrameStageCheckingRelease => "checking the pinned release",
            Key::RtFrameStageVerifyingArchive => "verifying the selected archive",
            Key::RtFrameArchiveWorkerFailed => "The local archive worker failed",
            Key::RtFrameCandidateLostHelper => {
                "the applied candidate lost its helper before the app confirmed the exit"
            }
            Key::RtFrameUpdatedCoreLostHelper => {
                "the updated core lost its helper before the app confirmed the exit"
            }
            Key::RtFrameApiListenerNotOwned => {
                "the API listener on the active port is not owned by the spawned core"
            }
            Key::RtFrameApiProbeFailed => "the readiness probe failed: {}",
            Key::RtReasonStopRequested => "stop requested",
            Key::RtReasonShutdownRequested => "shutdown requested",
            Key::RtReasonGuiChannelClosed => "the GUI command channel closed",
            Key::RtReasonCoreExitedUnexpectedly => "the core exited unexpectedly",
            Key::RtReasonHelperDisconnected => "the elevated helper disconnected unexpectedly",
            Key::OperationConnect => "connect",
            Key::OperationDisconnect => "disconnect",
            Key::OperationRestart => "restart",
            Key::OperationApplyConfig => "config apply",
            Key::OperationTestConfig => "config test",
            Key::OperationUpdateCore => "core update",
            Key::OperationLatencyProbe => "latency test",
            Key::OperationValidateProfiles => "profile validation",
            Key::SeatRuntimeStopping => {
                "The request was cancelled because the runtime is stopping."
            }
            Key::SeatCoreNotRunning => "The core is not running.",
            Key::SeatBalancerTagRequired => "The balancer tag is required.",
            Key::SeatOverrideTargetRequired => {
                "The override target is required. Use Clear override to remove the override."
            }
            Key::SeatRuleTagRequired => "The rule tag is required.",
            Key::SeatInvalidRouteTest => "The app rejected the route test",
            Key::SeatInvalidTrialRule => "The app rejected the trial rule",
            Key::SeatBusyWithOperation => "The runtime is busy with a {} operation.",
            Key::SeatValidationCancelled => {
                "The app cancelled the profile validation before it finished."
            }
            Key::GrpcTestRouteFailed => "The route test failed: {}",
            Key::GrpcBalancerInfoFailed => "The app could not read the balancer info: {}",
            Key::GrpcBalancerInfoMissing => "The core returned no balancer information.",
            Key::GrpcBalancerNotFound => {
                "The running core has no balancer named {}. Apply the configuration, then \
                 refresh the runtime state."
            }
            Key::GrpcBalancerOverrideFailed => "The app could not set the balancer override: {}",
            Key::GrpcBalancerOverrideClearFailed => {
                "The app could not clear the balancer override: {}"
            }
            Key::GrpcRestartLoggerFailed => "The app could not restart the core logger: {}",
            Key::GrpcAddRuleFailed => "The app could not add the trial rule: {}",
            Key::GrpcRemoveRuleFailed => "The app could not remove the trial rule: {}",
            Key::GrpcListRulesFailed => "The app could not read the trial rules: {}",
            Key::GrpcRuntimeStateFailed => "The app could not read the runtime state: {}",
            Key::GrpcTrialRuleTagRequired => "The trial rule needs a rule tag.",
            Key::GrpcTrialRuleFieldUnsupported => "The app does not support '{}' in trial rules.",
            Key::GrpcTrialRuleTargetRequired => "Choose an outbound or a balancer target.",
            Key::GrpcTrialRuleTargetConflict => {
                "A rule cannot target both an outbound and a balancer."
            }
            Key::GrpcGeodataSyntaxError => "The geodata entry has a syntax error.",
            Key::GrpcGeodataEmptyFile => "The geodata file name is empty.",
            Key::GrpcGeodataEmptyAttr => "The geodata attribute is empty.",
            Key::GrpcGeodataEmptyCode => "The geodata code is empty.",
            Key::GrpcDotlessRuleContainsDot => "A dotless rule must not contain a dot.",
            Key::GrpcUnsupportedAddressFamily => "The app does not support this address family.",
            Key::GrpcInvalidCidrPrefix => "The CIDR prefix length '{}' is not a number.",
            Key::GrpcCidrPrefixTooLong => "The CIDR prefix length {} exceeds the maximum of {}.",
            Key::GrpcInvalidRouteIp => "The {} IP '{}' is not an address.",
            Key::GrpcUnsupportedNetwork => "The app does not support the network '{}'.",
            Key::HelperPipeIdInvalid => "The helper pipe id is invalid.",
            Key::HelperParentArgMissing => "The helper command line carries no parent process id.",
            Key::HelperParentArgDuplicate => {
                "The helper command line carries more than one parent process id."
            }
            Key::HelperParentArgInvalid => {
                "The helper command line carries an invalid parent process id."
            }
            Key::HelperProcessOpenFailed => {
                "The elevated helper could not open process {} for the identity check"
            }
            Key::HelperProcessTimeReadFailed => {
                "The elevated helper could not read the creation time of process {}"
            }
            Key::HelperParentExitedBeforeConnect => {
                "The launching app exited before the helper connection."
            }
            Key::HelperConnectTimeout => "The helper client did not connect in time.",
            Key::HelperConnectFailed => {
                "The app could not connect to the helper pipe {}. The helper may not be running"
            }
            Key::HelperParentOpenFailed => {
                "The elevated helper could not open the launching app process"
            }
            Key::HelperParentExitedBeforePipe => {
                "The launching app exited before the helper created the pipe."
            }
            Key::HelperParentTimeReadFailed => {
                "The elevated helper could not read the creation time of the launching app"
            }
            Key::HelperParentTokenOpenFailed => {
                "The elevated helper could not open the launching app token"
            }
            Key::HelperParentSidReadFailed => {
                "The elevated helper could not read the launching app user SID"
            }
            Key::HelperOwnTokenOpenFailed => {
                "The elevated helper could not open its own process token"
            }
            Key::HelperOwnSidReadFailed => "The elevated helper could not read its own user SID",
            Key::HelperWellKnownSidFailed => {
                "The elevated helper could not create a protected runtime SID"
            }
            Key::HelperPipeAttributesFailed => {
                "The elevated helper could not build the protected pipe attributes"
            }
            Key::HelperPipeCreateFailed => "The elevated helper could not create its pipe",
            Key::HelperPipeModeFailed => {
                "The elevated helper could not set the helper server pipe mode"
            }
            Key::HelperClientPidReadFailed => {
                "The elevated helper could not read the pipe client process id"
            }
            Key::HelperClientTimeReadFailed => {
                "The elevated helper could not read the pipe client creation time"
            }
            Key::HelperClientNotLaunchingGui => "The helper pipe client was not the launching app.",
            Key::HelperPipeDuplicateFailed => "The helper pipe could not be duplicated",
            Key::HelperAuthReadFailed => {
                "The elevated helper could not read the authentication message"
            }
            Key::HelperAuthMessageMissing => "The helper authentication message is missing.",
            Key::HelperAuthParseFailed => "The helper authentication message is not valid JSON",
            Key::HelperAuthRejected => "The elevated helper rejected the authentication.",
            Key::HelperAuthTimeout => "The helper authentication did not finish in time.",
            Key::HelperPipeClosed => "The helper pipe closed",
            Key::HelperAuthTokenInvalid => "The helper authentication token is invalid.",
            Key::HelperParentPidInvalid => "The helper parent process id is invalid.",
            Key::HelperConnectCancelled => "The app cancelled the helper connection.",
            Key::HelperClientPipeModeFailed => "The app could not set the helper client pipe mode",
            Key::HelperPipeWriterPoisoned => "The helper pipe writer is poisoned.",
            Key::HelperAuthWriteFailed => "The app could not send the helper authentication",
            Key::HelperAuthFlushFailed => "The app could not flush the helper authentication",
            Key::HelperReaderThreadFailed => "The app could not start the helper reader thread",
            Key::HelperStartPortInvalid => "The start command API port is invalid.",
            Key::HelperStartCorePathNotAbsolute => "The managed helper core path is not absolute.",
            Key::HelperPipeWriteFailed => "The app could not write to the helper pipe",
            Key::HelperPipeFlushFailed => "The app could not flush the helper pipe",
            Key::HelperProgramDataResolveFailed => {
                "The elevated helper could not resolve the ProgramData folder"
            }
            Key::HelperProgramDataDecodeFailed => {
                "The elevated helper could not decode the ProgramData folder path"
            }
            Key::HelperProgramDataInspectFailed => "The elevated helper could not inspect {}",
            Key::HelperProgramDataNotDirectory => {
                "The ProgramData folder is not a local ordinary directory."
            }
            Key::HelperDirectoryInspectFailed => {
                "The elevated helper could not inspect the protected directory {}"
            }
            Key::HelperDirectoryNotOrdinary => {
                "The protected runtime path is not an ordinary directory."
            }
            Key::HelperDescriptorSizeQueryFailed => {
                "The elevated helper could not query the size of the protected runtime security \
                 descriptor."
            }
            Key::HelperDescriptorReadFailed => {
                "The elevated helper could not read the protected runtime security descriptor"
            }
            Key::HelperDescriptorControlReadFailed => {
                "The elevated helper could not read the protected runtime DACL control bits"
            }
            Key::HelperOwnerReadFailed => {
                "The elevated helper could not read the protected runtime owner"
            }
            Key::HelperDaclReadFailed => {
                "The elevated helper could not read the protected runtime DACL"
            }
            Key::HelperDaclMissingOrInherited => {
                "The protected runtime directory DACL is missing or inherited."
            }
            Key::HelperOwnerUnexpected => {
                "The protected runtime directory owner is not Administrators or the helper user."
            }
            Key::HelperDaclMissing => "The protected runtime directory DACL is missing.",
            Key::HelperDaclUnexpectedPrincipals => {
                "The protected runtime directory DACL has {} ACEs instead of 2."
            }
            Key::HelperAceReadFailed => {
                "The elevated helper could not read a protected runtime ACE"
            }
            Key::HelperAceMalformed => "The protected runtime directory has a malformed ACE.",
            Key::HelperAceNotFullControl => {
                "The protected runtime directory has a non-allow or non-full-control ACE."
            }
            Key::HelperAceSystemRepeated => {
                "The protected runtime directory repeats the SYSTEM ACE."
            }
            Key::HelperAceAdministratorsRepeated => {
                "The protected runtime directory repeats the Administrators ACE."
            }
            Key::HelperAceUnexpectedSid => {
                "The protected runtime directory grants an unexpected SID."
            }
            Key::HelperAcePrincipalMissing => {
                "The protected runtime directory omits a required principal."
            }
            Key::HelperDeviationNotBenign => {
                "The protected directory deviation is no longer benign."
            }
            Key::HelperDescriptorBuildFailed => {
                "The elevated helper could not build the protected runtime descriptor"
            }
            Key::HelperDaclRepairFailed => {
                "The elevated helper could not repair the protected directory DACL"
            }
            Key::HelperDirectoryAttributesFailed => {
                "The elevated helper could not build the protected directory attributes"
            }
            Key::HelperDirectoryCreateFailed => {
                "The elevated helper could not create the protected directory {}"
            }
            Key::HelperStageEnumerateFailed => {
                "The elevated helper could not enumerate the secure stage {}"
            }
            Key::HelperStageEntryReadFailed => {
                "The elevated helper could not read a secure stage entry"
            }
            Key::HelperStageEntryInspectFailed => {
                "The elevated helper could not inspect the secure stage entry {}"
            }
            Key::HelperStageEntryUnexpected => {
                "The secure stage contains an unexpected or reparse entry."
            }
            Key::HelperStageMarkerMissing => {
                "The stale runtime directory lacks the Broccoli stage marker."
            }
            Key::HelperStageEntryRemoveFailed => {
                "The elevated helper could not remove the secure stage entry {}"
            }
            Key::HelperStageRemoveFailed => {
                "The elevated helper could not remove the secure stage {}"
            }
            Key::HelperStagedConfigCreateFailed => {
                "The elevated helper could not create the staged config {}"
            }
            Key::HelperStagedConfigWriteFailed => {
                "The elevated helper could not write the staged config"
            }
            Key::HelperStagedConfigFlushFailed => {
                "The elevated helper could not flush the staged config to disk"
            }
            Key::HelperStagedConfigLockFailed => {
                "The elevated helper could not lock the staged config {}"
            }
            Key::HelperStagedConfigProofFailed => "The staged config failed its copy proof.",
            Key::HelperStageMarkerCreateFailed => {
                "The elevated helper could not create the secure stage marker {}"
            }
            Key::HelperStageMarkerWriteFailed => {
                "The elevated helper could not write the secure stage marker"
            }
            Key::HelperStageMarkerFlushFailed => {
                "The elevated helper could not flush the secure stage marker"
            }
            Key::HelperHashRewindFailed => "The elevated helper could not rewind the hash input",
            Key::HelperHashReadFailed => "The elevated helper could not read the hash input",
            Key::HelperWirePathMissing => "The start command has no UTF-16 source path.",
            Key::HelperWirePathLengthInvalid => {
                "The start command carries a source path of invalid length."
            }
            Key::HelperWirePathUnitInvalid => {
                "The start command carries an invalid UTF-16 source path unit."
            }
            Key::HelperWirePathNul => "The start command source path contains a NUL unit.",
            Key::HelperWirePathNotAbsolute => "The start command source path is not absolute.",
            Key::HelperWireConfigMissing => "The start command has no configuration content.",
            Key::HelperWireConfigEncodingInvalid => {
                "The start command configuration content is not valid base64."
            }
            Key::HelperWirePortInvalid => "The start command carries an invalid API port.",
            Key::HelperConfigTooLarge => {
                "The configuration content of {} bytes cannot cross the helper pipe with its {} byte \
                 cap, so the app refuses to start."
            }
            Key::HelperMalformedStartCommand => {
                "The elevated helper rejected a malformed start command"
            }
            Key::HelperStageValidated => {
                "The elevated helper staged and validated the pinned Xray core {}."
            }
            Key::HelperStageRefused => {
                "The elevated helper refused to start the core before secure staging"
            }
            Key::HelperCoreSpawnFailed => "The elevated helper could not start the staged core",
            Key::HelperJobSetupFailed => {
                "The elevated helper could not isolate the staged core in a job object"
            }
            Key::HelperShieldRemovedAfterExit => {
                "Core {} exited during the adapter index poll, so the elevated helper removed the \
                 DNS shield again."
            }
            Key::HelperShieldNotInstalledAfterExit => {
                "Core {} exited during the adapter index poll, so the elevated helper did not \
                 install the DNS shield."
            }
            Key::HelperDnsShieldTeardownFailed => {
                "The elevated helper could not remove the DNS shield"
            }
            Key::HelperDnsShieldNotEngaged => {
                "The elevated helper could not install the DNS shield"
            }
            Key::HelperTunAdapterMissing => {
                "TUN adapter {} never appeared, so the elevated helper could not resolve its \
                 interface index."
            }
            Key::HelperConfigNoTunAdapter => "The staged configuration has no TUN adapter name.",
            Key::HelperTunCleanupConfigReadFailed => {
                "The elevated helper could not read the staged configuration for the TUN cleanup"
            }
            Key::HelperTunCleanupTimeout => {
                "TUN adapter {} did not finish its cleanup in time. The elevated helper starts the \
                 core now."
            }
            Key::HelperStagedValidationSpawnFailed => {
                "The elevated helper could not start the staged Xray validation"
            }
            Key::HelperStagedValidationIsolateFailed => {
                "The elevated helper could not isolate the staged Xray validation process"
            }
            Key::HelperStagedConfigRejected => {
                "The staged Xray core rejected the configuration with status {}."
            }
            Key::HelperStagedValidationTimeout => {
                "The staged Xray core did not finish the configuration validation in time."
            }
            Key::HelperStagedValidationWaitFailed => {
                "The elevated helper could not wait for the staged Xray validation"
            }
            Key::ApplyActiveReadFailed => "The app could not read the active configuration",
            Key::ApplyListenMissing => "The candidate configuration has no api.listen value.",
            Key::ApplyListenInvalid => {
                "The candidate configuration api.listen is not a socket address: {}."
            }
            Key::ApplyListenNotLoopback => {
                "The candidate configuration api.listen must be a non-zero loopback address: {}."
            }
            Key::ApplyFileReadFailed => "The app could not read {}",
            Key::ApplyFileParseFailed => "The app could not parse {}",
            Key::ApplyValidationSpawnFailed => "The app could not start the validation process",
            Key::ApplyValidationChildExited => {
                "The validation process exited before the app assigned its job."
            }
            Key::ApplyValidationJobCreateFailed => {
                "The app could not create the job object for the validation process"
            }
            Key::ApplyValidationJobAssignFailed => {
                "The app could not assign the validation process to its job"
            }
            Key::ApplyFilesystemWorkerFailed => "The app could not run the filesystem operation",
            Key::ApplyConfigDirCreateFailed => {
                "The app could not create the configuration directory"
            }
            Key::ApplyCandidateSerializeFailed => {
                "The app could not serialize the candidate configuration"
            }
            Key::ApplyFileCreateFailed => "The app could not create {}",
            Key::ApplyFileWriteFailed => "The app could not write {}",
            Key::ApplyFileFlushFailed => "The app could not flush {} to disk",
            Key::ApplyLastgoodStageFailed => {
                "The app could not stage the last known-good configuration"
            }
            Key::ApplyLastgoodReplaceFailed => "The app could not replace config.lastgood.json",
            Key::ApplyActiveReplaceFailed => {
                "The app could not replace config.json with the validated candidate"
            }
            Key::ApplyRollbackMissing => {
                "The app has no last known-good configuration to roll back to."
            }
            Key::ApplyRollbackStageFailed => {
                "The app could not stage the last known-good configuration for the rollback"
            }
            Key::ApplyRollbackRestoreFailed => "The app could not restore config.lastgood.json",
            Key::ApplyValidationTimeout => "The validation did not finish within {} s.",
            Key::ApplyValidationRunFailed => "The validation run failed",
            Key::ApplyCoreVerifyFailed => {
                "The app could not verify the managed core before validation"
            }
            Key::ApplyCoreVerifyWorkerFailed => "The app lost the core verification worker",
            Key::SupervisorVerifyFailed => {
                "The app could not verify the Xray core payload before the start"
            }
            Key::SupervisorVerifyWorkerFailed => "The app lost the payload verification worker",
            Key::SupervisorSpawnFailed => "The app could not start xray.exe",
            Key::SupervisorChildExited => "The core exited before the app assigned its job.",
            Key::SupervisorJobCreateFailed => {
                "The app could not create the job object for the core"
            }
            Key::SupervisorJobAssignFailed => "The app could not assign the core to its job",
            Key::WfpMissingXrayPath => {
                "The elevated helper cannot install the DNS shield without a staged xray path."
            }
            Key::WfpMissingTunIfindex => {
                "The elevated helper cannot install the DNS shield without a TUN interface index."
            }
            Key::WfpEngineOpenFailed => {
                "The elevated helper could not open the Windows filter engine. The status is {} \
                 ({})."
            }
            Key::WfpSubLayerAddFailed => {
                "The elevated helper could not add the DNS shield sublayer. The status is {} ({})."
            }
            Key::WfpAppIdReadFailed => {
                "The elevated helper could not read the staged xray application identity. The status \
                 is {} ({})."
            }
            Key::WfpFilterAddFailed => {
                "The elevated helper could not add a DNS shield filter. The status is {} ({})."
            }
            Key::CoreDlPayloadRewindFailed => "The app could not rewind the staged payload {}",
            Key::CoreDlPayloadCreateFailed => "The app could not create the protected payload {}",
            Key::CoreDlPayloadCopyFailed => "The app could not copy the protected payload {}",
            Key::CoreDlPayloadFlushFailed => {
                "The app could not flush the protected payload {} to disk"
            }
            Key::CoreDlPayloadLockFailed => "The app could not lock the protected payload {}",
            Key::CoreDlPayloadProofFailed => {
                "The protected payload {} failed its copy proof: expected {}, got {}."
            }
            Key::CoreDlCorePathNotAbsolute => "The managed core path is not absolute.",
            Key::CoreDlSourceInspectFailed => {
                "The app could not inspect the managed core source {}"
            }
            Key::CoreDlSourceNotDirectory => {
                "The managed core source is not an ordinary directory: {}."
            }
            Key::CoreDlSourceNotFile => "The managed core source is not an ordinary file: {}.",
            Key::CoreDlMetadataOpenFailed => "The app could not open the release metadata {}",
            Key::CoreDlMetadataParseFailed => "The app could not parse the release metadata {}",
            Key::CoreDlMetadataMismatch => {
                "The managed core release metadata does not match the compiled release pins."
            }
            Key::CoreDlPayloadOpenFailed => "The app could not open the managed payload {}",
            Key::CoreDlPayloadVerifyFailed => {
                "The managed payload {} failed release verification: expected {}, got {}."
            }
            Key::CoreDlPayloadStillDrifted => {
                "The managed payload {} still fails release verification after the automatic \
                 restore: expected {}, got {}."
            }
            Key::CoreDlPayloadRestoreFailed => {
                "The managed payload {} failed release verification and the automatic restore \
                 failed: expected {}, got {}"
            }
            Key::CoreDlVersionPrefixMissing => {
                "The compiled Xray version in Broccoli is missing its v prefix."
            }
            Key::CoreDlVersionInvalid => "The compiled Xray version in Broccoli is invalid.",
            Key::CoreDlArchivePinInvalid => "The compiled Xray archive pin in Broccoli is invalid.",
            Key::CoreDlArchiveMismatch => {
                "The Xray archive does not match its compiled SHA-256 pin: expected {}, got {}."
            }
            Key::CoreDlStageDownload => "downloading the pinned release",
            Key::CoreDlStageVerifyPin => "verifying the release pin",
            Key::CoreDlStageInstall => "installing the pinned release",
            Key::CoreDlHttpRequestFailed => "The app could not download the pinned release from {}",
            Key::CoreDlHttpStatusRejected => {
                "The release server refused the pinned release request from {}"
            }
            Key::CoreDlDownloadTooLarge => {
                "The download from {} declares {} bytes, more than the {} byte limit."
            }
            Key::CoreDlDownloadTimeout => "The download from {} did not finish within {} s",
            Key::CoreDlDownloadStreamFailed => "The download stream failed",
            Key::CoreDlDownloadSizeOverflow => "The download size exceeds the supported range.",
            Key::CoreDlDownloadLimitExceeded => "The download from {} exceeds the {} byte limit.",
            Key::CoreDlDownloadWriteFailed => "The app could not write the downloaded file {}",
            Key::CoreDlDownloadFlushFailed => {
                "The app could not flush the downloaded file {} to disk"
            }
            Key::CoreDlDirectoryCreateFailed => "The app could not create the directory {}",
            Key::CoreDlFileOpenFailed => "The app could not open {}",
            Key::CoreDlFileCreateFailed => "The app could not create {}",
            Key::CoreDlFileWriteFailed => "The app could not write {}",
            Key::CoreDlFileFlushFailed => "The app could not flush {} to disk",
            Key::CoreDlFileRemoveFailed => "The app could not remove {}",
            Key::CoreDlFileCopyFailed => "The app could not copy {}",
            Key::CoreDlFileReplaceFailed => "The app could not replace {} with {}",
            Key::CoreDlHashingFailed => "The app could not hash the file",
            Key::CoreDlMetadataSerializeFailed => {
                "The app could not serialize the release metadata"
            }
            Key::CoreDlArchiveOpenFailed => "The app could not open the release archive {}",
            Key::CoreDlArchiveInvalid => "The release archive is not a valid ZIP archive",
            Key::CoreDlArchiveEntryUnreadable => {
                "The app could not read entry {} of the release archive"
            }
            Key::CoreDlArchiveExtractFailed => {
                "The app could not extract {} from the release archive"
            }
            Key::CoreDlArchiveMissingXray => "The release archive does not contain xray.exe.",
            Key::CoreDlArchivePayloadsMismatch => {
                "The pinned archive payloads do not match the compiled release pins."
            }
            Key::CoreDlPristineCopyFailed => {
                "The app could not copy the pristine payload from {} to {}"
            }
            Key::CoreDlPristineMismatch => {
                "The pristine {} does not match the compiled release pin: expected {}, got {}."
            }
            Key::CoreDlRestoreUnavailable => {
                "The app cannot restore the managed geo data because the pristine {} is missing or \
                 is not an ordinary file."
            }
            Key::CoreDlCoreNotDirectory => "The managed core path is not a directory.",
            Key::CoreDlBackupNotDirectory => "The managed core backup path is not a directory.",
            Key::CoreDlRecoverBackupFailed => {
                "The app could not restore the core backup after a torn update marker"
            }
            Key::CoreDlMarkerCorrupt => "The core update marker is corrupt.",
            Key::CoreDlRecoverInterruptedFailed => {
                "The app could not restore the core backup after an interrupted update"
            }
            Key::CoreDlInterruptedWithoutCore => {
                "The app found an interrupted core update with no live core or backup."
            }
            Key::CoreDlUpdatePendingHealth => {
                "A previous core update waits for a successful core health check."
            }
            Key::CoreDlBackupRemoveFailed => {
                "The app could not remove the last known-good core after the health check"
            }
            Key::CoreDlQuarantineFailed => {
                "The app could not quarantine the failed update candidate"
            }
            Key::CoreDlRestoreLastgoodFailed => {
                "The app could not restore the last known-good core"
            }
            Key::CoreDlRestoreCandidateFailed => {
                "The app could not restore the failed update candidate"
            }
            Key::CoreDlStagingMissing => {
                "The core staging directory is missing or is not a sibling of the core directory."
            }
            Key::CoreDlBackupStagingFailed => {
                "The app could not move the managed core to its backup"
            }
            Key::CoreDlInstallFailed => "The app could not move the staged core into place",
            Key::CoreDlRestoreAfterValidationFailed => {
                "The app could not restore the previous core after the staged core failed validation"
            }
            Key::HelperLaunchDeclined => "You declined the administrator prompt.",
            Key::HelperShellExecuteFailed => "Windows ShellExecuteW returned error code {}.",
            Key::HelperLaunchExePathFailed => {
                "The app could not resolve its own executable path: {}"
            }
            Key::HelperTokenFileOwnerFailed => {
                "The app could not resolve the owner of the helper token file: {}"
            }
            Key::HelperTokenFileCreateFailed => {
                "The app could not create the helper token file: {}"
            }
            Key::HelperTokenFileSecurityFailed => {
                "The app could not set the helper token file security: {}"
            }
            Key::HelperTokenFileWriteFailed => "The app could not write the helper token file: {}",
            Key::GeodataErrorIo => "The app could not {} `{}`: {}",
            Key::GeodataErrorTooLarge => {
                "The geodata file `{}` is {} bytes. The safety limit is {} bytes."
            }
            Key::GeodataErrorMalformed => "The geodata file `{}` is malformed at byte {}: {}",
            Key::GeodataOperationOpen => "open",
            Key::GeodataOperationInspect => "inspect",
            Key::GeodataOperationRead => "read",
            Key::DashboardLatencyNoObservation => "no observation data",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_dead_verdict_keys_degrade_optional_parts() {
        // The dead-verdict message composes "did not respond" with optional
        // address and reason parts; each combination is its own key so
        // translations never splice English fragments.
        assert_eq!(
            t(Language::En, Key::LatencyProbeOneDeadAtReason),
            "Server '{}' ({}) did not respond: {}."
        );
        assert_eq!(
            t(Language::En, Key::LatencyProbeOneDeadAt),
            "Server '{}' ({}) did not respond."
        );
        assert_eq!(
            t(Language::En, Key::LatencyProbeOneDeadReason),
            "Server '{}' did not respond: {}."
        );
        assert_eq!(
            t(Language::En, Key::LatencyFeedbackPartialWarn),
            "{} of {} outbounds responded."
        );
    }

    #[test]
    fn validation_messages_parity_with_previous_model_strings() {
        use crate::model::CustomSockopt;
        use crate::model::outbound::{
            BlackholeResponse, OutboundModel, Protocol, ProtocolSettings,
        };
        use crate::model::stream::{
            HysteriaTransport, Network, Security, SockoptModel, StreamModel, XhttpSettings,
        };
        use crate::model::validation::{
            ValidationCode, validate_finalmask, validate_outbound, validate_sockopt,
            validate_stream,
        };
        use serde_json::json;

        fn vless_public() -> OutboundModel {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            // Canonical essentials under the settings rules (port,
            // uuid id), so only the pre-seam messages under test are pinned.
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
            outbound
        }

        let mut vision = vless_public();
        let ProtocolSettings::Vless(settings) = &mut vision.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();

        let mut trojan = OutboundModel::new(Protocol::Trojan);
        let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
            unreachable!()
        };
        settings.address = "8.8.8.8".into();
        settings.port = 443;
        settings.password = "secret".into();

        let mut hysteria = OutboundModel::new(Protocol::Hysteria);
        // `new()` normalizes version=2 and security=Tls via enforce_invariants;
        // force every violation explicitly so all three rules fire.
        {
            let ProtocolSettings::Hysteria(settings) = &mut hysteria.settings else {
                unreachable!()
            };
            settings.version = 1;
        }
        hysteria.stream.network = Network::Hysteria;
        hysteria.stream.security = Security::None;
        hysteria.stream.hysteria_settings = Some(HysteriaTransport {
            version: 1,
            ..Default::default()
        });

        let mut reality_ws = vless_public();
        reality_ws.stream.security = Security::Reality;
        reality_ws.stream.network = Network::Ws;
        reality_ws.stream.ws_settings = Some(Default::default());

        let mut reality_missing = vless_public();
        reality_missing.stream.security = Security::Reality;
        reality_missing.stream.network = Network::Raw;

        let mut tls_missing = vless_public();
        tls_missing.stream.security = Security::Tls;

        let mut ws_missing = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut ws_missing.settings else {
            unreachable!()
        };
        settings.address = "router.local".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.encryption = "none".into();
        ws_missing.stream.network = Network::Ws;

        let mut stream_one = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut stream_one.settings else {
            unreachable!()
        };
        settings.address = "router.local".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.encryption = "none".into();
        stream_one.stream.network = Network::Xhttp;
        stream_one.stream.xhttp_settings = Some(XhttpSettings {
            mode: "stream-one".into(),
            download_settings: Some(Box::new(StreamModel::default())),
            ..Default::default()
        });

        let mut depth_stream = StreamModel::default();
        let mut current = &mut depth_stream;
        for _ in 0..=crate::model::stream::MAX_XHTTP_DOWNLOAD_DEPTH {
            current.network = Network::Xhttp;
            let settings = current
                .xhttp_settings
                .get_or_insert_with(XhttpSettings::default);
            current = settings
                .download_settings
                .get_or_insert_with(|| Box::new(StreamModel::default()))
                .as_mut();
        }

        let bad_sockopt = SockoptModel {
            domain_strategy: "future".into(),
            address_port_strategy: "future".into(),
            tcp_fast_open: Some(json!("not bool or number")),
            tcp_keep_alive_idle: Some(-1),
            tcp_keep_alive_interval: Some(30),
            custom_sockopt: vec![CustomSockopt::default()],
            ..Default::default()
        };

        let bad_finalmask: crate::model::stream::FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "future-udp", "settings": {"opaque": true}}],
            "quicParams": {"brutalUp": "1 kbps"}
        }))
        .unwrap();

        let mut ss_level = OutboundModel::new(Protocol::Shadowsocks);
        let ProtocolSettings::Shadowsocks(settings) = &mut ss_level.settings else {
            unreachable!()
        };
        // Canonical essentials under the settings rules, so only
        // the level-range message under test is pinned.
        settings.address = "example.com".into();
        settings.port = 8388;
        settings.method = "aes-128-gcm".into();
        settings.password = "secret".into();
        settings.level = Some(256);

        let mut blackhole = OutboundModel::new(Protocol::Blackhole);
        let ProtocolSettings::Blackhole(settings) = &mut blackhole.settings else {
            unreachable!()
        };
        settings.response = Some(BlackholeResponse {
            r#type: "future".into(),
            ..Default::default()
        });

        // Every message must render byte-identical to the strings the moved
        // model validators produced before the seam (except the Hysteria
        // version rule, which deliberately collapsed its two phrasings into
        // one path-disambiguated message).
        let cases: Vec<(Vec<ValidationCode>, Vec<&'static str>)> = vec![
            (
                validate_outbound(&vision)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["VLESS Vision flow requires TLS or REALITY"],
            ),
            (
                validate_outbound(&vless_public())
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["public VLESS endpoints require TLS/REALITY or non-none VLESS encryption"],
            ),
            (
                validate_outbound(&trojan)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["public Trojan endpoints require TLS or REALITY"],
            ),
            (
                validate_outbound(&hysteria)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec![
                    "Hysteria transport requires TLS",
                    "Hysteria version must be 2",
                    "Hysteria version must be 2",
                ],
            ),
            (
                validate_outbound(&reality_ws)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec![
                    "REALITY requires raw, XHTTP, or gRPC transport",
                    "REALITY settings are missing",
                ],
            ),
            (
                validate_outbound(&reality_missing)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["REALITY settings are missing"],
            ),
            (
                validate_outbound(&tls_missing)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["TLS settings are missing"],
            ),
            (
                validate_outbound(&ws_missing)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["WebSocket settings are missing"],
            ),
            (
                validate_outbound(&stream_one)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["stream-one cannot use downloadSettings"],
            ),
            (
                validate_stream(&depth_stream)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["XHTTP downloadSettings nesting exceeds the safety depth"],
            ),
            (
                validate_outbound(&ss_level)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["Shadowsocks level must be between 0 and 255"],
            ),
            (
                validate_outbound(&blackhole)
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec!["Blackhole response type must be none or http"],
            ),
            (
                validate_sockopt(&bad_sockopt, "stream.sockopt")
                    .into_iter()
                    .map(|issue| issue.code)
                    .collect(),
                vec![
                    "domainStrategy is not supported by Xray SocketConfig",
                    "addressPortStrategy is not supported by Xray SocketConfig",
                    "tcpFastOpen must be a boolean or number",
                    "tcpKeepAliveIdle and tcpKeepAliveInterval cannot have opposite signs",
                    "customSockopt opt is required",
                    "customSockopt type must be int or str",
                ],
            ),
        ];

        for (codes, expected) in cases {
            assert_eq!(codes.len(), expected.len(), "codes {codes:#?}");
            let mut messages: Vec<&str> = codes
                .iter()
                .map(|code| validation_message(code, Language::En))
                .collect();
            messages.sort_unstable();
            let mut expected = expected;
            expected.sort_unstable();
            assert_eq!(messages, expected);
        }

        // Parameterized rules keep their values through full issue rendering.
        let finalmask_issues = validate_finalmask(&bad_finalmask);
        let mut finalmask_messages: Vec<String> = finalmask_issues
            .iter()
            .map(|issue| validation_issue_message(issue, Language::En))
            .collect();
        finalmask_messages.sort_unstable();
        assert_eq!(
            finalmask_messages,
            [
                "finalmask.quicParams.brutalUp: use 0/empty or at least 524288 bps (65536 bytes/s)",
                "finalmask.udp[0]: unsupported future UDP mask discriminator Some(\"future-udp\"). The raw value is preserved",
            ]
        );

        // Whole-model findings render without a path prefix.
        let issues = validate_outbound(&vision);
        let vision_issue = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::VisionRequiresTlsOrReality)
            .expect("vision finding");
        assert_eq!(
            validation_issue_message(vision_issue, Language::En),
            "settings.flow: VLESS Vision flow requires TLS or REALITY"
        );
    }

    /// Configuration-warning pins: the two Severity::Warning codes
    /// render through the same seam, prefixed by their wire path, and name
    /// the incompatibility, the fix, and the XUDP exception / per-block
    /// plausible-value guidance.
    #[test]
    fn configuration_warning_messages_name_the_incompatibility_and_the_fix() {
        use crate::model::validation::{Severity, ValidationIssue};

        let mux_issue = ValidationIssue {
            code: ValidationCode::MuxWithVisionFlow,
            path: Some("mux".into()),
            severity: Severity::Warning,
        };
        assert_eq!(
            validation_message(&mux_issue.code, Language::En),
            "VLESS Vision flow rejects TCP carried over mux. The server tears the whole mux \
             connection down on the first TCP frame, so traffic dies with an EOF. Disable mux, \
             or set concurrency to -1 to keep TCP direct. The XUDP options \
             (xudpConcurrency/xudpProxyUDP443) remain compatible."
        );
        assert_eq!(
            validation_issue_message(&mux_issue, Language::En),
            "mux: VLESS Vision flow rejects TCP carried over mux. The server tears the whole \
             mux connection down on the first TCP frame, so traffic dies with an EOF. \
             Disable mux, or set concurrency to -1 to keep TCP direct. The XUDP options \
             (xudpConcurrency/xudpProxyUDP443) remain compatible."
        );

        for (path, guidance) in [
            (
                "stream.tlsSettings.serverName",
                "the server's own domain, for example www.example.com",
            ),
            (
                "stream.realitySettings.serverName",
                "one of the server's serverNames, typically the camouflage site's domain",
            ),
        ] {
            let issue = ValidationIssue {
                code: ValidationCode::ServerNameImplausible,
                path: Some(path.into()),
                severity: Severity::Warning,
            };
            let rendered = validation_issue_message(&issue, Language::En);
            assert!(rendered.starts_with(&format!("{path}: ")), "{rendered}");
            assert!(
                rendered.contains("cannot be a real DNS name or IP"),
                "{rendered}"
            );
            assert!(rendered.contains(guidance), "{rendered}");
        }
    }

    /// The REALITY fingerprint advisory names the stored value, the three
    /// names upstream's REALITY scenarios exercise, and the acceptance; the
    /// inline editor verdict fills the same template without the path, so
    /// the editor and the warnings list can never disagree.
    #[test]
    fn reality_fingerprint_advisory_names_the_value_and_the_exercised_names() {
        use crate::model::validation::{Severity, ValidationIssue};

        let issue = ValidationIssue {
            code: ValidationCode::RealityFingerprintUntested("ios".into()),
            path: Some("stream.realitySettings.fingerprint".into()),
            severity: Severity::Warning,
        };
        let rendered = validation_issue_message(&issue, Language::En);
        for needle in ["ios", "chrome", "firefox", "safari"] {
            assert!(rendered.contains(needle), "{rendered}");
        }
        assert!(rendered.contains("still accepts"), "{rendered}");
        assert!(
            !rendered.contains("rejects"),
            "the advisory must not read as a rejection: {rendered}"
        );
        assert_eq!(
            rendered.strip_prefix("stream.realitySettings.fingerprint: "),
            Some(
                t_fmt(
                    Language::En,
                    Key::OutboundRealityFingerprintUntested,
                    &[&"ios"]
                )
                .as_str()
            )
        );
    }

    /// The mask-order findings name the mask type, the required end, and the
    /// move that repairs the chain; the interval-hop advisory names the
    /// constraint and the `perConnRemote` fallback.
    #[test]
    fn mask_order_and_interval_hop_messages_name_the_fix() {
        use crate::model::validation::{Severity, ValidationIssue};

        let not_last = ValidationIssue {
            code: ValidationCode::FinalmaskUdpMaskNotLast("realm".into()),
            path: Some("finalmask.udp[0]".into()),
            severity: Severity::Error,
        };
        assert_eq!(
            validation_issue_message(&not_last, Language::En),
            "finalmask.udp[0]: realm must be the last UDP mask entry. Move it to the end of the \
             list"
        );
        let not_first = ValidationIssue {
            code: ValidationCode::FinalmaskUdpMaskNotFirst("sudoku".into()),
            path: Some("finalmask.udp[1]".into()),
            severity: Severity::Error,
        };
        assert_eq!(
            validation_issue_message(&not_first, Language::En),
            "finalmask.udp[1]: sudoku must be the first UDP mask entry. Move it to the \
             beginning of the list"
        );
        let interval = ValidationIssue {
            code: ValidationCode::FinalmaskUdpHopIntervalTransportConflict,
            path: None,
            severity: Severity::Warning,
        };
        assert_eq!(
            validation_issue_message(&interval, Language::En),
            "The udphop interval modes need hysteria2, HTTP/3 xhttp, or WireGuard. Other \
             transports cannot run interval hops"
        );
    }
    #[test]
    fn english_table_matches_hand_written_literals() {
        // Expected values written by hand, never computed from the table.
        let expected: &[(Key, &str)] = &[
            (Key::Language, "Language"),
            (Key::LanguageEnglish, "English"),
            (Key::Theme, "Theme"),
            (Key::ThemeSystem, "System"),
            (
                Key::ThemeSystemHint,
                "Follows the Windows light/dark setting",
            ),
            (Key::ThemeDark, "Dark"),
            (Key::ThemeDarkHint, "Dark background, light text"),
            (Key::ThemeLight, "Light"),
            (Key::ThemeLightHint, "Light background, dark text"),
            (Key::AccentColor, "Accent color"),
            (Key::AccentColorReset, "Reset"),
            (
                Key::AccentColorResetHint,
                "Restore egui's stock accent for both themes",
            ),
            (Key::SrvLeafPin, "Leaf pin"),
            (Key::SrvCaPins, "CA pins"),
            (Key::SrvCopyPin, "Copy"),
            (Key::SrvApplyPin, "Apply to server"),
            (Key::SrvPinApplied, "Pin applied."),
            (
                Key::SrvPinCaution,
                "Pinning trusts the server certificate exactly as presented now (trust-on-first-use). Use it only for self-signed or otherwise untrusted certificates. If the server certificate changes, the server stops working until the pin is updated.",
            ),
            (
                Key::SrvProbeNoPin,
                "No certificate pin found in the probe output.",
            ),
            (Key::SrvShowProbeOutput, "Show original output"),
            (Key::SrvProbeOutputTitle, "TLS probe output"),
            (Key::SrvProbeQuicHandshake, "Probe QUIC handshake"),
            (
                Key::SrvProbeQuicHint,
                "In-app QUIC (UDP) handshake for servers that do not answer TCP, for example Hysteria2. The pin comes from the certificate the server presents",
            ),
            (
                Key::SrvQuicProbeDomainInvalid,
                "QUIC probe domain is invalid: {0}",
            ),
            (
                Key::SrvQuicProbeResolveFailed,
                "Failed to resolve QUIC probe address: {0}",
            ),
            (
                Key::SrvQuicProbeHandshakeFailed,
                "QUIC handshake failed: {0}",
            ),
            (Key::SrvQuicProbeTimeout, "QUIC handshake timed out"),
            (
                Key::SrvQuicProbeNoCert,
                "The server presented no certificate",
            ),
            (Key::SettingsResetToDefault, "Reset to default…"),
            (
                Key::SettingsResetToDefaultHint,
                "Restore a fresh install's defaults. The app keeps your server list and exits to finish the reset.",
            ),
            (Key::SettingsResetTitle, "Reset to default"),
            (
                Key::SettingsResetBody,
                "All settings return to a fresh install's defaults: mode, local endpoints, DNS, latency, theme. The app exits to finish the reset and clears the generated configurations and logs. The app keeps your server list. The next launch starts as a fresh install with your servers.",
            ),
            (Key::SettingsResetConfirm, "Reset to default"),
            (
                Key::SettingsGeodataProvenanceRelease,
                "Release-managed: the geo data matches the pinned release.",
            ),
            (
                Key::SettingsGeodataProvenanceUserOn,
                "User-managed: the geo data differs from the pinned release (last modified {}).",
            ),
            (Key::SettingsGeodataRestore, "Restore built-in geo data"),
            (Key::SettingsGeodataRestoreFailed, "Restore failed: {}."),
        ];
        for &(key, literal) in expected {
            assert_eq!(t(Language::En, key), literal, "{key:?}");
        }
    }

    #[test]
    fn unknown_or_absent_language_resolves_to_english() {
        for tag in ["xx", "zhHans", "EN"] {
            let language: Language = serde_json::from_str(&format!("\"{tag}\"")).unwrap();
            assert_eq!(
                language,
                Language::En,
                "tag {tag:?} must fall back to English"
            );
        }
    }

    #[test]
    fn t_fmt_single_placeholder() {
        assert_eq!(t_fmt(Language::En, Key::LatencyMs, &[&42]), "42 ms");
    }

    #[test]
    fn t_fmt_multi_placeholder() {
        assert_eq!(
            t_fmt(
                Language::En,
                Key::CoreSetupProgress,
                &[&"downloading", &2, &5]
            ),
            "downloading — 2/5 bytes"
        );
    }

    #[test]
    fn t_fmt_placeholder_at_start_and_end() {
        assert_eq!(
            t_fmt(Language::En, Key::SrvUnknownFutureFields, &[&3]),
            "3 unknown future customSockopt field(s) are preserved unchanged."
        );
        assert_eq!(
            t_fmt(Language::En, Key::SrvCustomSockoptN, &[&1]),
            "custom sockopt 1"
        );
    }

    #[test]
    fn t_fmt_adjacent_placeholders() {
        // Adjacent placeholders substitute back-to-back with no separator.
        assert_eq!(
            t_fmt(
                Language::En,
                Key::SrvXrayExited,
                &[&"xray run -test", &"true", &"tail"]
            ),
            "xray xray run -test exited truetail"
        );
    }

    #[test]
    fn t_fmt_empty_template() {
        assert_eq!(fill_placeholders("", &[]), "");
        assert_eq!(fill_placeholders("", &[&1]), "");
    }

    #[test]
    fn t_fmt_no_placeholder_template() {
        assert_eq!(
            t_fmt(Language::En, Key::SrvXrayTestSilent, &[]),
            "xray run -test failed without diagnostic output"
        );
    }

    #[test]
    fn t_fmt_debug_placeholder_uses_preformatted_arg() {
        // The inner text of the placeholder is ignored; the caller pre-formats.
        assert_eq!(
            t_fmt(
                Language::En,
                Key::SrvDuplicateAcceptedId,
                &[&format!("{:?}", "abc")]
            ),
            "another accepted profile in this import already uses ID \"abc\""
        );
    }

    #[test]
    fn safety_messages_render_payload_and_hazard_labels() {
        use crate::model::safety::{HazardClass, SafetyCode, SafetyFinding};
        use crate::model::settings::Language;
        let lang = Language::En;
        for (code, expected) in [
            (
                SafetyCode::SocksListenerExposed("0.0.0.0".into()),
                "SOCKS listener on 0.0.0.0 requires no authentication and accepts \
                 connections beyond loopback.",
            ),
            (
                SafetyCode::HttpListenerExposed("192.168.1.5".into()),
                "HTTP listener on 192.168.1.5 requires no authentication and accepts \
                 connections beyond loopback.",
            ),
            (
                SafetyCode::DokodemoListenerExposed("::".into()),
                "dokodemo-door listener on :: is open beyond loopback (it has no \
                 authentication).",
            ),
        ] {
            let finding = SafetyFinding {
                path: "socks.listen".into(),
                class: HazardClass::Exposure,
                code,
            };
            assert_eq!(safety_finding_message(&finding, lang), expected);
        }
        assert_eq!(hazard_class_label(HazardClass::Exposure, lang), "Exposure");
        assert_eq!(
            safety_finding_message(
                &SafetyFinding {
                    path: "tun".into(),
                    class: HazardClass::Privacy,
                    code: SafetyCode::TunDnsUnprotected,
                },
                lang,
            ),
            "TUN mode has no DNS configuration. The adapter falls back to plaintext \
             1.1.1.1/8.8.8.8 and DNS is not intercepted."
        );
        assert_eq!(
            safety_finding_message(
                &SafetyFinding {
                    path: "routing.balancers[0]".into(),
                    class: HazardClass::Breakage,
                    code: SafetyCode::BalancerSelectorNoMatch("bal".into()),
                },
                lang,
            ),
            "Balancer bal has no selector that matches any outbound tag. The balancer \
             cannot carry traffic."
        );
        assert_eq!(hazard_class_label(HazardClass::Privacy, lang), "Privacy");
        assert_eq!(hazard_class_label(HazardClass::Breakage, lang), "Breakage");
    }

    #[test]
    fn fill_placeholders_missing_arg_keeps_placeholder_literal() {
        // Degradation contract: with fewer args than placeholders, the
        // unmatched placeholder stays literal and nothing panics.
        assert_eq!(fill_placeholders("hi {name}!", &[]), "hi {name}!");
        assert_eq!(fill_placeholders("{} {} {}", &[&1]), "1 {} {}");
    }

    #[test]
    fn fill_placeholders_extra_args_ignored() {
        assert_eq!(fill_placeholders("{} ok", &[&1, &2, &3]), "1 ok");
        assert_eq!(fill_placeholders("", &[&1, &2]), "");
    }

    #[test]
    fn t_fmt_placeholder_inner_text_ignored() {
        // {name}-style inner text is consumed positionally like bare {}.
        assert_eq!(
            t_fmt(Language::En, Key::SrvSetLabel, &[&"my-label"]),
            "set my-label"
        );
    }

    #[test]
    fn settings_verdict_messages_reproduce_the_generator_bytes() {
        use crate::model::validation::Severity;

        // The settings-wide rules replaced the generator's free-form
        // strings; every rendered byte must be identical (Debug-quoted tags
        // included), because callers surface the first finding verbatim.
        let rendered = |code: ValidationCode| {
            validation_issue_message(
                &ValidationIssue {
                    code,
                    path: None,
                    severity: Severity::Error,
                },
                Language::En,
            )
        };
        assert_eq!(
            rendered(ValidationCode::BalancerTagMissing(2)),
            "balancer 2 has no tag"
        );
        assert_eq!(
            rendered(ValidationCode::BalancerSelectorMissing("bal".into())),
            "balancer \"bal\" has no outbound selector"
        );
        assert_eq!(
            rendered(ValidationCode::BalancerTagDuplicated("bal".into())),
            "balancer tag \"bal\" is duplicated"
        );
        assert_eq!(
            rendered(ValidationCode::BalancerFallbackMissing(
                "bal".into(),
                "gone".into()
            )),
            "balancer \"bal\" references missing fallback outbound \"gone\""
        );
        assert_eq!(
            rendered(ValidationCode::InboundTagDuplicated("tun-in".into())),
            "inbound tag \"tun-in\" is duplicated"
        );
        assert_eq!(
            rendered(ValidationCode::DokodemoUnixSocketConflict(
                "in-doko".into(),
                "in-doko-2".into(),
                r"C:\x.sock".into()
            )),
            r#"dokodemo inbound "in-doko" conflicts with "in-doko-2" on UNIX socket "C:\\x.sock""#
        );
        assert_eq!(
            rendered(ValidationCode::ListenerConflict(
                "local inbound \"in-socks-1\"".into(),
                "API".into(),
                "127.0.0.1".into(),
                1080
            )),
            "local inbound \"in-socks-1\" conflicts with API on 127.0.0.1:1080"
        );
        assert_eq!(
            rendered(ValidationCode::RoutingRuleTarget(
                1,
                "choose an outbound or balancer target".into()
            )),
            "routing rule 1: choose an outbound or balancer target"
        );
        assert_eq!(
            rendered(ValidationCode::RoutingRuleOutboundMissing(3, "gone".into())),
            "routing rule 3 references missing outbound \"gone\""
        );
        assert_eq!(
            rendered(ValidationCode::FakeDnsPoolCapacityExceeded(
                1,
                1_048_577,
                "198.18.0.0/15".into()
            )),
            "fakeDNS pool 1: poolSize 1048577 exceeds the 198.18.0.0/15 subnet capacity"
        );
        assert_eq!(
            rendered(ValidationCode::ProfileTagDuplicated(
                1,
                "aaaaaaaa".into(),
                2,
                "bbbbbbbb".into(),
                "srv-x".into()
            )),
            "server profiles 1 (\"aaaaaaaa\") and 2 (\"bbbbbbbb\") generate duplicate \
             outbound tag \"srv-x\". IDs must differ within their first 8 characters"
        );
        assert_eq!(
            rendered(ValidationCode::OutboundChainCycle(
                "srv-a -> srv-b -> srv-a".into()
            )),
            "outbound chain cycle: srv-a -> srv-b -> srv-a"
        );
        assert_eq!(
            rendered(ValidationCode::TunIpv4GatewayRequired),
            "TUN mode needs at least one IPv4 gateway (the in-tun DNS address is derived from it)"
        );
        assert_eq!(
            rendered(ValidationCode::GeodataUrlInvalid("geoip.dat".into())),
            format!(
                "geodata geoip.dat: {}",
                t(Language::En, Key::GeodataUrlNotHttps)
            )
        );
        assert_eq!(
            rendered(ValidationCode::GeodataCronInvalid),
            format!(
                "geodata: {}",
                t(Language::En, Key::GeodataCronNotFiveFields)
            )
        );
    }
}
