//! One constructed [`ValidationCode`] per variant, and the generated variant
//! list the coverage check ties it to.
//!
//! The enum is the model layer's whole vocabulary of rejections, and every
//! caller renders it through `broccoli::i18n::validation_message`. That
//! renderer asserts its own template and placeholder counts in debug builds,
//! but only for the codes a test happens to exercise. This corpus closes the
//! gap: [`all_codes`] holds one plausible instance per variant,
//! [`validation_codes`] generates the variant list the coverage test compares
//! it against, and the driver that declares this module
//! (`tests/validation_code_corpus.rs`) checks that coverage and renders the
//! whole list in every locale the app ships. Coverage is mechanical at both
//! ends: a variant left out of the generated list fails the build, and a
//! variant listed there without a corpus entry fails the coverage test.
//!
//! Include it beside `common`, from the file that drives it:
//!
//! ```text
//! #[path = "common/validation_corpus.rs"]
//! mod corpus;
//! ```

use broccoli::model::stream::Network;
use broccoli::model::validation::ValidationCode;

/// The number of [`ValidationCode`] variants the corpus lists, taken from the
/// generated name list rather than typed: the list and the count cannot drift.
pub(crate) const VARIANT_COUNT: usize = VARIANT_NAMES.len();

/// One constructed instance per [`ValidationCode`] variant, in the enum's own
/// declaration order.
///
/// Payloads are the values a model pass stores for the rule: server profile
/// IDs, inbound and outbound tags, 1-based indices, listen ports. Any plausible
/// value renders the same sentence shape, so the entries stay short rather than
/// realistic in every detail. The two transport-carrying rules name a transport
/// that carries settings at all — the renderer asserts on the transports those
/// rules cannot name.
pub(crate) fn all_codes() -> Vec<ValidationCode> {
    use ValidationCode::*;
    vec![
        XhttpDepthExceeded,
        TransportSettingsMissing(Network::Xhttp),
        HeaderValuesNotStrings(Network::Ws),
        HysteriaTransportRequiresTls,
        HysteriaTransportVersion,
        RealityRequiresTransport,
        RealitySettingsMissing,
        TlsSettingsMissing,
        StreamOneNoDownload,
        MasterKeyLogNotSupported,
        TlsAllowInsecureRemoved,
        ShadowsocksLevelRange,
        BlackholeResponseInvalid,
        BlackholeCustomResponseDataInvalid,
        VlessFlowUnsupported,
        VlessEncryptionUnsupported,
        ShadowsocksMethodUnsupported,
        Shadowsocks2022KeyInvalid,
        TrojanSettingsIncomplete,
        ShadowsocksSettingsIncomplete,
        SettingsPortZero,
        SettingsIdNotUuid,
        RealityPublicKeyInvalid,
        RealityShortIdInvalid,
        RealitySpiderXInvalid,
        RealityMldsa65Invalid,
        TlsFingerprintUnsupported,
        RealityFingerprintUnsupported,
        RealityFingerprintUntested("edge".into()),
        PinnedPeerCertSha256Invalid,
        TlsFromMitmAlpnShort,
        TlsCertificateRequired,
        VisionRequiresTlsOrReality,
        PublicVlessRequiresTlsOrEncryption,
        PublicTrojanRequiresTlsOrReality,
        ListenAddressInvalid,
        SockoptDomainStrategyInvalid,
        SockoptAddressPortStrategyInvalid,
        SockoptTcpFastOpenType,
        SockoptKeepaliveSigns,
        SockoptCustomOptRequired,
        SockoptCustomTypeInvalid,
        FinalmaskQuicCongestionInvalid,
        FinalmaskQuicBbrProfileInvalid,
        FinalmaskQuicBandwidthTooSmall,
        FinalmaskQuicBandwidthSyntax,
        FinalmaskQuicBandwidthNonFinite,
        FinalmaskQuicBandwidthTooLarge,
        FinalmaskQuicBandwidthUnitInvalid("KB".into()),
        FinalmaskQuicForceBrutalNeedsUp,
        FinalmaskQuicHopMoved,
        FinalmaskUdpHopModeInvalid,
        FinalmaskUdpHopIntervalTooSmall,
        FinalmaskUdpHopIpInvalid,
        FinalmaskDialerProxyConflict,
        FinalmaskUdpMaskNotLast("realm".into()),
        FinalmaskUdpMaskNotFirst("sudoku".into()),
        FinalmaskUdpHopIntervalTransportConflict,
        FinalmaskQuicReceiveWindowTooSmall,
        FinalmaskQuicMaxIdleTimeoutInvalid,
        FinalmaskQuicKeepAlivePeriodInvalid,
        FinalmaskQuicMaxIncomingStreamsInvalid,
        FinalmaskPortNumberRange,
        FinalmaskPortEnvNameRequired,
        FinalmaskPortListInvalid("70000".into()),
        FinalmaskBytesValueRequired("sudoku.magic".into()),
        FinalmaskArrayByteSyntax,
        FinalmaskStrByteSyntax,
        FinalmaskHexByteSyntax,
        FinalmaskBase64ByteSyntax,
        FinalmaskUnknownByteSyntax("0o47".into()),
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
        FinalmaskUnknownTcpMask(Some("future-tcp".into())),
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
        FinalmaskRealmUrlSyntax("realm://example.com:443".into()),
        FinalmaskRealmStunRequired,
        FinalmaskRealmStunFormat,
        FinalmaskRealmAllowInsecureRemoved,
        FinalmaskRealmFingerprintUnknown,
        FinalmaskRealmAlpnFromMitm,
        FinalmaskRealmCertRequired,
        FinalmaskRealmEchKeysBase64,
        FinalmaskUnknownUdpMask(Some("future-udp".into())),
        SendThroughInvalid,
        FreedomFinalRuleInvalid,
        DnsRuleActionInvalid,
        WireguardRemoteDnsInvalid,
        ActiveProfileMissing("1f0a6c1e-0000-4000-8000-000000000001".into()),
        ActiveProfileAmbiguous("1f0a6c1e-0000-4000-8000-000000000001".into(), 2),
        ProfilesRequired,
        ProfileIdEmpty(1),
        ProfileIdDuplicated(1, 2, "1f0a6c1e-0000-4000-8000-000000000001".into()),
        ProfileTagEmpty(1, "1f0a6c1e-0000-4000-8000-000000000001".into()),
        ProfileTagInvalid(
            1,
            "1f0a6c1e-0000-4000-8000-000000000001".into(),
            "bad tag".into(),
        ),
        ProfileTagReserved(
            1,
            "1f0a6c1e-0000-4000-8000-000000000001".into(),
            "direct".into(),
        ),
        ProfileTagDuplicated(
            1,
            "1f0a6c1e-0000-4000-8000-000000000001".into(),
            2,
            "2b7d4f60-0000-4000-8000-000000000002".into(),
            "proxy-1".into(),
        ),
        OutboundProxySettingsRemoved,
        OutboundChainMissing("proxy-1".into(), "proxy-2".into()),
        OutboundChainCycle("proxy-1 -> proxy-2 -> proxy-1".into()),
        BalancerTagMissing(1),
        BalancerSelectorMissing("balancer-1".into()),
        BalancerTagDuplicated("balancer-1".into()),
        BalancerFallbackMissing("balancer-1".into(), "proxy-9".into()),
        LocalInboundAuthRequiresAccounts,
        LocalInboundPortZero("socks-in".into()),
        InboundTagDuplicated("socks-in".into()),
        DokodemoTagMissing(3),
        DokodemoNetworkInvalid(
            "dokodemo-1".into(),
            "listener network contains unknown token \"tcp+udp\"".into(),
        ),
        DokodemoUnixSocketRequired("dokodemo-1".into()),
        DokodemoUnixSocketConflict(
            "dokodemo-1".into(),
            "dokodemo-2".into(),
            "/run/xray/dokodemo.sock".into(),
        ),
        DokodemoPortZero("dokodemo-1".into()),
        TunIpv4GatewayRequired,
        ListenerConflict(
            "socks-in".into(),
            "http-in".into(),
            "127.0.0.1".into(),
            10808,
        ),
        RoutingRuleTarget(
            1,
            "exactly one of outboundTag and balancerTag is required".into(),
        ),
        RoutingRuleOutboundMissing(1, "proxy-9".into()),
        RoutingRuleBalancerMissing(2, "balancer-9".into()),
        RoutingRuleInboundMissing(3, "socks-in".into()),
        DnsServerAddressMissing(1),
        FakeDnsPoolCidrInvalid(1),
        FakeDnsPoolSizeInvalid(1),
        FakeDnsPoolCapacityExceeded(1, 4096, "198.18.0.0/24".into()),
        GeodataUrlInvalid("geosite.dat".into()),
        GeodataCronInvalid,
        MuxWithVisionFlow,
        ServerNameImplausible,
        TlsVersionRangeInvalid,
        TlsMinExceedsMax,
        XhttpModeUnsupported,
        XhttpPaddingBytesInvalid,
        XhttpPaddingPlacementInvalid,
        XhttpPaddingMethodInvalid,
        XhttpUplinkDataPlacementInvalid,
        XhttpUplinkDataPlacementRequiresPacketUp,
        XhttpUplinkHttpMethodRequiresPacketUp,
        XhttpSessionIdPlacementInvalid,
        XhttpSeqPlacementInvalid,
        XhttpSessionIdLengthRequired,
        XhttpSessionIdTableInvalid,
        XhttpXmuxLimitsExclusive,
        SniffingDestOverrideInvalid,
        OutboundTargetStrategyInvalid,
        SockoptTproxySilentOff,
        KcpRangeSoft,
        KcpRangeInvalid,
        XhttpServerMaxHeaderBytesInvalid,
        GrpcNegativeClamp,
        MuxXudpProxyUdp443Unsupported,
        MuxConcurrencyReinterpreted,
        MuxXudpKnobsInert,
        TrojanFlowRemoved,
        KcpSeedHeaderRemoved,
        KcpHeaderTypeIgnored,
        VmessAlterIdIgnored,
        VlessSeedIgnored,
        FreedomNoiseRemoved,
        FreedomDomainStrategyUnsupported,
        RealityServerFormKeysInert,
        HysteriaQuicKnobsMoved,
        XhttpExtraShadowsSettings("mode".into()),
        ProtocolSettingsMismatch,
        ServerAddressRequired,
        ServerPortRequired,
        VlessIdRequired,
        VlessEncryptionRequired,
        VlessReverseTagRequired,
        VmessIdRequired,
        VmessSecurityUnsupported,
        WireguardSecretKeyInvalid,
        WireguardReservedKeyBytes,
        WireguardPeersRequired,
        WireguardPeerPublicKeyRequired,
        WireguardPeerEndpointRequired,
        WireguardPresharedKeyInvalid,
        FreedomFragmentInvalid,
        FreedomNoiseInvalid,
        LoopbackTagRequired,
    ]
}

/// The variant list the corpus must cover, in the enum's declaration order.
///
/// [`variant_name`] is generated from this list with no wildcard arm, so a
/// variant added to the enum and left out of the list is a compile error. The
/// coverage test then compares the corpus entries' names against
/// [`VARIANT_NAMES`], so a variant listed here without an entry is a test
/// failure. Both ends of the coverage claim are mechanical.
/// The variant lists the corpus must cover: the payload-free variants and the
/// ones that carry a payload, as two identifier lists.
///
/// [`variant_name`] is generated from these lists with no wildcard arm, so a
/// variant added to the enum and left out of a list is a compile error. The
/// coverage test then compares the corpus entries' names against
/// [`VARIANT_NAMES`], so a variant listed here without an entry is a test
/// failure. Both ends of the coverage claim are mechanical.
macro_rules! validation_codes {
    (
        unit { $( $unit:ident ),* $(,)? }
        tuple { $( $tuple:ident ),* $(,)? }
    ) => {
        pub(crate) const VARIANT_NAMES: &[&str] =
            &[ $( stringify!($unit), )* $( stringify!($tuple), )* ];

        /// The variant's name, without its payload. Two corpus entries are the
        /// same variant exactly when their names are equal, which is what makes
        /// the coverage check a set comparison.
        pub(crate) fn variant_name(code: &ValidationCode) -> &'static str {
            match code {
                $( ValidationCode::$unit => stringify!($unit), )*
                $( ValidationCode::$tuple(..) => stringify!($tuple), )*
            }
        }
    };
}

validation_codes! {
    unit {
        XhttpDepthExceeded, HysteriaTransportRequiresTls, HysteriaTransportVersion,
        RealityRequiresTransport, RealitySettingsMissing, TlsSettingsMissing,
        StreamOneNoDownload, MasterKeyLogNotSupported, TlsAllowInsecureRemoved,
        ShadowsocksLevelRange, BlackholeResponseInvalid, BlackholeCustomResponseDataInvalid,
        VlessFlowUnsupported, VlessEncryptionUnsupported, ShadowsocksMethodUnsupported,
        Shadowsocks2022KeyInvalid, TrojanSettingsIncomplete, ShadowsocksSettingsIncomplete,
        SettingsPortZero, SettingsIdNotUuid, RealityPublicKeyInvalid, RealityShortIdInvalid,
        RealitySpiderXInvalid, RealityMldsa65Invalid, TlsFingerprintUnsupported,
        RealityFingerprintUnsupported, PinnedPeerCertSha256Invalid, TlsFromMitmAlpnShort,
        TlsCertificateRequired, VisionRequiresTlsOrReality, PublicVlessRequiresTlsOrEncryption,
        PublicTrojanRequiresTlsOrReality, ListenAddressInvalid, SockoptDomainStrategyInvalid,
        SockoptAddressPortStrategyInvalid, SockoptTcpFastOpenType, SockoptKeepaliveSigns,
        SockoptCustomOptRequired, SockoptCustomTypeInvalid, FinalmaskQuicCongestionInvalid,
        FinalmaskQuicBbrProfileInvalid, FinalmaskQuicBandwidthTooSmall,
        FinalmaskQuicBandwidthSyntax, FinalmaskQuicBandwidthNonFinite,
        FinalmaskQuicBandwidthTooLarge, FinalmaskQuicForceBrutalNeedsUp, FinalmaskQuicHopMoved,
        FinalmaskUdpHopModeInvalid, FinalmaskUdpHopIntervalTooSmall, FinalmaskUdpHopIpInvalid,
        FinalmaskDialerProxyConflict, FinalmaskUdpHopIntervalTransportConflict,
        FinalmaskQuicReceiveWindowTooSmall, FinalmaskQuicMaxIdleTimeoutInvalid,
        FinalmaskQuicKeepAlivePeriodInvalid, FinalmaskQuicMaxIncomingStreamsInvalid,
        FinalmaskPortNumberRange, FinalmaskPortEnvNameRequired, FinalmaskArrayByteSyntax,
        FinalmaskStrByteSyntax, FinalmaskHexByteSyntax, FinalmaskBase64ByteSyntax,
        FinalmaskTransformOpRequired, FinalmaskTransformArgRequired,
        FinalmaskTransformArgExclusive, FinalmaskVarNameInvalid, FinalmaskCustomItemExclusive,
        FinalmaskRandRangeInvalid, FinalmaskXmcProfilesRequired, FinalmaskXmcPasswordRequired,
        FinalmaskXmcUsernameInvalid, FinalmaskXmcUuidInvalid, FinalmaskXmcTexturesRequired,
        FinalmaskPacketsFirstNotZero, FinalmaskPacketsSyntax, FinalmaskLengthsStartAboveZero,
        FinalmaskUdpHeaderModeInvalid, FinalmaskMkcpHeaderInvalid, FinalmaskNoisePacketExclusive,
        FinalmaskSalamanderPacketSize, FinalmaskXdnsDomainRemoved, FinalmaskXdnsEmpty,
        FinalmaskXdnsResolverUdp, FinalmaskXicmpIpInvalid, FinalmaskRealmScheme,
        FinalmaskRealmHostRequired, FinalmaskRealmTokenBeforeAt, FinalmaskRealmIdInPath,
        FinalmaskRealmStunRequired, FinalmaskRealmStunFormat, FinalmaskRealmAllowInsecureRemoved,
        FinalmaskRealmFingerprintUnknown, FinalmaskRealmAlpnFromMitm, FinalmaskRealmCertRequired,
        FinalmaskRealmEchKeysBase64, SendThroughInvalid, FreedomFinalRuleInvalid,
        DnsRuleActionInvalid, WireguardRemoteDnsInvalid, ProfilesRequired,
        OutboundProxySettingsRemoved, LocalInboundAuthRequiresAccounts, TunIpv4GatewayRequired,
        GeodataCronInvalid, MuxWithVisionFlow, ServerNameImplausible, TlsVersionRangeInvalid,
        TlsMinExceedsMax, XhttpModeUnsupported, XhttpPaddingBytesInvalid,
        XhttpPaddingPlacementInvalid, XhttpPaddingMethodInvalid, XhttpUplinkDataPlacementInvalid,
        XhttpUplinkDataPlacementRequiresPacketUp, XhttpUplinkHttpMethodRequiresPacketUp,
        XhttpSessionIdPlacementInvalid, XhttpSeqPlacementInvalid, XhttpSessionIdLengthRequired,
        XhttpSessionIdTableInvalid, XhttpXmuxLimitsExclusive, SniffingDestOverrideInvalid,
        OutboundTargetStrategyInvalid, SockoptTproxySilentOff, KcpRangeSoft, KcpRangeInvalid,
        XhttpServerMaxHeaderBytesInvalid, GrpcNegativeClamp, MuxXudpProxyUdp443Unsupported,
        MuxConcurrencyReinterpreted, MuxXudpKnobsInert, TrojanFlowRemoved, KcpSeedHeaderRemoved,
        KcpHeaderTypeIgnored, VmessAlterIdIgnored, VlessSeedIgnored, FreedomNoiseRemoved,
        FreedomDomainStrategyUnsupported, RealityServerFormKeysInert, HysteriaQuicKnobsMoved,
        ProtocolSettingsMismatch, ServerAddressRequired, ServerPortRequired, VlessIdRequired,
        VlessEncryptionRequired, VlessReverseTagRequired, VmessIdRequired,
        VmessSecurityUnsupported, WireguardSecretKeyInvalid, WireguardReservedKeyBytes,
        WireguardPeersRequired, WireguardPeerPublicKeyRequired, WireguardPeerEndpointRequired,
        WireguardPresharedKeyInvalid, FreedomFragmentInvalid, FreedomNoiseInvalid,
        LoopbackTagRequired,
    }
    tuple {
        TransportSettingsMissing, HeaderValuesNotStrings, RealityFingerprintUntested,
        FinalmaskQuicBandwidthUnitInvalid, FinalmaskUdpMaskNotLast, FinalmaskUdpMaskNotFirst,
        FinalmaskPortListInvalid, FinalmaskBytesValueRequired, FinalmaskUnknownByteSyntax,
        FinalmaskUnknownTcpMask, FinalmaskRealmUrlSyntax, FinalmaskUnknownUdpMask,
        ActiveProfileMissing, ActiveProfileAmbiguous, ProfileIdEmpty, ProfileIdDuplicated,
        ProfileTagEmpty, ProfileTagInvalid, ProfileTagReserved, ProfileTagDuplicated,
        OutboundChainMissing, OutboundChainCycle, BalancerTagMissing, BalancerSelectorMissing,
        BalancerTagDuplicated, BalancerFallbackMissing, LocalInboundPortZero,
        InboundTagDuplicated, DokodemoTagMissing, DokodemoNetworkInvalid,
        DokodemoUnixSocketRequired, DokodemoUnixSocketConflict, DokodemoPortZero,
        ListenerConflict, RoutingRuleTarget, RoutingRuleOutboundMissing,
        RoutingRuleBalancerMissing, RoutingRuleInboundMissing, DnsServerAddressMissing,
        FakeDnsPoolCidrInvalid, FakeDnsPoolSizeInvalid, FakeDnsPoolCapacityExceeded,
        GeodataUrlInvalid, XhttpExtraShadowsSettings,
    }
}
