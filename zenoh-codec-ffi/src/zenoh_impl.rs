use crate::macros::{impl_for_enum, impl_for_struct};
pub use convert_case::{Case, Casing};

pub struct ZenohProtocol;

mod impl_for_zenoh_protocol {
    use super::ZenohProtocol;
    use crate::header_field::{FieldKind, HeaderFieldMap, Registration};
    use zenoh_protocol::{scouting::ScoutingMessage, transport::TransportMessage};

    impl Registration for ZenohProtocol {
        fn generate_hf_map(prefix: &str) -> HeaderFieldMap {
            let mut hf_map = HeaderFieldMap::new()
                .add(prefix.to_string(), "Zenoh Protocol", FieldKind::Branch)
                .add(format!("{prefix}.batch"), "Batch", FieldKind::Branch);
            hf_map.extend(TransportMessage::generate_hf_map(prefix));
            hf_map.extend(ScoutingMessage::generate_hf_map(prefix));
            hf_map
        }

        fn generate_subtree_names(prefix: &str) -> Vec<String> {
            let mut names = vec![prefix.to_string(), format!("{prefix}.batch")];
            names.extend(TransportMessage::generate_subtree_names(prefix));
            names.extend(ScoutingMessage::generate_subtree_names(prefix));
            names
        }
    }
}

mod impl_for_transport {
    use zenoh_protocol::{
        network::NetworkMessage,
        transport::{
            Close, Fragment, Frame, InitAck, InitSyn, Join, KeepAlive, Oam, OpenAck, OpenSyn,
            TransportBody, TransportMessage,
        },
    };

    use crate::zenoh_impl::*;

    impl_for_struct! {
        struct InitAck {
            version: u8,
            whatami: WhatAmI,
            zid: ZenohId,
            resolution: Resolution,
            batch_size: BatchSize,
            cookie: ZSlice,
            ext_qos: Option<QoS>,
            ext_qos_link: Option<QoSLink>,
            ext_auth: Option<Auth>,
            ext_mlink: Option<MultiLink>,
        }
    }

    impl_for_struct! {
        struct InitSyn {
            version: u8,
            whatami: WhatAmI,
            zid: ZenohId,
            resolution: Resolution,
            batch_size: BatchSize,
            ext_qos: Option<QoS>,
            ext_qos_link: Option<QoSLink>,
            ext_auth: Option<Auth>,
            ext_mlink: Option<MultiLink>,
        }
    }

    impl_for_struct! {
        struct OpenSyn {
            lease: Duration,
            initial_sn: TransportSn,
            cookie: ZSlice,
            ext_qos: Option<QoS>,
            ext_auth: Option<Auth>,
            ext_mlink: Option<MultiLinkSyn>,
        }
    }

    impl_for_struct! {
        struct OpenAck {
            lease: Duration,
            initial_sn: TransportSn,
            ext_qos: Option<QoS>,
            ext_auth: Option<Auth>,
            ext_mlink: Option<MultiLinkAck>,
        }
    }

    impl_for_struct! {
        struct Close {
            reason: u8,
            session: bool,
        }
    }

    impl_for_struct! {
        struct KeepAlive {}
    }

    impl_for_struct! {
        struct Frame {
            reliability: Reliability,
            sn: TransportSn,
            ext_qos: QoSType,
            #[dissect(expand_vec_as = "network")]
            payload: Vec<NetworkMessage>,
        }
    }

    impl_for_struct! {
        struct Fragment {
            reliability: Reliability,
            more: bool,
            sn: TransportSn,
            payload: ZSlice,
            ext_qos: QoSType,
        }
    }

    impl_for_struct! {
        struct Oam {
            id: OamId,
            body: ZExtBody,
            ext_qos: QoSType,
        }
    }

    impl_for_struct! {
        struct Join {
            version: u8,
            whatami: WhatAmI,
            zid: ZenohId,
            resolution: Resolution,
            batch_size: BatchSize,
            lease: Duration,
            next_sn: PrioritySn,
            ext_qos: Option<QoSType>,
            ext_shm: Option<Shm>,
        }
    }

    impl_for_enum! {
        enum TransportBody {
            InitSyn(InitSyn),
            InitAck(InitAck),
            OpenSyn(OpenSyn),
            OpenAck(OpenAck),
            Close(Close),
            KeepAlive(KeepAlive),
            Frame(Frame),
            Fragment(Fragment),
            OAM(Oam),
            Join(Join),
        }
    }

    impl_for_struct! {
        struct TransportMessage {
            #[dissect(expand_as = "transport")]
            body: TransportBody,
        }
    }
}

mod impl_for_zenoh {
    use zenoh_protocol::zenoh::{
        err::Err, query::Query, reply::Reply, Del, PushBody, Put, RequestBody, ResponseBody,
    };

    use crate::zenoh_impl::*;

    impl_for_struct! {
        struct Put {
            timestamp: Option<Timestamp>,
            encoding: Encoding,
            ext_sinfo: Option<SourceInfoType>,
            ext_unknown: Vec<ZExtUnknown>,
            payload: ZBuf,
        }
    }

    impl_for_struct! {
        struct Del {
            timestamp: Option<Timestamp>,
            ext_sinfo: Option<SourceInfoType>,
            ext_unknown: Vec<ZExtUnknown>,
        }
    }

    impl_for_struct! {
        struct Query {
            parameters: String,
            consolidation: Consolidation,
            ext_sinfo: Option<SourceInfoType>,
            ext_body: Option<QueryBodyType>,
            ext_unknown: Vec<ZExtUnknown>,
        }
    }

    impl_for_struct! {
        struct Reply {
            consolidation: Consolidation,
            ext_unknown: Vec<ZExtUnknown>,
            payload: PushBody,
        }
    }

    impl_for_struct! {
        struct Err {
            ext_sinfo: Option<SourceInfoType>,
            ext_unknown: Vec<ZExtUnknown>,
        }
    }

    impl_for_enum! {
        enum RequestBody {
            Query(Query),
        }
    }

    impl_for_enum! {
        enum PushBody {
            Put(Put),
            Del(Del),
        }
    }

    impl_for_enum! {
        enum ResponseBody {
            Reply(Reply),
            Err(Err),
        }
    }
}

mod impl_for_network {
    use zenoh_protocol::{
        network::{
            Declare, DeclareBody, DeclareFinal, DeclareKeyExpr, DeclareQueryable,
            DeclareSubscriber, DeclareToken, Interest, NetworkBody, NetworkMessage, Oam, Push,
            Request, Response, ResponseFinal, UndeclareKeyExpr, UndeclareQueryable,
            UndeclareSubscriber, UndeclareToken,
        },
        zenoh::{PushBody, RequestBody, ResponseBody},
    };

    use crate::zenoh_impl::*;

    impl_for_struct! {
        struct Push {
            wire_expr: WireExpr<'static>,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
            ext_nodeid: NodeIdType,
            #[dissect(expand)]
            payload: PushBody,
        }
    }

    impl_for_struct! {
        struct Request {
            id: RequestId,
            wire_expr: WireExpr<'static>,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
            ext_nodeid: NodeIdType,
            ext_target: TargetType,
            ext_budget: Option<BudgetType>,
            ext_timeout: Option<TimeoutType>,
            #[dissect(expand)]
            payload: RequestBody,
        }
    }

    impl_for_struct! {
        struct Response {
            rid: RequestId,
            wire_expr: WireExpr<'static>,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
            ext_respid: Option<ResponderIdType>,
            #[dissect(expand)]
            payload: ResponseBody,
        }
    }

    impl_for_struct! {
        struct ResponseFinal {
            rid: RequestId,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
        }
    }

    impl_for_struct! {
        struct Interest {
            id: InterestId,
            mode: InterestMode,
            options: InterestOptions,
            wire_expr: Option<WireExpr<'static>>,
            ext_qos: ext::QoSType,
            ext_tstamp: Option<ext::TimestampType>,
            ext_nodeid: ext::NodeIdType,
        }
    }

    mod impl_for_declare {
        use zenoh_protocol::network::{
            DeclareFinal, DeclareKeyExpr, DeclareQueryable, DeclareSubscriber, DeclareToken,
            UndeclareKeyExpr, UndeclareQueryable, UndeclareSubscriber, UndeclareToken,
        };

        use crate::zenoh_impl::*;

        impl_for_struct! {
            struct DeclareKeyExpr {
                id: ExprId,
                wire_expr: WireExpr<'static>,
            }
        }

        impl_for_struct! {
            struct UndeclareKeyExpr {
                id: ExprId,
            }
        }

        impl_for_struct! {
            struct DeclareSubscriber {
                id: SubscriberId,
                wire_expr: WireExpr<'static>,
            }
        }

        impl_for_struct! {
            struct UndeclareSubscriber {
                id: SubscriberId,
                ext_wire_expr: WireExprType,
            }
        }

        impl_for_struct! {
            struct DeclareQueryable {
                id: QueryableId,
                wire_expr: WireExpr<'static>,
                ext_info: QueryableInfo,
            }
        }

        impl_for_struct! {
            struct UndeclareQueryable {
                id: QueryableId,
                ext_wire_expr: WireExprType,
            }
        }

        impl_for_struct! {
            struct DeclareToken {
                id: TokenId,
                wire_expr: WireExpr<'static>,
            }
        }

        impl_for_struct! {
            struct UndeclareToken {
                id: TokenId,
                ext_wire_expr: WireExprType,
            }
        }

        impl_for_struct! {
            struct DeclareFinal {}
        }
    }

    impl_for_enum! {
        enum DeclareBody {
            DeclareKeyExpr(DeclareKeyExpr),
            UndeclareKeyExpr(UndeclareKeyExpr),
            DeclareSubscriber(DeclareSubscriber),
            UndeclareSubscriber(UndeclareSubscriber),
            DeclareQueryable(DeclareQueryable),
            UndeclareQueryable(UndeclareQueryable),
            DeclareToken(DeclareToken),
            UndeclareToken(UndeclareToken),
            DeclareFinal(DeclareFinal),
        }
    }

    impl_for_struct! {
        struct Declare {
            interest_id: Option<super::interest::InterestId>,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
            ext_nodeid: NodeIdType,
            #[dissect(expand)]
            body: DeclareBody,
        }
    }

    impl_for_struct! {
        struct Oam {
            id: OamId,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
            body: ZExtBody,
        }
    }

    impl_for_enum! {
        enum NetworkBody {
            Push(Push),
            Request(Request),
            Response(Response),
            ResponseFinal(ResponseFinal),
            Interest(Interest),
            Declare(Declare),
            OAM(Oam),
        }
    }

    impl_for_struct! {
        struct NetworkMessage {
            #[dissect(expand)]
            body: NetworkBody,
        }
    }
}

mod impl_for_scouting {
    use zenoh_protocol::scouting::{
        hello::HelloProto, scout::Scout, ScoutingBody, ScoutingMessage,
    };

    use crate::zenoh_impl::*;

    impl_for_struct! {
        struct Scout {
            version: u8,
            what: WhatAmIMatcher,
            zid: Option<ZenohIdProto>,
        }
    }

    impl_for_struct! {
        struct HelloProto {
            version: u8,
            whatami: WhatAmI,
            zid: ZenohIdProto,
            locators: Vec<Locator>,
        }
    }

    impl_for_enum! {
        enum ScoutingBody {
            Scout(Scout),
            Hello(HelloProto),
        }
    }

    impl_for_struct! {
        struct ScoutingMessage {
            #[dissect(expand)]
            body: ScoutingBody,
        }
    }
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    use crate::header_field::{FieldKind, Registration};
    use zenoh_protocol::{network::NetworkBody, scouting::ScoutingBody, transport::TransportBody};

    fn assert_subtree_consistent(
        prefix: &str,
        hf_map: &crate::header_field::HeaderFieldMap,
        subtree_names: &[String],
    ) {
        assert!(
            hf_map.contains_key(prefix),
            "prefix '{prefix}' missing from hf_map"
        );
        assert!(
            subtree_names.contains(&prefix.to_string()),
            "prefix '{prefix}' missing from subtree_names"
        );
    }

    #[test]
    fn transport_body_variants_registered_as_branches() {
        let hf = TransportBody::generate_hf_map("zenoh.body");
        for v in [
            "init_syn",
            "init_ack",
            "open_syn",
            "open_ack",
            "close",
            "keep_alive",
            "frame",
            "fragment",
            "oam",
            "join",
        ] {
            let key = format!("zenoh.body.{v}");
            assert!(
                hf.contains_key(&key),
                "variant branch '{key}' missing from hf_map"
            );
            assert!(
                matches!(hf[&key].kind, FieldKind::Branch),
                "variant '{key}' must be FieldKind::Branch"
            );
        }
    }

    #[test]
    fn transport_body_variants_registered_as_subtrees() {
        let names = TransportBody::generate_subtree_names("zenoh.body");
        for v in [
            "init_syn",
            "init_ack",
            "open_syn",
            "open_ack",
            "close",
            "keep_alive",
            "frame",
            "fragment",
            "oam",
            "join",
        ] {
            let key = format!("zenoh.body.{v}");
            assert!(
                names.contains(&key),
                "variant subtree '{key}' missing from generate_subtree_names"
            );
        }
    }

    #[test]
    fn keep_alive_variant_is_consistent() {
        let hf = TransportBody::generate_hf_map("zenoh.body");
        let names = TransportBody::generate_subtree_names("zenoh.body");
        assert_subtree_consistent("zenoh.body.keep_alive", &hf, &names);
    }

    #[test]
    fn network_body_variants_registered() {
        let hf = NetworkBody::generate_hf_map("zenoh.body.frame.body");
        let names = NetworkBody::generate_subtree_names("zenoh.body.frame.body");
        for v in [
            "push",
            "request",
            "response",
            "response_final",
            "interest",
            "declare",
            "oam",
        ] {
            let key = format!("zenoh.body.frame.body.{v}");
            assert_subtree_consistent(&key, &hf, &names);
        }
    }

    #[test]
    fn scouting_body_variants_registered() {
        let hf = ScoutingBody::generate_hf_map("zenoh.body");
        let names = ScoutingBody::generate_subtree_names("zenoh.body");
        for v in ["scout", "hello"] {
            let key = format!("zenoh.body.{v}");
            assert_subtree_consistent(&key, &hf, &names);
        }
    }

    #[test]
    fn all_hf_branches_have_subtree_entries() {
        let hf = ZenohProtocol::generate_hf_map("zenoh");
        let names: std::collections::HashSet<String> =
            ZenohProtocol::generate_subtree_names("zenoh")
                .into_iter()
                .collect();

        let mut missing = vec![];
        for (key, field) in hf.iter() {
            if matches!(field.kind, FieldKind::Branch) && !names.contains(key) {
                missing.push(key.as_str());
            }
        }
        missing.sort();
        assert!(
            missing.is_empty(),
            "Branch nodes in hf_map have no subtree entry: {missing:?}"
        );
    }
}
