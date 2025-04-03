use crate::header_field::*;
use crate::macros::{impl_for_enum, impl_for_struct};
use crate::tree::*;
use crate::utils::nul_terminated_str;
use anyhow::Result;
use convert_case::{Case, Casing};

pub struct ZenohProtocol;

mod impl_for_zenoh_protocol {
    use super::ZenohProtocol;
    use crate::header_field::{FieldKind, HeaderFieldMap, Registration};
    use zenoh_protocol::transport::TransportMessage;

    impl Registration for ZenohProtocol {
        fn generate_hf_map(prefix: &str) -> HeaderFieldMap {
            let mut hf_map =
                HeaderFieldMap::new().add(prefix.to_string(), "ZenohProtocol", FieldKind::Branch);
            hf_map.extend(TransportMessage::generate_hf_map(prefix));
            hf_map
        }

        fn generate_subtree_names(prefix: &str) -> Vec<String> {
            let mut names = vec![prefix.to_string()];
            names.extend(TransportMessage::generate_subtree_names(prefix));
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

    // InitAck
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

    // InitSyn
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

    // OpenSyn
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

    // OpenAck
    impl_for_struct! {
        struct OpenAck {
            lease: Duration,
            initial_sn: TransportSn,
            ext_qos: Option<QoS>,
            ext_auth: Option<Auth>,
            ext_mlink: Option<MultiLinkAck>,
        }
    }

    // Close
    impl_for_struct! {
        struct Close {
            reason: u8,
            session: bool,
        }
    }

    // KeepAlive
    impl_for_struct! {
        struct KeepAlive {

        }
    }

    // Frame
    impl_for_struct! {
        struct Frame {
            reliability: Reliability,
            sn: TransportSn,
            ext_qos: QoSType,
            #[decode(vec)]
            payload: Vec<NetworkMessage>,
        }
    }

    // Fragment
    impl_for_struct! {
        struct Fragment {
            reliability: Reliability,
            more: bool,
            sn: TransportSn,
            payload: ZSlice,
            ext_qos: QoSType,
        }
    }

    // OAM
    impl_for_struct! {
        struct Oam {
            id: OamId,
            body: ZExtBody,
            ext_qos: QoSType,
        }
    }

    // Join
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

    // TransportBody
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

    // TransportMessage
    impl_for_struct! {
        struct TransportMessage {
            #[dissect(expand)]
            body: TransportBody,
        }
    }
}

mod impl_for_zenoh {
    use zenoh_protocol::zenoh::{
        err::Err, query::Query, reply::Reply, Del, PushBody, Put, RequestBody, ResponseBody,
    };

    use crate::zenoh_impl::*;

    // Put
    impl_for_struct! {
        struct Put {
            timestamp: Option<Timestamp>,
            encoding: Encoding,
            ext_sinfo: Option<SourceInfoType>,
            ext_unknown: Vec<ZExtUnknown>,
            payload: ZBuf,
        }
    }

    // Del
    impl_for_struct! {
        struct Del {
            timestamp: Option<Timestamp>,
            ext_sinfo: Option<SourceInfoType>,
            ext_unknown: Vec<ZExtUnknown>,
        }
    }

    // Query
    impl_for_struct! {
        struct Query {
            parameters: String,
            consolidation: Consolidation,
            ext_sinfo: Option<SourceInfoType>,
            ext_body: Option<QueryBodyType>,
            ext_unknown: Vec<ZExtUnknown>,
        }
    }

    // Reply
    impl_for_struct! {
        struct Reply {
            consolidation: Consolidation,
            ext_unknown: Vec<ZExtUnknown>,
            payload: PushBody,
        }
    }

    // Err
    impl_for_struct! {
        struct Err {
            ext_sinfo: Option<SourceInfoType>,
            ext_unknown: Vec<ZExtUnknown>,
        }
    }

    // RequestBody
    impl_for_enum! {
        enum RequestBody {
            Query(Query),
        }
    }

    // PushBody
    impl_for_enum! {
        enum PushBody {
            Put(Put),
            Del(Del),
        }
    }

    // ResponseBody
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

    // Push
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

    // Request
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

    // Response
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

    // ResponseFinal
    impl_for_struct! {
        struct ResponseFinal {
            rid: RequestId,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
        }
    }

    // Interest
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

        // DeclareKeyExpr
        impl_for_struct! {
            struct DeclareKeyExpr {
                id: ExprId,
                wire_expr: WireExpr<'static>,
            }
        }

        // UndeclareKeyExpr
        impl_for_struct! {
            struct UndeclareKeyExpr {
                id: ExprId,
            }
        }

        // DeclareSubscriber
        impl_for_struct! {
            struct DeclareSubscriber {
                id: SubscriberId,
                wire_expr: WireExpr<'static>,
            }
        }

        // UndeclareSubscriber
        impl_for_struct! {
            struct UndeclareSubscriber {
                id: SubscriberId,
                ext_wire_expr: WireExprType,
            }
        }

        // DeclareQueryable
        impl_for_struct! {
            struct DeclareQueryable {
                id: QueryableId,
                wire_expr: WireExpr<'static>,
                ext_info: QueryableInfo,
            }
        }

        // UndeclareQueryable
        impl_for_struct! {
            struct UndeclareQueryable {
                id: QueryableId,
                ext_wire_expr: WireExprType,
            }
        }

        // DeclareToken
        impl_for_struct! {
            struct DeclareToken {
                id: TokenId,
                wire_expr: WireExpr<'static>,
            }
        }

        // UndeclareToken
        impl_for_struct! {
            struct UndeclareToken {
                id: TokenId,
                ext_wire_expr: WireExprType,
            }
        }

        // DeclareFinal
        impl_for_struct! {
            struct DeclareFinal {
            }
        }
    }

    // DeclareBody
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

    // Declare
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

    // Oam
    impl_for_struct! {
        struct Oam {
            id: OamId,
            ext_qos: QoSType,
            ext_tstamp: Option<TimestampType>,
            body: ZExtBody,
        }
    }

    // NetworkBody
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

    // NetworkMessage
    impl_for_struct! {
        struct NetworkMessage {
            #[dissect(expand)]
            body: NetworkBody,
        }
    }
}
