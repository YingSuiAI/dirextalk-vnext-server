include!("group_parts/group_test_prelude.rs");

include!("group_parts/group_test_helpers_types.rs");
include!("group_parts/group_test_helpers_admission.rs");
include!("group_parts/group_test_helpers_proofs.rs");
include!("group_parts/group_test_helpers_mls.rs");
include!("group_parts/group_test_helpers_assertions.rs");

mod remote {
    use super::*;
    include!("group_parts/group_test_remote.rs");
}
mod discovery {
    use super::*;
    include!("group_parts/group_test_discovery.rs");
}
mod feed {
    use super::*;
    include!("group_parts/group_test_feed.rs");
}
mod recovery {
    use super::*;
    include!("group_parts/group_test_recovery.rs");
}
mod federated_recovery {
    use super::*;
    include!("group_parts/group_test_federated_recovery.rs");
}
mod parser {
    use super::*;
    include!("group_parts/group_test_parser.rs");
}
mod compose {
    use super::*;
    include!("group_parts/group_test_compose.rs");
}
mod replay {
    use super::*;
    include!("group_parts/group_test_replay.rs");
}
mod control {
    use super::*;
    include!("group_parts/group_test_control.rs");
}
