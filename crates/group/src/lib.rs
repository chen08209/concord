#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod bridge;
mod check;
mod deps;
mod error;
mod fetch;
mod first_write;
mod group;
pub mod health;
pub mod http;
mod node;
mod outbounds;
mod provider;
mod public_suffix;
mod selection;
mod shared;
mod strategy;
mod urltest;
mod views;

#[cfg(test)]
mod tests;

pub use bridge::ProxyFactory;
pub use check::{Check, CheckSpec, Extra};
pub use deps::{
    BuildFailure, Built, Builtin, DEFAULT_TEST_TIMEOUT, DEFAULT_TEST_URL, EnvFactory, GroupDeps,
    NoDefaults, NodeFactory, RouteMoved, TestDefaults,
};
pub use error::{FetchError, FetchErrorKind, GroupError, ProviderError};
pub use fetch::{FetchHead, FetchRequest, FetchResponse, Fetcher};
pub use group::{Emptiness, Group, Members, Pick, Policy, Touch};
pub use health::{DelayRecord, HealthSnapshot, NodeHealth, Outcome, StatusRanges, UrlHealth};
pub use node::{Ghost, Item, Leaf, Node};
pub use outbounds::{Outbounds, Resolved, SelectOutcome, Staged, load_balancer_exit, node_exit};
pub use provider::{ProviderNodes, ProviderView, ProxyProvider, SubscriptionInfo, VehicleType};
pub use selection::SelectionStore;
pub use strategy::Strategy;
pub use views::{GroupView, NodeStateView, NodeView, ProxyView, ProxyViews};
