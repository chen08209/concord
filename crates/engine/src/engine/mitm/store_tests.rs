use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use concord_config::mitm::modules::{AppliedModule, ModuleSpec};
use concord_group::{FetchError, FetchErrorKind, FetchRequest, FetchResponse, Fetcher};

use super::*;

/// Answers each URL from a table the test edits; a URL not in it fails to connect. While
/// `hang` is set, no request is answered.
#[derive(Default)]
struct Answers(
    Mutex<BTreeMap<String, (u16, Vec<u8>)>>,
    std::sync::atomic::AtomicBool,
);

impl Answers {
    fn set(&self, url: &str, status: u16, body: &[u8]) {
        lock(&self.0).insert(url.to_string(), (status, body.to_vec()));
    }
}

#[async_trait]
impl Fetcher for Answers {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        if self.1.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let (status, body) = lock(&self.0)
            .get(&request.url)
            .cloned()
            .ok_or_else(|| FetchError::new(FetchErrorKind::Connection, "refused"))?;
        Ok(FetchResponse {
            status,
            headers: Vec::new(),
            body,
        })
    }
}

const URL: &str = "https://cdn.test/s.js";

fn store(dir: &std::path::Path) -> (Arc<Answers>, ModuleResources) {
    let answers = Arc::new(Answers::default());
    let home = Arc::new(HomeDir::new(dir));
    (answers.clone(), ModuleResources::open(home, answers))
}

fn read(dir: &std::path::Path, file: &str) -> Vec<u8> {
    std::fs::read(dir.join(RESOURCES_DIR).join(file)).unwrap()
}

#[tokio::test]
async fn a_fetched_file_is_stored_by_its_content_and_outlives_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let (answers, resources) = store(dir.path());
    assert_eq!(resources.state(URL), (ResourceState::Missing, None));
    answers.set(URL, 200, b"one");
    assert_eq!(resources.fetch(URL).await, Ok(true));
    let first = resources.stored(URL).unwrap();
    assert_eq!(first, stored_name(URL, b"one"));
    assert_eq!(read(dir.path(), &first), b"one");
    assert_eq!(resources.state(URL), (ResourceState::Ok, None));
    assert_eq!(resources.fetch(URL).await, Ok(false));

    answers.set(URL, 200, b"two");
    assert_eq!(resources.fetch(URL).await, Ok(true));
    let second = resources.stored(URL).unwrap();
    assert_eq!(read(dir.path(), &second), b"two");
    assert!(!dir.path().join(RESOURCES_DIR).join(&first).exists());

    let (_, reopened) = store(dir.path());
    assert_eq!(reopened.stored(URL), Some(second));
}

#[tokio::test]
async fn a_failed_fetch_names_its_reason_and_keeps_the_file_in_force() {
    let dir = tempfile::tempdir().unwrap();
    let (answers, resources) = store(dir.path());
    let failure = resources.fetch(URL).await.unwrap_err();
    assert_eq!(failure.reason, FailureReason::Connection);
    assert_eq!(resources.state(URL), (ResourceState::Failed, Some(failure)));
    assert_eq!(resources.stored(URL), None);

    answers.set(URL, 200, b"one");
    resources.fetch(URL).await.unwrap();
    answers.set(URL, 404, b"");
    let failure = resources.fetch(URL).await.unwrap_err();
    assert_eq!(
        (failure.reason, failure.status),
        (FailureReason::Http, Some(404))
    );
    assert_eq!(resources.state(URL).0, ResourceState::Failed);
    assert_eq!(resources.stored(URL), Some(stored_name(URL, b"one")));
}

#[tokio::test]
async fn a_file_one_url_shares_with_another_stays_when_either_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (answers, resources) = store(dir.path());
    let other = "https://mirror.test/s.js";
    answers.set(URL, 200, b"same");
    answers.set(other, 200, b"same");
    resources.fetch(URL).await.unwrap();
    resources.fetch(other).await.unwrap();
    let shared = resources.stored(URL).unwrap();
    answers.set(URL, 200, b"new");
    resources.fetch(URL).await.unwrap();
    assert_eq!(read(dir.path(), &shared), b"same");
}

fn adopting(url: &str, file: &str) -> AppliedModule {
    AppliedModule {
        spec: ModuleSpec {
            name: "m".into(),
            adopt_resources: BTreeMap::from([(url.to_string(), file.to_string())]),
            ..ModuleSpec::default()
        },
        ..AppliedModule::default()
    }
}

#[test]
fn a_file_the_host_stored_is_adopted_only_while_it_is_there_and_unindexed() {
    let dir = tempfile::tempdir().unwrap();
    let (_, resources) = store(dir.path());
    assert!(!resources.adopt(&[adopting(URL, "host.js")]));
    std::fs::create_dir_all(dir.path().join(RESOURCES_DIR)).unwrap();
    std::fs::write(dir.path().join(RESOURCES_DIR).join("host.js"), "x").unwrap();
    assert!(!resources.adopt(&[adopting(URL, "../host.js")]));
    assert!(resources.adopt(&[adopting(URL, "host.js")]));
    assert_eq!(resources.stored(URL).as_deref(), Some("host.js"));
    assert!(!resources.adopt(&[adopting(URL, "host.js")]));
}

#[tokio::test]
async fn a_fetch_dropped_halfway_leaves_the_url_free_to_fetch_again() {
    let dir = tempfile::tempdir().unwrap();
    let (answers, resources) = store(dir.path());
    answers.1.store(true, std::sync::atomic::Ordering::SeqCst);
    {
        let fetch = resources.fetch(URL);
        tokio::pin!(fetch);
        tokio::select! {
            _ = &mut fetch => panic!("the fetch was answered"),
            () = async {
                while resources.state(URL).0 != ResourceState::Fetching {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    }
    assert_eq!(resources.state(URL), (ResourceState::Missing, None));
    answers.1.store(false, std::sync::atomic::Ordering::SeqCst);
    answers.set(URL, 200, b"one");
    assert_eq!(resources.fetch(URL).await, Ok(true));
    assert_eq!(resources.state(URL), (ResourceState::Ok, None));
}
