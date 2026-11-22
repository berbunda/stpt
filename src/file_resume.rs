//! Server-instance upload retention. Tokens never enter diagnostics or argv.
use crate::file_protocol::{Request, Status};
use crate::process::Account;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::OwnedSemaphorePermit;

pub struct Worker {
    pub child: Option<Child>,
    pub input: Option<ChildStdin>,
    pub output: Option<ChildStdout>,
    pub permit: Option<OwnedSemaphorePermit>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.input.take();
        self.output.take();
        if let Some(mut child) = self.child.take() {
            let permit = self.permit.take();
            tokio::spawn(async move {
                let _permit = permit;
                if tokio::time::timeout(Duration::from_secs(2), child.wait())
                    .await
                    .is_err()
                {
                    tracing::warn!("file worker cleanup stalled");
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                }
            });
        }
    }
}
struct Record {
    token: Option<Vec<u8>>,
    account: Account,
    request: Request,
    worker: Option<Worker>,
    interrupted: Instant,
}
#[derive(Default)]
pub struct Store(Mutex<BTreeMap<u64, Record>>);
impl Store {
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
    pub fn expire(&self) {
        self.0.lock().unwrap().retain(|_, r| {
            r.worker.is_none() || r.interrupted.elapsed() < Duration::from_secs(3600)
        });
    }
    pub fn acquire(
        self: &Arc<Self>,
        account: &Account,
        q: &Request,
    ) -> Result<(Lease, Option<Worker>), Status> {
        self.expire();
        let a = q
            .resume
            .as_ref()
            .and_then(crate::cbor::Value::as_array)
            .unwrap();
        let mut records = self.0.lock().unwrap();
        if a[0].as_uint() == Some(1) {
            let crate::cbor::Value::Bytes(token) = &a[1] else {
                unreachable!()
            };
            let Some((&id, r)) = records
                .iter_mut()
                .find(|(_, r)| r.token.as_ref() == Some(token))
            else {
                return Err(Status::ResumeUnavailable);
            };
            let old = &r.request;
            if r.account != *account
                || old.path != q.path
                || old.length != q.length
                || old.replace != q.replace
                || old.algorithm != q.algorithm
            {
                return Err(Status::ResumeUnavailable);
            }
            let worker = r.worker.take().ok_or(Status::ResumeBusy)?;
            return Ok((
                Lease {
                    store: self.clone(),
                    id,
                    parked: false,
                },
                Some(worker),
            ));
        }
        let length = q.length.unwrap();
        let same: Vec<_> = records
            .values()
            .filter(|r| r.account.name == account.name)
            .collect();
        if records.len() >= 16
            || same.len() >= 4
            || records
                .values()
                .map(|r| r.request.length.unwrap())
                .sum::<u64>()
                .saturating_add(length)
                > 16 * 1024 * 1024 * 1024
            || same
                .iter()
                .map(|r| r.request.length.unwrap())
                .sum::<u64>()
                .saturating_add(length)
                > 8 * 1024 * 1024 * 1024
        {
            return Err(Status::Limit);
        }
        let id = (0..).find(|n| !records.contains_key(n)).unwrap();
        records.insert(
            id,
            Record {
                token: None,
                account: account.clone(),
                request: q.clone(),
                worker: None,
                interrupted: Instant::now(),
            },
        );
        Ok((
            Lease {
                store: self.clone(),
                id,
                parked: false,
            },
            None,
        ))
    }
}
pub struct Lease {
    store: Arc<Store>,
    id: u64,
    parked: bool,
}
impl Lease {
    pub fn token(&self, token: Vec<u8>) {
        if let Some(r) = self.store.0.lock().unwrap().get_mut(&self.id) {
            r.token = Some(token);
        }
    }
    pub fn park(mut self, worker: Worker) {
        if let Some(r) = self.store.0.lock().unwrap().get_mut(&self.id) {
            r.worker = Some(worker);
            r.interrupted = Instant::now();
            self.parked = true;
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.parked {
            self.store.0.lock().unwrap().remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    fn request(length: u64, mode: Value) -> Request {
        Request {
            id: 0,
            kind: 2,
            path: Value::Array(vec![
                Value::Uint(0),
                Value::Array(vec![Value::Bytes(b"file".to_vec())]),
            ]),
            destination: None,
            replace: false,
            length: Some(length),
            algorithm: 1,
            resume: Some(mode),
        }
    }
    #[tokio::test]
    async fn binding_busy_expiry_and_quotas_do_not_disclose_records() {
        #[cfg(unix)]
        let name = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name;
        #[cfg(windows)]
        let name = Account::current_name().unwrap();
        let account = Account::lookup(&name).unwrap().unwrap();
        let store = Arc::new(Store::default());
        let q = request(1024, Value::Array(vec![Value::Uint(0)]));
        let (lease, _) = store.acquire(&account, &q).unwrap();
        lease.token(vec![9; 32]);
        let mut resume = request(
            1024,
            Value::Array(vec![Value::Uint(1), Value::Bytes(vec![9; 32])]),
        );
        assert!(matches!(
            store.acquire(&account, &resume),
            Err(Status::ResumeBusy)
        ));
        let mut foreign = account.clone();
        foreign.name.push_str("-foreign");
        assert!(matches!(
            store.acquire(&foreign, &resume),
            Err(Status::ResumeUnavailable)
        ));
        resume.replace = true;
        assert!(matches!(
            store.acquire(&account, &resume),
            Err(Status::ResumeUnavailable)
        ));
        resume.replace = false;
        lease.park(Worker {
            child: None,
            input: None,
            output: None,
            permit: None,
        });
        let (lease, worker) = store.acquire(&account, &resume).unwrap();
        assert!(worker.is_some());
        assert!(matches!(
            store.acquire(&account, &resume),
            Err(Status::ResumeBusy)
        ));
        lease.park(worker.unwrap());
        store
            .0
            .lock()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()
            .interrupted = Instant::now() - Duration::from_secs(3601);
        store.expire();
        assert!(matches!(
            store.acquire(&account, &resume),
            Err(Status::ResumeUnavailable)
        ));
        let mut leases = Vec::new();
        for _ in 0..4 {
            leases.push(store.acquire(&account, &q).unwrap().0);
        }
        assert!(matches!(store.acquire(&account, &q), Err(Status::Limit)));
        drop(leases);
        let too_large = request(
            8 * 1024 * 1024 * 1024 + 1,
            Value::Array(vec![Value::Uint(0)]),
        );
        assert!(matches!(
            store.acquire(&account, &too_large),
            Err(Status::Limit)
        ));
        assert!(store.0.lock().unwrap().is_empty());
    }
}
