//! A small thread-safe event bus. Unlike the key client's `&mut self` bus this one subscribes and
//! emits through `&self`, because the signature client shares it with closures that forward key
//! client events into it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

pub type Listener<E> = Arc<dyn Fn(&E) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenerId(u64);

struct Inner<E> {
    next_id: u64,
    listeners: Vec<(ListenerId, Listener<E>)>,
}

pub struct Bus<E> {
    inner: Mutex<Inner<E>>,
}

impl<E> Default for Bus<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> Bus<E> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_id: 0,
                listeners: Vec::new(),
            }),
        }
    }

    pub fn subscribe(&self, listener: Listener<E>) -> ListenerId {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let id = ListenerId(inner.next_id);
        inner.next_id += 1;
        inner.listeners.push((id, listener));
        id
    }

    pub fn unsubscribe(&self, id: ListenerId) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let before = inner.listeners.len();
        inner.listeners.retain(|(lid, _)| *lid != id);
        inner.listeners.len() != before
    }

    /// Listeners run outside the lock, so a listener may subscribe/unsubscribe. A panicking
    /// listener never breaks the emitter.
    pub fn emit(&self, event: &E) {
        let listeners: Vec<Listener<E>> = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            inner.listeners.iter().map(|(_, l)| Arc::clone(l)).collect()
        };
        for listener in listeners {
            let _ = catch_unwind(AssertUnwindSafe(|| listener(event)));
        }
    }
}
