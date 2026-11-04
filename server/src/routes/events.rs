//! Server-Sent Events: `event: sync` with `{"revision": N}` — never content.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::{self, Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::AuthUser;
use crate::state::AppState;

pub async fn events(State(st): State<AppState>, user: AuthUser) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = st.subscribe(user.org_id);
    let hello = stream::once(async { Ok(Event::default().comment("connected")) });
    let updates = BroadcastStream::new(rx).filter_map(|r| async move {
        r.ok().map(|rev| Ok(Event::default().event("sync").data(format!("{{\"revision\":{rev}}}"))))
    });
    Sse::new(hello.chain(updates)).keep_alive(KeepAlive::new().interval(Duration::from_secs(25)).text("keep-alive"))
}
