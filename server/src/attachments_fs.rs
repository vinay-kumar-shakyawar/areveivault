//! Encrypted attachment blobs on disk: `<ATTACHMENT_DIR>/<org_id>/<attachment_id>`.
//! Contents are client-side STREAM ciphertext; ids are UUIDs, so no path traversal.

use std::path::PathBuf;

use uuid::Uuid;

use crate::state::AppState;

pub fn path(st: &AppState, org_id: Uuid, id: Uuid) -> PathBuf {
    st.cfg.attachment_dir.join(org_id.to_string()).join(id.to_string())
}

pub async fn write(st: &AppState, org_id: Uuid, id: Uuid, data: &[u8]) -> std::io::Result<()> {
    let p = path(st, org_id, id);
    tokio::fs::create_dir_all(p.parent().unwrap()).await?;
    let tmp = p.with_extension("tmp");
    tokio::fs::write(&tmp, data).await?;
    tokio::fs::rename(&tmp, &p).await
}

pub async fn remove_all(st: &AppState, org_id: Uuid, ids: &[Uuid]) {
    for id in ids {
        let _ = tokio::fs::remove_file(path(st, org_id, *id)).await;
    }
}
