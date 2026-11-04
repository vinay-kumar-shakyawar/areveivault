//! Security notifications (new-device login, invites, membership changes).
//! The email provider is an open decision (architecture §22), so the only
//! implementation logs a structured event; swap in SMTP/SES behind this trait.

#[derive(Debug, Clone, Copy)]
pub enum Notice {
    NewDeviceLogin,
    Invited,
    AccountApproved,
    AccountOffboarded,
    AccountLocked,
}

pub trait Notifier: Send + Sync {
    /// `detail` must never contain secrets (tokens, codes, ciphertext).
    fn notify(&self, to: &str, notice: Notice, detail: &str);
}

pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn notify(&self, to: &str, notice: Notice, detail: &str) {
        tracing::info!(target: "notify", to, notice = ?notice, detail, "notification (log-only delivery)");
    }
}
