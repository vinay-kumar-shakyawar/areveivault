//! Outgoing email over SMTP. Optional: without `SMTP_HOST` nothing is sent.
//! Only used for staff notifications, never for anything that carries vault data.

use std::time::Duration;

use anyhow::Context;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Smtp;

pub struct Email<'a> {
    pub to: &'a [String],
    pub cc: &'a [String],
    /// Skipped when it isn't a valid address.
    pub reply_to: Option<&'a str>,
    pub subject: &'a str,
    pub body: String,
}

pub async fn send(smtp: &Smtp, email: Email<'_>) -> anyhow::Result<()> {
    let from_name = (!smtp.from_name.is_empty()).then(|| smtp.from_name.clone());
    let from = smtp.from.parse::<Address>().context("SMTP_FROM is not an email address")?;
    let mut msg = Message::builder()
        .from(Mailbox::new(from_name, from))
        .subject(email.subject)
        .header(ContentType::TEXT_PLAIN);
    for a in email.to {
        msg = msg.to(Mailbox::new(None, a.parse::<Address>().with_context(|| format!("recipient {a}"))?));
    }
    for a in email.cc {
        msg = msg.cc(Mailbox::new(None, a.parse::<Address>().with_context(|| format!("cc recipient {a}"))?));
    }
    if let Some(Ok(a)) = email.reply_to.map(|a| a.parse::<Address>()) {
        msg = msg.reply_to(Mailbox::new(None, a));
    }
    let msg = msg.body(email.body)?;

    // 465 is TLS from the first byte; every other port upgrades with STARTTLS. Never plaintext.
    let builder = if smtp.port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)?
    };
    let mut builder = builder.port(smtp.port).timeout(Some(Duration::from_secs(15)));
    if !smtp.user.is_empty() {
        builder = builder.credentials(Credentials::new(smtp.user.clone(), smtp.pass.clone()));
    }
    let transport: AsyncSmtpTransport<Tokio1Executor> = builder.build();
    transport.send(msg).await?;
    Ok(())
}
