//! OPAQUE (RFC 9807) via `opaque-ke`. The password input is `K_auth` from the
//! two-secret KDF, already stretched by Argon2id, so the OPAQUE KSF is Identity.
//! The server crate uses the same `Suite`.

pub use opaque_ke;
use opaque_ke::key_exchange::tripledh::TripleDh;
use opaque_ke::ksf::Identity;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialResponse, RegistrationResponse, Ristretto255,
};

use crate::{Error, Result};

pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeGroup = Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = Identity;
}

pub struct RegistrationStart {
    pub state: ClientRegistration<Suite>,
    pub message: Vec<u8>,
}

pub fn registration_start(k_auth: &[u8]) -> Result<RegistrationStart> {
    let r = ClientRegistration::<Suite>::start(&mut rand::rngs::OsRng, k_auth).map_err(|_| Error::Opaque)?;
    Ok(RegistrationStart { message: r.message.serialize().to_vec(), state: r.state })
}

/// Returns the registration upload for the server.
pub fn registration_finish(state: ClientRegistration<Suite>, k_auth: &[u8], response: &[u8]) -> Result<Vec<u8>> {
    let resp = RegistrationResponse::<Suite>::deserialize(response).map_err(|_| Error::Opaque)?;
    let r = state
        .finish(&mut rand::rngs::OsRng, k_auth, resp, ClientRegistrationFinishParameters::default())
        .map_err(|_| Error::Opaque)?;
    Ok(r.message.serialize().to_vec())
}

pub struct LoginStart {
    pub state: ClientLogin<Suite>,
    pub message: Vec<u8>,
}

pub fn login_start(k_auth: &[u8]) -> Result<LoginStart> {
    let r = ClientLogin::<Suite>::start(&mut rand::rngs::OsRng, k_auth).map_err(|_| Error::Opaque)?;
    Ok(LoginStart { message: r.message.serialize().to_vec(), state: r.state })
}

/// Fails (without revealing why) on a wrong password, wrong Secret Key, or an
/// impostor server. Returns the finalization message for the server.
pub fn login_finish(state: ClientLogin<Suite>, k_auth: &[u8], response: &[u8]) -> Result<Vec<u8>> {
    let resp = CredentialResponse::<Suite>::deserialize(response).map_err(|_| Error::Opaque)?;
    let r = state
        .finish(k_auth, resp, ClientLoginFinishParameters::default())
        .map_err(|_| Error::Opaque)?;
    Ok(r.message.serialize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin,
        ServerLoginStartParameters, ServerRegistration, ServerSetup,
    };

    fn register(setup: &ServerSetup<Suite>, pw: &[u8], id: &[u8]) -> ServerRegistration<Suite> {
        let start = registration_start(pw).unwrap();
        let req = RegistrationRequest::<Suite>::deserialize(&start.message).unwrap();
        let resp = ServerRegistration::<Suite>::start(setup, req, id).unwrap();
        let upload = registration_finish(start.state, pw, &resp.message.serialize()).unwrap();
        ServerRegistration::<Suite>::finish(RegistrationUpload::<Suite>::deserialize(&upload).unwrap())
    }

    fn login(setup: &ServerSetup<Suite>, record: Option<ServerRegistration<Suite>>, pw: &[u8], id: &[u8]) -> bool {
        let start = login_start(pw).unwrap();
        let req = CredentialRequest::<Suite>::deserialize(&start.message).unwrap();
        let s = ServerLogin::start(&mut rand::rngs::OsRng, setup, record, req, id, ServerLoginStartParameters::default())
            .unwrap();
        let Ok(fin) = login_finish(start.state, pw, &s.message.serialize()) else {
            return false;
        };
        s.state.finish(CredentialFinalization::<Suite>::deserialize(&fin).unwrap()).is_ok()
    }

    #[test]
    fn full_flow() {
        let setup = ServerSetup::<Suite>::new(&mut rand::rngs::OsRng);
        let id = b"user@arevei.com";
        let rec = register(&setup, b"k_auth-correct", id);
        let bytes = rec.serialize();
        let reload = || ServerRegistration::<Suite>::deserialize(&bytes).unwrap();
        assert!(login(&setup, Some(reload()), b"k_auth-correct", id));
        assert!(!login(&setup, Some(reload()), b"k_auth-wrong", id));
        // Unknown user: server runs the fake-record flow; client fails indistinguishably.
        assert!(!login(&setup, None, b"anything", b"nobody@arevei.com"));
    }
}
