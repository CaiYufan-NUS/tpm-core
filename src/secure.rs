use crate::{
    auth::{write_cmd_session, AuthErr, RspAuth},
    chip::MSG_MAX,
    crypto::{HmacSha256Ctx, NonceSource, Sha256Ctx},
    phy::TisPhy,
    session::AuthSession,
    xfer::{Xfer, XferErr, RC_SUCCESS},
};
use core::sync::atomic::{AtomicUsize, Ordering};

static NEXT_GUARD_ID: AtomicUsize = AtomicUsize::new(1);

/// Partition of an authorized command within the buffer.
///
/// This is provided by the caller rather than inferred by this layer: the partition depends on how
/// many handles the command has and how its parameters are arranged, which is command-layer
/// knowledge. This layer is responsible only for checking that these partitions do not overlap and
/// then filling them in.
///
/// Callers must ensure `sess_off + CMD_SESSION_LEN` and `param_off + param_len` are within the
/// command buffer and that the two areas do not overlap.
pub struct CmdLayout {
    /// Total command length. It must match the length field in the packet header; this is checked by
    /// the link layer.
    pub len: usize,
    /// Start of the authorization area.
    pub sess_off: usize,
    /// This session's index within the authorization area.
    pub index: usize,
    /// Start of the parameter area.
    pub param_off: usize,
    /// Length of the parameter area.
    pub param_len: usize,
    /// Number of handles in the response. The digest covers the portion after the handles, and if this
    /// count is wrong, the entire offset layout becomes wrong.
    pub rhandles: usize,
}
impl CmdLayout {
    fn validate(&self, buf_len: usize) -> bool {
        let Some(sess_end) = self.sess_off.checked_add(crate::auth::CMD_SESSION_LEN) else {
            return false;
        };
        let Some(param_end) = self.param_off.checked_add(self.param_len) else {
            return false;
        };
        if sess_end > buf_len
            || param_end > buf_len
            || sess_end > self.param_off && self.sess_off < param_end
        {
            return false;
        }
        self.len <= buf_len
    }
}
/// A credential certifying that “this response MAC matches”.
///
/// The location result `a` can be made public: reading a few offsets does not create any capability; the
/// capability lies in the credential itself. The credential is created only after [`Guarded::invoke`]
/// validates successfully, and `#[non_exhaustive]` prevents external code from constructing one out of
/// thin air.
#[non_exhaustive]
pub struct Authenticated {
    pub a: RspAuth,
    guard_id: usize,
    generation: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecErr {
    /// Bytes did not complete a full round trip.
    Bus(XferErr),
    /// The device returned a non-zero return code. This type of response has no authorization area and
    /// cannot be validated.
    Rc(u32),
    /// The response arrived, but authorization validation failed.
    Auth(AuthErr),
}
pub struct Guarded<P: TisPhy> {
    x: Xfer<P>,
    sess: AuthSession,
    guard_id: usize,
    generation: u64,
    active_auth: Option<RspAuth>,
    /// Response buffer. All guarantees of this layer rely on the fact that the caller outside the module
    /// cannot access it.
    rbuf: [u8; MSG_MAX],
}
impl<P: TisPhy> Guarded<P> {
    pub fn new(x: Xfer<P>, sess: AuthSession) -> Self {
        Guarded {
            x,
            sess,
            guard_id: NEXT_GUARD_ID.fetch_add(1, Ordering::Relaxed),
            generation: 0,
            active_auth: None,
            rbuf: [0u8; MSG_MAX],
        }
    }
    fn credential_matches(&self, t: &Authenticated) -> bool {
        t.guard_id == self.guard_id
            && t.generation == self.generation
            && self.active_auth == Some(t.a)
    }
    /// Send an authorized command; it returns only if the MAC matches.
    ///
    /// The caller must have already prepared the packet header, handle area, and parameter area and must
    /// leave space for the authorization area according to `lay`. The authorization area is filled by
    /// this function; it contains the current nonce, which is generated only when the round is finalized,
    /// so the caller cannot fill it in advance.
    ///
    /// All failure paths invalidate the session. Retrying with the same key after the session has failed
    /// gives the peer one more guessing opportunity; invalidating it forces a fresh handshake, which costs
    /// one round trip but prevents guessing opportunities from accumulating.
    pub fn invoke<S: Sha256Ctx, H: HmacSha256Ctx, R: NonceSource>(
        &mut self,
        rng: &mut R,
        cmd: &mut [u8],
        lay: CmdLayout,
        names: &[u8],
        ordinal: u32,
        attrs: u8,
    ) -> Result<Authenticated, SecErr> {
        self.active_auth = None;
        if !lay.validate(cmd.len()) {
            self.sess.close();
            return Err(SecErr::Auth(AuthErr::Malformed));
        }
        self.sess.begin(rng, ordinal, attrs);
        let handle = self.sess.handle();
        let nonce = self.sess.our_nonce();
        let sattrs = self.sess.attrs();
        write_cmd_session(cmd, lay.sess_off, handle, &nonce, sattrs);
        if self
            .sess
            .finalize::<S, H>(
                cmd,
                lay.sess_off,
                lay.index,
                names,
                lay.param_off,
                lay.param_len,
            )
            .is_err()
        {
            self.sess.close();
            return Err(SecErr::Auth(AuthErr::Malformed));
        }
        let n = match self.x.run(&*cmd, lay.len, &mut self.rbuf) {
            Ok((n, rc)) => {
                if rc != RC_SUCCESS {
                    self.sess.close();
                    return Err(SecErr::Rc(rc));
                }
                n
            }
            Err(e) => {
                self.sess.close();
                return Err(SecErr::Bus(e));
            }
        };
        let raw = &self.rbuf[0..n];
        let a = match self.sess.check_response::<S, H>(raw, lay.rhandles) {
            Ok(a) => a,
            Err(e) => return Err(SecErr::Auth(e)),
        };
        self.generation = self.generation.wrapping_add(1);
        self.active_auth = Some(a);
        Ok(Authenticated {
            a,
            guard_id: self.guard_id,
            generation: self.generation,
        })
    }
    /// Extract the parameter area from the response.
    ///
    /// This is the **only exit** for response bytes from this structure. The precondition requires a
    /// credential matching the current temporary buffer contents; without a credential, the bytes cannot
    /// be obtained, and an expired credential also prevents access.
    ///
    /// # Panics
    ///
    /// Panics if `t` is not the credential produced by the most recent successful [`Guarded::invoke`]
    /// on this guard.
    pub fn params<'a>(&'a self, t: &Authenticated) -> &'a [u8] {
        assert!(self.credential_matches(t), "stale or foreign credential");
        let off = t.a.param_off;
        let len = t.a.param_len;
        &self.rbuf[off..off + len]
    }
    /// Length of the response parameter area. The credential has already fixed this value, so there is
    /// no need to parse the packet again before reading it.
    ///
    /// # Panics
    ///
    /// Panics if `t` is not the credential produced by the most recent successful [`Guarded::invoke`]
    /// on this guard.
    pub fn param_len(&self, t: &Authenticated) -> usize {
        assert!(self.credential_matches(t), "stale or foreign credential");
        t.a.param_len
    }
    /// Return the link and end the authorized phase.
    ///
    /// The session disappears together with `self`, which is exactly what we want: a session that no
    /// longer holds the link has a broken nonce chain, and leaving it behind would make it appear
    /// type-wise valid to keep speaking with an old session.
    /// The response buffer is released as well, and the previously created credentials no longer have a
    /// matching packet to read. Their preconditions require the packet to match byte-for-byte the
    /// contents at creation time, and that packet is no longer present.
    pub fn release(self) -> Xfer<P> {
        self.x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::NONCE_LEN, tis::TisErr, tis_core::Tis};

    struct NullPhy;

    impl TisPhy for NullPhy {
        fn read8(&mut self, _addr: u32) -> Result<u8, TisErr> {
            Ok(0)
        }
        fn read32(&mut self, _addr: u32) -> Result<u32, TisErr> {
            Ok(0)
        }
        fn write8(&mut self, _addr: u32, _value: u8) -> Result<(), TisErr> {
            Ok(())
        }
        fn write32(&mut self, _addr: u32, _value: u32) -> Result<(), TisErr> {
            Ok(())
        }
        fn read_fifo(
            &mut self,
            _addr: u32,
            _out: &mut [u8],
            _off: usize,
            _n: usize,
        ) -> Result<(), TisErr> {
            Ok(())
        }
        fn write_fifo(
            &mut self,
            _addr: u32,
            _data: &[u8],
            _off: usize,
            _n: usize,
        ) -> Result<(), TisErr> {
            Ok(())
        }
        fn reset_fifo(&mut self, _addr: u32) {}
        fn delay(&mut self) {}
    }

    struct TestHmac;

    impl HmacSha256Ctx for TestHmac {
        fn with_key(_key: &[u8]) -> Self {
            Self
        }
        fn update(&mut self, _data: &[u8]) {}
        fn finish(self) -> [u8; crate::crypto::SHA256_LEN] {
            [0u8; crate::crypto::SHA256_LEN]
        }
    }

    fn new_guard() -> Guarded<NullPhy> {
        let x = Xfer::new(Tis::new(NullPhy, 0));
        let sess =
            AuthSession::open_session::<TestHmac>(1, &[], [1u8; NONCE_LEN], [2u8; NONCE_LEN]);
        Guarded::new(x, sess)
    }

    fn sample_auth() -> RspAuth {
        RspAuth {
            param_off: 4,
            param_len: 3,
            nonce_off: 16,
            hmac_off: 49,
            attrs: 0,
            tpm_nonce: [7u8; NONCE_LEN],
        }
    }

    #[test]
    fn params_accepts_current_credential() {
        let mut g = new_guard();
        g.rbuf[4..7].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let a = sample_auth();
        g.generation = 1;
        g.active_auth = Some(a);
        let t = Authenticated {
            a,
            guard_id: g.guard_id,
            generation: g.generation,
        };
        assert_eq!(g.param_len(&t), 3);
        assert_eq!(g.params(&t), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    #[should_panic(expected = "stale or foreign credential")]
    fn params_rejects_stale_credential() {
        let mut g = new_guard();
        let a = sample_auth();
        g.generation = 2;
        g.active_auth = Some(a);
        let stale = Authenticated {
            a,
            guard_id: g.guard_id,
            generation: 1,
        };
        let _ = g.params(&stale);
    }

    #[test]
    #[should_panic(expected = "stale or foreign credential")]
    fn params_rejects_retargeted_window() {
        let mut g = new_guard();
        let a = sample_auth();
        g.generation = 1;
        g.active_auth = Some(a);
        let mut retargeted = Authenticated {
            a,
            guard_id: g.guard_id,
            generation: g.generation,
        };
        retargeted.a.param_off = 0;
        retargeted.a.param_len = 32;
        let _ = g.params(&retargeted);
    }
}
