//! 握手与密钥磋商（V1.2）。
//!
//! 白皮书规定：握手阶段复用 **QUIC**（强制 TLS1.3 + 证书/公钥指纹校验）作为可靠承载，
//! 在受保护的可靠流内完成 X25519 标准 DH 交换，再以 HKDF-SHA256 派生会话根种子 `S₀`。
//!
//! 本模块：
//! - 提供纯密码学的 DH 磋商与根种子派生（可脱离网络直接验证）。
//! - 通过 [`Transport`] trait 定义与 QUIC 可靠通道的集成契约，便于接入 quinn/quiche 等实现。
//!
//! **安全要点（必须遵守，否则引入中间人漏洞）：**
//! 1. 必须在 QUIC 上强制启用 TLS1.3，并**显式校验对端证书指纹 / 自签公钥**，
//!    禁止关闭证书验证、禁止无条件跳过校验。
//! 2. 仅接受既受信任的指纹集合，扩展指纹需人工审计。

use crate::crypto;
use crate::KEY_LEN;
use rand_core::{OsRng, RngCore};

/// 握手过程暴露的协议错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// 对端 DH 载荷长度非法（必须恰好 64 字节 = public_key(32) || salt(32)）。
    #[error("invalid peer payload length {0} (expected 64)")]
    BadPeerPayload(usize),
}

/// 一方在一次握手中的地位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// 一次 X25519 DH 密钥对。
pub struct DhKeyPair {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
}

impl std::fmt::Debug for DhKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 绝不打日志印私钥与共享密钥；仅暴露公钥观察信息。
        f.debug_struct("DhKeyPair").field("public", &self.public).finish()
    }
}

impl DhKeyPair {
    /// 生成一个全新的 DH 密钥对（客户端 / 服务端各自调用一次）。
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        DhKeyPair {
            secret,
            public: public.to_bytes(),
        }
    }

    /// 本地公钥（应通过 QUIC 受保护流发送给对方）。
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// 派生出待发送的握手帧 = public_key(32) || salt(32)。
    pub fn outbound_frame(&self, salt: &[u8; 32]) -> [u8; 64] {
        let mut f = [0u8; 64];
        f[..32].copy_from_slice(&self.public);
        f[32..].copy_from_slice(salt);
        f
    }

    /// 以对方公钥 + 双方拼接的会话盐派生会话根种子 `S₀`。
    /// 仅在 QUIC-TLS 校验完成、确认对方是可信对端后方可调用。
    pub fn derive_session_root_with_salt(
        &self,
        peer_public: &[u8; 32],
        session_salt: &[u8],
    ) -> [u8; KEY_LEN] {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        let dh = self.secret.diffie_hellman(&peer);
        let raw: [u8; 32] = dh.to_bytes();
        crypto::derive_session_root(&raw, session_salt)
    }
}

/// 解析一帧对端握手数据。
pub fn parse_peer_frame(frame: &[u8]) -> Result<([u8; 32], [u8; 32]), HandshakeError> {
    if frame.len() != 64 {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let mut peer_pub = [0u8; 32];
    let mut peer_salt = [0u8; 32];
    peer_pub.copy_from_slice(&frame[..32]);
    peer_salt.copy_from_slice(&frame[32..64]);
    Ok((peer_pub, peer_salt))
}

/// 生成 32 字节密码学安全随机数（用于会话盐等一次性随机值）。
pub fn random_bytes_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// 与 QUIC 可靠通道绑定的握手传输契约。
///
/// 实现方负责：在 QUIC（TLS1.3，强制证书/指纹校验）连接上完成身份校验后，
/// 通过可靠流可靠地交换 64 字节握手帧。QUIC 自带重传，握手包缺失被可靠承载，
/// 恰好满足白皮书“握手可靠性、抗丢包”的要求。
pub trait Transport {
    type Error;
    /// 可靠写入（QUIC 提供的流语义）。
    fn reliable_write(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    /// 可靠读取一帧（QUIC 提供的流语义）。
    fn reliable_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// 在任意满足 [`Transport`] 的可信通道上完成一次完整 DH 磋商（单端视角）。
///
/// 流程（双方各执行一次 `negotiate`）：
/// 1. 生成 DH 密钥对与会话盐；
/// 2. 可靠发送 `public_key || salt`；
/// 3. 可靠读取对方 `peer_public_key || peer_salt`；
/// 4. 按角色拼接双方盐，派生会话根种子 `S₀`。
///
/// > 调用前必须在 QUIC-TLS 层完成对端身份校验；身份未通过的连接不得进入本流程。
pub fn negotiate<T: Transport>(
    role: Role,
    transport: &mut T,
) -> Result<(DhKeyPair, [u8; KEY_LEN], [u8; 32]), HandshakeError>
where
    T::Error: std::fmt::Debug,
{
    let kp = DhKeyPair::generate();
    let salt = random_bytes_32();
    let outbound = kp.outbound_frame(&salt);

    transport
        .reliable_write(&outbound)
        .expect("QUIC stream write failure");
    let mut frame = [0u8; 64];
    transport
        .reliable_read_exact(&mut frame)
        .expect("QUIC stream read failure");
    let (peer_pub, peer_salt) = parse_peer_frame(&frame)?;

    // 双方盐拼接；角色顺序固定为 A||B 以保证两端一致。
    let combined = match role {
        Role::Initiator => crypto::combine_session_salts(&salt, &peer_salt),
        Role::Responder => crypto::combine_session_salts(&peer_salt, &salt),
    };
    let root = kp.derive_session_root_with_salt(&peer_pub, &combined);
    Ok((kp, root, salt))
}

/// 便捷：验证给定公钥是否在受信任指纹集合中（自签证书指纹比对场景）。
pub fn is_trusted_peer(peer_public: &[u8; 32], trusted_set: &[[u8; 32]]) -> bool {
    trusted_set.iter().any(|t| t == peer_public)
}