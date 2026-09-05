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
    /// 对端 DH 载荷长度非法（必须恰好 [`HANDSHAKE_FRAME_LEN`] 字节）。
    #[error("invalid peer payload length {0} (expected {expected})", expected = HANDSHAKE_FRAME_LEN)]
    BadPeerPayload(usize),
    /// X25519 派生出全零共享密钥（对端公钥为低阶点），握手被强制拒绝。
    #[error("weak/zero DH shared secret (low-order peer public key)")]
    WeakDhSecret,
    /// 底层可靠通道（QUIC）读写失败。
    ///
    /// 返回错误而非 panic，避免攻击者以 RST/断开流的方式让握手进程崩溃。
    #[error("transport error during handshake")]
    Transport,
    /// 对端握手帧版本 / 能力与本地不兼容。
    ///
    /// 握手帧携带协议版本与能力位图（含方向化密钥），一旦对方缺失所需能力，
    /// 拒绝建立会话而非降级回单一 root 模式，封死旧客户端降级攻击（漏洞 F）。
    #[error("incompatible peer during handshake (version {peer_version}, capabilities {capabilities:#010b}, required {required:#010b})")]
    IncompatiblePeer {
        /// 对端声明的协议版本。
        peer_version: u8,
        /// 对端声明的能力位图。
        capabilities: u8,
        /// 握手必需的能力位图。
        required: u8,
    },
}

/// 握手帧长度：`version(1) || capabilities(1) || public_key(32) || salt(32)`。
pub const HANDSHAKE_FRAME_LEN: usize = 66;
/// 本实现支持的协议版本。V1.2 对应的版本号 = 2。
pub const PROTOCOL_VERSION: u8 = 2;
/// 能力位：支持**方向化根种子**（双向链路密钥空间隔离，防跨方向重放）。
pub const CAP_DIRECTIONAL_KEYS: u8 = 0b0000_0001;
/// 握手成立**必须**满足的能力集。
///
/// 任何一方若声明的能力缺少本位，`negotiate` 将返回 [`HandshakeError::IncompatiblePeer`]，
/// 拒绝降级到缺失该能力的（旧）单一 root 模式 —— 该模式下双向密钥可跨方向重放。
pub const REQUIRED_CAPABILITIES: u8 = CAP_DIRECTIONAL_KEYS;

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

    /// 派生出待发送的握手帧 =
    /// `version(1) || capabilities(1) || public_key(32) || salt(32)`。
    ///
    /// 帧头携带协议版本与能力位图，使对端能在派生密钥前进行能力协商；
    /// 缺失必需能力的对端将连接失败，而非静默降级（见 [`REQUIRED_CAPABILITIES`]）。
    pub fn outbound_frame(&self, salt: &[u8; 32]) -> [u8; HANDSHAKE_FRAME_LEN] {
        let mut f = [0u8; HANDSHAKE_FRAME_LEN];
        f[0] = PROTOCOL_VERSION;
        f[1] = CAP_DIRECTIONAL_KEYS;
        f[2..34].copy_from_slice(&self.public);
        f[34..].copy_from_slice(salt);
        f
    }

    /// 暴露原始 X25519 共享密钥（用于审计验证；正常流程请走
    /// [`DhKeyPair::derive_directional_roots_with_salt`] 的校验路径）。
    pub fn dh_shared_secret(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }

    /// 以对方公钥 + 双方拼接的会话盐派生**方向化会话根种子对**
    /// `(root_initiator_to_responder, root_responder_to_initiator)`。
    ///
    /// 除执行 RFC 7748 低阶点校验外，本方法同时产出两个互不相同的方向根，
    /// 使双向链路密钥空间隔离 —— 复用单一根种子会让双向密钥在相同 coord 下完全一致，
    /// 攻击者可跨方向解密或重放。返回的对请按 [`Role`] 分配给两端各自的 Sender/Receiver。
    pub fn derive_directional_roots_with_salt(
        &self,
        peer_public: &[u8; 32],
        session_salt: &[u8],
    ) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), HandshakeError> {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        let dh = self.secret.diffie_hellman(&peer);
        let raw: [u8; 32] = dh.to_bytes();
        if is_all_zero(&raw) {
            return Err(HandshakeError::WeakDhSecret);
        }
        Ok(crypto::derive_directional_roots(&raw, session_salt))
    }
}

/// 解析一帧对端握手数据，取出公钥与会话盐。
///
/// 纯载荷提取，**不校验**版本与能力（供审计验证 / 单元测试直接使用）。
/// 生产握手请走 [`parse_handshake_frame`]，它会强制版本与能力协商。
pub fn parse_peer_frame(frame: &[u8]) -> Result<([u8; 32], [u8; 32]), HandshakeError> {
    if frame.len() != HANDSHAKE_FRAME_LEN {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let mut peer_pub = [0u8; 32];
    let mut peer_salt = [0u8; 32];
    peer_pub.copy_from_slice(&frame[2..34]);
    peer_salt.copy_from_slice(&frame[34..HANDSHAKE_FRAME_LEN]);
    Ok((peer_pub, peer_salt))
}

/// 对端握手帧的解析结果（含版本与能力位图）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeFrame {
    /// 对端声明的协议版本。
    pub version: u8,
    /// 对端声明的能力位图。
    pub capabilities: u8,
    /// 对端 DH 公钥。
    pub peer_public: [u8; 32],
    /// 对端会话盐。
    pub peer_salt: [u8; 32],
}

/// 解析对端握手帧，并执行**版本 + 能力协商**。
///
/// 若对端版本 ≠ [`PROTOCOL_VERSION`]，或对端能力缺少 [`REQUIRED_CAPABILITIES`]
/// （即方向化密钥），返回 [`HandshakeError::IncompatiblePeer`] —— **拒绝建立会话**，
/// 而非静默降级回单一 root 模式（该模式允许跨方向重放，漏洞 F）。
pub fn parse_handshake_frame(frame: &[u8]) -> Result<HandshakeFrame, HandshakeError> {
    if frame.len() != HANDSHAKE_FRAME_LEN {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let hf = HandshakeFrame {
        version: frame[0],
        capabilities: frame[1],
        peer_public: <[u8; 32]>::try_from(&frame[2..34]).expect("slice is exactly 32 bytes"),
        peer_salt: <[u8; 32]>::try_from(&frame[34..HANDSHAKE_FRAME_LEN])
            .expect("slice is exactly 32 bytes"),
    };
    if hf.version != PROTOCOL_VERSION
        || (hf.capabilities & REQUIRED_CAPABILITIES) != REQUIRED_CAPABILITIES
    {
        return Err(HandshakeError::IncompatiblePeer {
            peer_version: hf.version,
            capabilities: hf.capabilities,
            required: REQUIRED_CAPABILITIES,
        });
    }
    Ok(hf)
}

/// RFC 7748：拒绝全零共享密钥，避免低阶点注入弱密钥。
fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|&b| b == 0)
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

/// 一次完整 DH 磋商的产物。
///
/// `Debug` 实现通过 `DhKeyPair` 的自定义安全 Debug，绝不打印私钥与共享密钥。
#[derive(Debug)]
pub struct HandshakeSession {
    /// 本地 DH 密钥对（公钥用于后续审计验证）。
    pub keypair: DhKeyPair,
    /// 本次磋商中己方扮演的角色。
    pub role: Role,
    /// Initiator→Responder 方向会话根种子。
    ///
    /// 分配给 **Initiator 的发送端** 与 **Responder 的接收端**。
    pub root_initiator_to_responder: [u8; KEY_LEN],
    /// Responder→Initiator 方向会话根种子。
    ///
    /// 分配给 **Responder 的发送端** 与 **Initiator 的接收端**。
    pub root_responder_to_initiator: [u8; KEY_LEN],
    /// 本地产生的会话盐。
    pub session_salt: [u8; 32],
}

/// 在任意满足 [`Transport`] 的可信通道上完成一次完整 DH 磋商（单端视角）。
///
/// 流程（双方各执行一次 `negotiate`）：
/// 1. 生成 DH 密钥对与会话盐；
/// 2. 可靠发送 `public_key || salt`；
/// 3. 可靠读取对方 `peer_public_key || peer_salt`；
/// 4. 按角色拼接双方盐，派生方向化会话根种子对。
///
/// > 调用前必须在 QUIC-TLS 层完成对端身份校验；身份未通过的连接不得进入本流程。
///
/// # 安全
///
/// 底层可靠通道的读写错误以 [`HandshakeError::Transport`] 返回，**绝不 panic**：
/// 攻击者通过 RST 或断开流中止握手时，只会得到一个可处理的错误，不会击穿进程。
pub fn negotiate<T: Transport>(
    role: Role,
    transport: &mut T,
) -> Result<HandshakeSession, HandshakeError> {
    let kp = DhKeyPair::generate();
    let salt = random_bytes_32();
    let outbound = kp.outbound_frame(&salt);

    transport
        .reliable_write(&outbound)
        .map_err(|_| HandshakeError::Transport)?;
    let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
    transport
        .reliable_read_exact(&mut frame)
        .map_err(|_| HandshakeError::Transport)?;
    // 版本 + 能力协商：对端缺失方向化密钥能力时直接拒绝，绝不降级回
    // 单一 root 模式（该模式允许跨方向重放 / 旧客户端降级，见漏洞 F/I）。
    let peer = parse_handshake_frame(&frame)?;
    let peer_pub = peer.peer_public;
    let peer_salt = peer.peer_salt;

    // 双方盐拼接；角色顺序固定为 A||B 以保证两端一致。
    let combined = match role {
        Role::Initiator => crypto::combine_session_salts(&salt, &peer_salt),
        Role::Responder => crypto::combine_session_salts(&peer_salt, &salt),
    };
    let (root_initiator_to_responder, root_responder_to_initiator) =
        kp.derive_directional_roots_with_salt(&peer_pub, &combined)?;
    Ok(HandshakeSession {
        keypair: kp,
        role,
        root_initiator_to_responder,
        root_responder_to_initiator,
        session_salt: salt,
    })
}

/// 便捷：验证给定公钥是否在受信任指纹集合中（自签证书指纹比对场景）。
pub fn is_trusted_peer(peer_public: &[u8; 32], trusted_set: &[[u8; 32]]) -> bool {
    trusted_set.iter().any(|t| t == peer_public)
}