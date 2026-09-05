//! 握手与密钥磋商（V1.2）。
//!
//! 白皮书规定：握手阶段复用 **QUIC**（强制 TLS1.3 + 证书/公钥指纹校验）作为可靠承载，
//! 在受保护的可靠流内完成 X25519 标准 DH 交换，再以 HKDF-SHA256 派生会话根种子 `S₀`。
//!
//! 本模块：
//! - 提供纯密码学的 DH 磋商、**强制身份认证**与根种子派生（可脱离网络直接验证）。
//! - 通过 [`Transport`] trait 定义与 QUIC 可靠通道的集成契约，便于接入 quinn/quiche 等实现。
//!
//! **安全要点（身份认证已在代码内强制，不可绕过）：**
//! 1. `negotiate` 每次都以预共享身份密钥（[`IdentityKey`]）对握手帧做
//!    **Key-Confirmation（HMAC）认证**，只有持有该身份密钥的主体才能建立会话；
//!    即使底层 `Transport` 关闭了证书校验，未知身份密钥的 MITM 也无法通过认证。
//! 2. 底层 QUIC 仍应启用 TLS1.3 并校验证书指纹作为运输层第二道防线。

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
    /// 对端未通过身份认证（Key-Confirmation 校验失败）。
    ///
    /// 握手帧携带的 HMAC 认证器与共享身份密钥重算值不一致：可能是对端不持有该
    /// 预共享身份密钥（MITM / 伪造方 / 密钥不匹配），也可能是帧被篡改。一律拒绝会话。
    #[error("peer identity authentication failed")]
    AuthenticationFailed,
}

/// 握手帧长度（字节）：
/// `version(1) || capabilities(1) || public_key(32) || salt(32) || authenticator(32)`。
pub const HANDSHAKE_FRAME_LEN: usize = 98;
/// 握手帧中 DH 公钥的起始偏移（version + capabilities 之后）。
pub const PUBLIC_KEY_OFFSET: usize = 2;
/// 握手帧中盐的起始偏移（公钥结束）。
pub const SALT_OFFSET: usize = 34;
/// 握手帧尾部 32 字节身份认证器（Key-Confirmation）。
pub const AUTH_OFFSET: usize = SALT_OFFSET + 32;
/// 身份认证器长度（字节）。
pub const AUTHER_LEN: usize = 32;
/// 本实现支持的协议版本。V1.2 对应的版本号 = 2。
pub const PROTOCOL_VERSION: u8 = 2;
/// 能力位：支持**方向化根种子**（双向链路密钥空间隔离，防跨方向重放）。
pub const CAP_DIRECTIONAL_KEYS: u8 = 0b0000_0001;
/// 角色字节：Initiator 的编码（纳入身份认证器的角色绑定，防角色混淆）。
pub const ROLE_INITIATOR: u8 = 0x01;
/// 角色字节：Responder 的编码。
pub const ROLE_RESPONDER: u8 = 0x02;
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

impl Role {
    /// 角色的认证字节（纳入身份认证器，绑定「在哪一个方向上认证对端」）。
    pub fn byte(self) -> u8 {
        match self {
            Role::Initiator => ROLE_INITIATOR,
            Role::Responder => ROLE_RESPONDER,
        }
    }
}

/// 预共享身份密钥（32 字节长期身份），用于握手 **Key-Confirmation**。
///
/// 两端的部署方预先共享同一把身份密钥（带外分发 / 秘钥管理服务）。每次 `negotiate`
/// 都会在握手帧尾部附加 `HMAC-SHA256(identity, ...)` 认证器，接收方用同一把密钥
/// 重算并做常数时间对比。由此：
///
/// - **身份认证**：只有持有该密钥的主体才能产出有效认证器，双方相互证实「确实与
///   已知主体通信」，封死`无身份认证`的 MITM —— 攻击者不知密钥，无法提交带有效
///   认证器的握手帧。
/// - **完整性**：帧内任何一字节被篡改（代理改写版本/能力/公钥/盐）都会使重算结果
///   失配，会话被拒。
///
/// `Debug` 实现绝不打印密钥内容。
#[derive(Clone)]
pub struct IdentityKey([u8; 32]);

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentityKey(***redacted***)")
    }
}

impl IdentityKey {
    /// 从一个确定的 32 字节秘密构造身份密钥（部署时注入）。
    pub fn new(secret: &[u8; 32]) -> Self {
        IdentityKey(*secret)
    }

    /// 生成一把全新随机身份密钥 —— 仅用于部署引导 / 测试；生产应使用固定配置。
    pub fn generate() -> Self {
        let b = random_bytes_32();
        IdentityKey(b)
    }

    /// 取明文（仅限内部与必要处使用，切勿日志输出）。
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
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
    /// `version(1) || capabilities(1) || public_key(32) || salt(32) || authenticator(32)`。
    ///
    /// 帧头携带协议版本与能力位图，使对端能在派生密钥前进行能力协商；尾部附加
    /// 基于预共享身份密钥的 HMAC 认证器（Key-Confirmation），使对端能**认证我方身份**。
    /// 缺失必需能力的对端将连接失败，而非静默降级（见 [`REQUIRED_CAPABILITIES`]）。
    pub fn outbound_frame(
        &self,
        salt: &[u8; 32],
        identity: &IdentityKey,
        role: Role,
    ) -> [u8; HANDSHAKE_FRAME_LEN] {
        let mut f = [0u8; HANDSHAKE_FRAME_LEN];
        f[0] = PROTOCOL_VERSION;
        f[1] = CAP_DIRECTIONAL_KEYS;
        f[PUBLIC_KEY_OFFSET..SALT_OFFSET].copy_from_slice(&self.public);
        f[SALT_OFFSET..AUTH_OFFSET].copy_from_slice(salt);
        let auth = crypto::authenticate_frame(
            identity.bytes(),
            PROTOCOL_VERSION,
            CAP_DIRECTIONAL_KEYS,
            role.byte(),
            &self.public,
            salt,
        );
        f[AUTH_OFFSET..].copy_from_slice(&auth);
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
/// 纯载荷提取，**不校验**版本、能力与身份认证（供审计验证 / 单元测试直接使用）。
/// 生产握手请走 [`parse_handshake_frame`]，它会强制版本、能力协商与身份认证。
pub fn parse_peer_frame(frame: &[u8]) -> Result<([u8; 32], [u8; 32]), HandshakeError> {
    if frame.len() != HANDSHAKE_FRAME_LEN {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let mut peer_pub = [0u8; 32];
    let mut peer_salt = [0u8; 32];
    peer_pub.copy_from_slice(&frame[PUBLIC_KEY_OFFSET..SALT_OFFSET]);
    peer_salt.copy_from_slice(&frame[SALT_OFFSET..AUTH_OFFSET]);
    Ok((peer_pub, peer_salt))
}

/// 对端握手帧的解析结果（含版本、能力位图与身份认证器）。
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
    /// 对端附加的 32 字节身份认证器（已由 [`parse_handshake_frame`] 验证通过）。
    pub authenticator: [u8; 32],
}

/// 解析对端握手帧，并执行 **版本 + 能力协商 + 身份认证**。
///
/// 1. 长度校验（必须恰好 [`HANDSHAKE_FRAME_LEN`] 字节）；
/// 2. 版本 / 能力协商：对端版本 ≠ [`PROTOCOL_VERSION`] 或能力缺少
///    [`REQUIRED_CAPABILITIES`]（方向化密钥）→ [`HandshakeError::IncompatiblePeer`]，
///    **拒绝降级**回单一 root 模式（允许跨方向重放，漏洞 F）；
/// 3. **身份认证（漏洞：无身份认证）**：以预共享身份密钥 + `peer_role` 重算对端帧的
///    HMAC 认证器，与帧内携带值做常数时间对比。失配一律 [`HandshakeError::AuthenticationFailed`]。
///
/// `local_role` 用于推导对端角色（Initiator↔Responder 互逆），并把该角色字节纳入
/// 认证输入，绑定发送方的身份声明。
pub fn parse_handshake_frame(
    frame: &[u8],
    identity: &IdentityKey,
    local_role: Role,
) -> Result<HandshakeFrame, HandshakeError> {
    if frame.len() != HANDSHAKE_FRAME_LEN {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let peer_role = match local_role {
        Role::Initiator => Role::Responder,
        Role::Responder => Role::Initiator,
    };
    let hf = HandshakeFrame {
        version: frame[0],
        capabilities: frame[1],
        peer_public: <[u8; 32]>::try_from(&frame[PUBLIC_KEY_OFFSET..SALT_OFFSET])
            .expect("slice is exactly 32 bytes"),
        peer_salt: <[u8; 32]>::try_from(&frame[SALT_OFFSET..AUTH_OFFSET])
            .expect("slice is exactly 32 bytes"),
        authenticator: <[u8; 32]>::try_from(&frame[AUTH_OFFSET..HANDSHAKE_FRAME_LEN])
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
    // Key-Confirmation：只有持有身份密钥的对端才能产出匹配的认证器。
    let expected = crypto::authenticate_frame(
        identity.bytes(),
        hf.version,
        hf.capabilities,
        peer_role.byte(),
        &hf.peer_public,
        &hf.peer_salt,
    );
    if !crypto::ct_eq(&expected, &hf.authenticator) {
        return Err(HandshakeError::AuthenticationFailed);
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
/// 实现方负责：在 QUIC（TLS1.3）连接上通过可靠流交换 [`HANDSHAKE_FRAME_LEN`] 字节握手帧。
/// QUIC 自带重传，握手包缺失被可靠承载，恰好满足白皮书“握手可靠性、抗丢包”的要求。
/// **身份认证由 [`negotiate`] 内的 Key-Confirmation 强制执行**，本 trait 不承担也不可绕过。
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

/// 在任意满足 [`Transport`] 的可信通道上完成一次 **强制身份认证** 的 DH 磋商（单端视角）。
///
/// 流程（双方各执行一次 `negotiate`）：
/// 1. 生成 DH 密钥对与会话盐；
/// 2. 发送已附 **身份认证器** 的握手帧（版本 || 能力 || 公钥 || 盐 || HMAC）；
/// 3. 可靠读取对端帧，先做 **版本 + 能力协商**，再以共享身份密钥做
///    **Key-Confirmation 认证** —— 身份不符 / 帧被篡改一律拒绝会话；
/// 4. 按角色拼接双方盐，派生方向化会话根种子对。
///
/// `identity` 必须是双方部署前共享的预共享身份密钥。身份认证在 `negotiate` 内**强制**执行，
/// 无法绕过 —— 即使底层 `Transport` 关闭了 QUIC 证书校验，未持有身份密钥的 MITM 也
/// 无法提交带有效认证器的握手帧，从而封死「无身份认证」漏洞。
///
/// # 安全
///
/// 底层可靠通道的读写错误以 [`HandshakeError::Transport`] 返回，**绝不 panic**：
/// 攻击者通过 RST 或断开流中止握手时，只会得到一个可处理的错误，不会击穿进程。
pub fn negotiate<T: Transport>(
    role: Role,
    identity: &IdentityKey,
    transport: &mut T,
) -> Result<HandshakeSession, HandshakeError> {
    let kp = DhKeyPair::generate();
    let salt = random_bytes_32();
    let outbound = kp.outbound_frame(&salt, identity, role);

    transport
        .reliable_write(&outbound)
        .map_err(|_| HandshakeError::Transport)?;
    let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
    transport
        .reliable_read_exact(&mut frame)
        .map_err(|_| HandshakeError::Transport)?;
    // 版本 + 能力协商 + **身份认证**：对端缺失方向化能力或身份认证失配时直接拒绝，
    // 绝不降级回单一 root 模式（允许跨方向重放）或与未知主体建连（允许 MITM）。
    let peer = parse_handshake_frame(&frame, identity, role)?;
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