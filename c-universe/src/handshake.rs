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
/// `version(1) || capabilities(1) || psk_id(1) || public_key(32) || salt(32) || authenticator(32)`。
pub const HANDSHAKE_FRAME_LEN: usize = 99;
/// 握手帧中预共享身份密钥版本号的偏移（版本 + 能力之后）。
///
/// PSK 轮换：帧携带发送方所用 PSK 的版本 ID，接收方据此在密钥环中选取同版本 PSK 验证，
/// 未知版本一律拒绝 —— 一根 PSK 泄露或被吊销后，两端更换密钥环即可整体轮换，无需求样整个信任体系。
pub const PSK_ID_OFFSET: usize = 2;
/// 握手帧中 DH 公钥的起始偏移（version + capabilities + psk_id 之后）。
pub const PUBLIC_KEY_OFFSET: usize = 3;
/// 握手帧中盐的起始偏移（公钥结束）。
pub const SALT_OFFSET: usize = 35;
/// 握手帧尾部 32 字节身份认证器（Key-Confirmation）。
pub const AUTH_OFFSET: usize = SALT_OFFSET + 32;
/// 身份认证器长度（字节）。
pub const AUTHER_LEN: usize = 32;
/// 本实现支持的协议版本。V1.2 对应的版本号 = 2。
pub const PROTOCOL_VERSION: u8 = 2;
/// 能力位：支持**方向化根种子**（双向链路密钥空间隔离，防跨方向重放）。
pub const CAP_DIRECTIONAL_KEYS: u8 = 0b0000_0001;
/// 能力位：支持 **PKI 证书身份认证**（Ed25519 身份签名 + 根 CA 验证）。
///
/// 该位为置起时，握手改走 [`outbound_frame_pki`] / [`parse_handshake_frame_pki`] /
/// [`negotiate_pki`]：身份由长期签名密钥 + 自建根 CA 证书承担，替代（或并存于）PSK
/// Key-Confirmation。PSK 兜底入口仍是 [`outbound_frame`] / [`parse_handshake_frame`]。
pub const CAP_PKI: u8 = 0b0000_0010;
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
/// 都会在握手帧尾部附加 `HMAC-SHA256(AUTHK, ...)` 认证器，接收方用同一把密钥
/// 重算并做常数时间对比。由此：
///
/// - **身份认证**：只有持有该密钥的主体才能产出有效认证器，双方相互证实「确实与
///   已知主体通信」，封死`无身份认证`的 MITM —— 攻击者不知密钥，无法提交带有效
///   认证器的握手帧。
/// - **完整性**：帧内任何一字节被篡改（代理改写版本/能力/公钥/盐）都会使重算结果
///   失配，会话被拒。
///
/// # PSK 泄露防护（三项加固）
///
/// 1. **密码学加固**：PSK **从不直接作为 HMAC 密钥**。认证密钥
///    `AUTHK = HKDF-SHA256(IKM=PSK, salt=发送方会话盐)` 由 [`crypto::derive_auth_key`]
///    逐握手派生（见 [`crypto::AUTH_KEY_INFO`]），PSK 仅作 HKDF 输入，缩小暴露面且跨会话不复用。
/// 2. **生命周期/轮换**：PSK 带版本号，握手帧携带 `psk_id`；[`IdentityKeyRing`] 支持
///    部署一组版本化 PSK，一根泄露/吊销后可整体轮换而无需重建信任体系。
/// 3. **内存加固**：`Drop` 时以 [`zeroize`] 擦除明文，降低从核心转储/内存残留中被捞走的风险。
///
/// # 安全分发（务必遵守）
///
/// > 身份密钥是**身份信任根**：它一旦泄露等于整个会话体系的信任崩塌。
///
/// - **带外安全渠道分发**：必须经秘钥管理服务（KMS / Vault / 1Password / 部署编排 secret）
///   等**带外**渠道分发，任何一端在接入网络前就已持有。严禁通过不可信信道传输。
/// - **配置文件使用环境变量注入**：配置/部署清单中只写**引用占位符**（如
///   `C_UNIVERSE_IDENTITY_KEY`），密钥值**仅存在于运行环境**，不入源码库、不落盘明文、
///   不打进镜像层。生产建议用 [`IdentityKey::from_env`] / [`IdentityKeyRing::from_env`] 启动时注入。
/// - 明文仅在进程内存瞬时持有；`Debug`/`bytes` 绝不打印，杜绝落日志。
///
/// `Debug` 实现绝不打印密钥内容。
#[derive(Clone)]
pub struct IdentityKey {
    /// PSK 版本号（用于轮换时在密钥环中定位；默认 0）。
    version: u8,
    /// 32 字节身份密钥明文（`Drop` 时擦除）。
    secret: [u8; 32],
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentityKey(***redacted***)")
    }
}

/// 内存加固：身份密钥销毁时立即擦除，防止明文残留在堆/栈、核心转储或内存抓取中。
impl Drop for IdentityKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl IdentityKey {
    /// 从一个确定的 32 字节秘密构造版本 0 的身份密钥（部署时注入）。
    pub fn new(secret: &[u8; 32]) -> Self {
        IdentityKey {
            version: 0,
            secret: *secret,
        }
    }

    /// 以指定版本号 + 32 字节秘密构造身份密钥（版本化 PSK，用于轮换）。
    pub fn new_v(version: u8, secret: &[u8; 32]) -> Self {
        IdentityKey {
            version,
            secret: *secret,
        }
    }

    /// 生成一把全新随机身份密钥（版本 0）—— 仅用于部署引导 / 测试；生产应使用固定配置。
    pub fn generate() -> Self {
        let b = random_bytes_32();
        IdentityKey {
            version: 0,
            secret: b,
        }
    }

    /// 本 PSK 的版本号。
    pub fn version(&self) -> u8 {
        self.version
    }

    /// 从环境变量 `var` 启动时注入 hex 编码的 32 字节身份密钥（版本 0，**生产推荐**分发方式）。
    ///
    /// 部署方在带外生成密钥 → 以 hex（64 个十六进制字符）写入部署环境变量 →
    /// 程序启动时调用本函数读取并注入。密钥只存在于运行环境，吻合「配置文件用环境变量
    /// 注入、不入库不落盘」的安全分发要求（见 [`IdentityKey`] 文档）。
    ///
    /// 返回 `None`：变量未设置，或值不是合法的 64 个十六进制字符。
    ///
    /// ```
    /// // 部署示例（等价于 shell 里：export C_UNIVERSE_IDENTITY_KEY=<64 hex>）
    /// use c_universe::handshake::IdentityKey;
    /// let key = IdentityKey::from_env("C_UNIVERSE_IDENTITY_KEY");
    /// assert!(key.is_none(), "示例环境无该变量 → 返回 None 符合预期");
    /// ```
    pub fn from_env(var: &str) -> Option<Self> {
        let hex = std::env::var(var).ok()?;
        let bin = decode_hex(&hex)?;
        // 身份密钥必须恰好 32 字节（64 个十六进制字符）。
        if bin.len() != 32 {
            return None;
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&bin);
        Some(IdentityKey {
            version: 0,
            secret: b,
        })
    }

    /// 取明文（仅限内部与必要处使用，切勿日志输出）。
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// 版本化预共享身份密钥环（生命周期 / 轮换）。
///
/// 部署方可将多个版本的身份密钥一次性注入（KMS / 编排 secret），握手时按帧内 `psk_id`
/// 选取同版本 PSK 验证。切换版本只改密钥环，不动协议与代码：
///
/// - **轮换**：预发送一把新版本 PSK，两端更新部署密钥环即可切换到新 PSK；
/// - **吊销**：从密钥环移除旧版本 → 旧帧将因[`HandshakeError::AuthenticationFailed`]
///   被拒绝，泄露的旧 PSK 立即失去效力，无需重建整个会话信任体系。
pub struct IdentityKeyRing {
    keys: Vec<IdentityKey>,
}

impl std::fmt::Debug for IdentityKeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.keys.iter().map(|k| k.version()))
            .finish()
    }
}

impl Default for IdentityKeyRing {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityKeyRing {
    /// 构造空密钥环。
    pub fn new() -> Self {
        IdentityKeyRing { keys: Vec::new() }
    }

    /// 插入一把版本化 PSK。同版本已存在则覆盖（最新为准）。
    pub fn insert(&mut self, key: IdentityKey) {
        if let Some(existing) = self.keys.iter_mut().find(|k| k.version() == key.version()) {
            *existing = key;
            return;
        }
        self.keys.push(key);
    }

    /// 按版本号查找 PSK；不存在返回 `None`。
    pub fn lookup(&self, version: u8) -> Option<&IdentityKey> {
        self.keys.iter().find(|k| k.version() == version)
    }

    /// 已配置的版本号集合（顺序不保证）。
    pub fn versions(&self) -> impl Iterator<Item = u8> + '_ {
        self.keys.iter().map(|k| k.version())
    }

    /// 密钥环中 PSK 数量。
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// 从环境变量 `var` 启动时注入**一组版本化 PSK**，格式：
    /// `"<version>:<64-hex>,<version>:<64-hex>,..."`（如 `"1:ab..ff,2:00..11"`）。
    ///
    /// 生产推荐用本函数承载多版本轮换 —— 只改部署 env 即可切换/吊销 PSK，代码与协议不变。
    /// 返回 `None`：变量未设置、任一表项格式非法，或环为空。
    ///
    /// ```
    /// use c_universe::handshake::IdentityKeyRing;
    /// let ring = IdentityKeyRing::from_env("C_UNIVERSE_ABSENT_ZZZ");
    /// assert!(ring.is_none(), "示例环境无该变量 → 返回 None 符合预期");
    /// ```
    pub fn from_env(var: &str) -> Option<Self> {
        let raw = std::env::var(var).ok()?;
        let mut ring = IdentityKeyRing::new();
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (version_s, hex) = part.split_once(':')?;
            let version: u8 = version_s.trim().parse().ok()?;
            let bin = decode_hex(hex.trim())?;
            if bin.len() != 32 {
                return None;
            }
            let mut b = [0u8; 32];
            b.copy_from_slice(&bin);
            ring.insert(IdentityKey::new_v(version, &b));
        }
        if ring.is_empty() {
            return None;
        }
        Some(ring)
    }
}

/// 将十六进制字符串解码为字节（身份密钥环境变量注入用）。
///
/// 仅接受偶数长度的十六进制；非十六进制字符或长度非偶返回 `None`。
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// 单个十六进制字符 → 数值（0-15）；非法字符返回 `None`。
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
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
    /// `version(1) || capabilities(1) || psk_id(1) || public_key(32) || salt(32) || authenticator(32)`。
    ///
    /// 帧头携带协议版本、能力位图与 **PSK 版本号**，使对端能在派生密钥前进行能力协商，
    /// 按版本号在密钥环中定位同版本 PSK；尾部附加基于**逐握手派生认证密钥**的
    /// HMAC 认证器（Key-Confirmation），使对端能**认证我方身份**。缺失必需能力的对端将
    /// 连接失败，而非静默降级（见 [`REQUIRED_CAPABILITIES`]）。
    pub fn outbound_frame(
        &self,
        salt: &[u8; 32],
        identity: &IdentityKey,
        role: Role,
    ) -> [u8; HANDSHAKE_FRAME_LEN] {
        let mut f = [0u8; HANDSHAKE_FRAME_LEN];
        f[0] = PROTOCOL_VERSION;
        f[1] = CAP_DIRECTIONAL_KEYS;
        f[PSK_ID_OFFSET] = identity.version();
        f[PUBLIC_KEY_OFFSET..SALT_OFFSET].copy_from_slice(&self.public);
        f[SALT_OFFSET..AUTH_OFFSET].copy_from_slice(salt);
        // 密码学加固：PSK 不直接作 HMAC 密钥，先经 HKDF 派生逐握手独立的认证密钥。
        let auth_key = crypto::derive_auth_key(identity.bytes(), salt);
        let auth = crypto::authenticate_frame(
            &auth_key,
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

/// 对端握手帧的解析结果（含版本、能力位图、PSK 版本与身份认证器）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeFrame {
    /// 对端声明的协议版本。
    pub version: u8,
    /// 对端声明的能力位图。
    pub capabilities: u8,
    /// 对端握手所用 PSK 的版本号（供轮换时在密钥环中定位）。
    pub psk_id: u8,
    /// 对端 DH 公钥。
    pub peer_public: [u8; 32],
    /// 对端会话盐。
    pub peer_salt: [u8; 32],
    /// 对端附加的 32 字节身份认证器（已由 [`parse_handshake_frame`] 验证通过）。
    pub authenticator: [u8; 32],
}

/// 对一帧已找到对应 PSK 的握手帧执行 **版本 + 能力协商 + 身份认证**（核心实现）。
///
/// 该私有函数不关心 PSK 版本如何解析，统一接收解析出的 PSK 明文与 `psk_id`：
/// - 长度非 [`HANDSHAKE_FRAME_LEN`] → [`HandshakeError::BadPeerPayload`]；
/// - 版本 / 能力缺失 → [`HandshakeError::IncompatiblePeer`]，拒绝降级；
/// - **Key-Confirmation**：以「该 PSK 派生出的逐握手认证密钥」（AUTHK = HKDF(PSK, 对端盐)）
///   重算对端帧认证器并与帧内值做常数时间对比，失配 → [`HandshakeError::AuthenticationFailed`]。
fn verify_frame(
    frame: &[u8],
    secret: &[u8; 32],
    psk_id: u8,
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
        psk_id,
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
    // Key-Confirmation：PSK 经 HKDF 派生逐握手独立认证密钥，从不直接作 HMAC 密钥。
    let auth_key = crypto::derive_auth_key(secret, &hf.peer_salt);
    let expected = crypto::authenticate_frame(
        &auth_key,
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

/// 解析对端握手帧，并执行 **版本 + 能力协商 + 身份认证**（单 PSK / 版本 0 便捷入口）。
///
/// 1. 长度校验（须至少能读到 [`PSK_ID_OFFSET`]，恰好 [`HANDSHAKE_FRAME_LEN`] 校验由
///    [`verify_frame`] 完成）；
/// 2. 帧内 `psk_id` 必须等于本端持有 PSK 的版本号，否则
///    [`HandshakeError::AuthenticationFailed`]（本端未配置该版本 PSK）；
/// 3. 版本 / 能力协商 + Key-Confirmation 身份认证（见 [`verify_frame`]）。
///
/// `local_role` 用于推导对端角色（Initiator↔Responder 互逆），并把该角色字节纳入
/// 认证输入，绑定发送方的身份声明。
pub fn parse_handshake_frame(
    frame: &[u8],
    identity: &IdentityKey,
    local_role: Role,
) -> Result<HandshakeFrame, HandshakeError> {
    if frame.len() < HANDSHAKE_FRAME_LEN {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let psk_id = frame[PSK_ID_OFFSET];
    if psk_id != identity.version() {
        // 本端只持有这一把 PSK，而对端用了不同版本 → 版本失配，拒绝。
        return Err(HandshakeError::AuthenticationFailed);
    }
    verify_frame(frame, identity.bytes(), psk_id, local_role)
}

/// 解析对端握手帧并执行 **版本 + 能力协商 + 身份认证**，支持**多版本 PSK 密钥环**（轮换）。
///
/// 依据帧内 `psk_id` 在密钥环中定位同版本 PSK：
/// - 密钥环中无该版本（如旧 PSK 已被吊销）→ [`HandshakeError::AuthenticationFailed`]；
/// - 命中则用该 PSK 执行 Key-Confirmation（见 [`verify_frame`]）。
///
/// 部署方通过 [`IdentityKeyRing::from_env`] 注入一组版本化 PSK；切换/吊销只改密钥环即可。
pub fn parse_handshake_frame_from_ring(
    frame: &[u8],
    ring: &IdentityKeyRing,
    local_role: Role,
) -> Result<HandshakeFrame, HandshakeError> {
    if frame.len() < HANDSHAKE_FRAME_LEN {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let psk_id = frame[PSK_ID_OFFSET];
    let key = ring
        .lookup(psk_id)
        .ok_or(HandshakeError::AuthenticationFailed)?;
    verify_frame(frame, key.bytes(), psk_id, local_role)
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
///
/// # ⚠️ 传输通道必须使用 TLS
///
/// > **本 trait 的落地实现必须承载在 QUIC-TLS1.3（或等价 TLS1.3 流）之上，严禁裸跑明文
/// > TCP 或去序传输。**
///
/// 原因：
/// - **握手机密性**：X25519 DH 的公钥/共享秘密若在明文通道上交换，被动窃听者可截获
///   DH 密钥材料；尽管身份认证（Key-Confirmation）能挡住「无身份密钥的 MITM」，却拦不住
///   线上被动的数据面监听 —— 数据面虽为 AEAD 加密，但握手阶段隶属会话面包围，必须由
///   TLS 提供传输层机密性与完整性。
/// - **证书级身份（叠加）**：QUIC-TLS1.3 提供证书认证与握手完整性，作为 PSK
///   Key-Confirmation 之上的第二道身份防线；一旦脱离 TLS，这道防线即消失而退化成
///   仅依赖 PSK 的单点身份校验。
/// - **抗降级与乱序**：TLS1.3 防降级、提供可靠有序语义，避免握手帧被中间层重排/注入。
///
/// 自检：若你的 `Transport` 实现不是建立在 `quinn` / `rustls` 等 TLS 栈之上，
/// 应视为**不安全**，除非你同时把 PSK 身份认证作为唯一信任根且完全接受明文握手面的代价。
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

// ---------------------------------------------------------------------------
// PKI 握手（Ed25519 身份签名 + 根 CA 验证）
// ---------------------------------------------------------------------------

/// PKI 握手帧长度（字节）：
/// `version(1) || capabilities(1) || dh_public(32) || salt(32) || identity_pub(32) ||
/// identity_sig(64) || ca_sig(64)`。
pub const PKI_FRAME_LEN: usize = 226;
/// PKI 握手帧中 DH 临时公钥的起始偏移。
pub const PKI_DH_OFFSET: usize = 2;
/// PKI 握手帧中会话盐的起始偏移。
pub const PKI_SALT_OFFSET: usize = 34;
/// PKI 握手帧中身份公钥的起始偏移。
pub const PKI_IDENTITY_OFFSET: usize = 66;
/// PKI 握手帧中身份签名（对 DH 交换片段）的起始偏移。
pub const PKI_IDENT_SIG_OFFSET: usize = 98;
/// PKI 握手帧中 CA 叶子证书（对身份公钥的签名）的起始偏移。
pub const PKI_CA_SIG_OFFSET: usize = 162;

/// PKI 握手帧的解析结果（身份认证通过后）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkiHandshakeFrame {
    /// 对端声明的协议版本。
    pub version: u8,
    /// 对端声明的能力位图。
    pub capabilities: u8,
    /// 对端临时 DH 公钥。
    pub peer_public: [u8; 32],
    /// 对端会话盐。
    pub peer_salt: [u8; 32],
    /// 对端受 CA 授权的长期身份公钥。
    pub identity: [u8; 32],
}

/// 构建一张 PKI 握手帧：
/// `version(1) || caps(1) || dh_pub(32) || salt(32) || identity_pub(32) || identity_sig(64) || ca_sig(64)`。
///
/// 身份签名覆盖 `role ‖ version ‖ caps ‖ 本端 DH 公钥 ‖ 本端盐`（见
/// [`crate::pki::handshake_transcript`]），把角色 / 方向 / 本轮 DH 交换全部绑定进签名。
pub fn outbound_frame_pki(
    dh: &DhKeyPair,
    salt: &[u8; 32],
    role: Role,
    identity: &crate::pki::CertifiedIdentity,
) -> [u8; PKI_FRAME_LEN] {
    let mut f = [0u8; PKI_FRAME_LEN];
    let caps = CAP_DIRECTIONAL_KEYS | CAP_PKI;
    f[0] = PROTOCOL_VERSION;
    f[1] = caps;
    f[PKI_DH_OFFSET..PKI_SALT_OFFSET].copy_from_slice(&dh.public);
    f[PKI_SALT_OFFSET..PKI_IDENTITY_OFFSET].copy_from_slice(salt);
    let id_pub = identity.public_bytes();
    f[PKI_IDENTITY_OFFSET..PKI_IDENT_SIG_OFFSET].copy_from_slice(&id_pub);
    let transcript = crate::pki::handshake_transcript(role, PROTOCOL_VERSION, caps, &dh.public, salt);
    let sig = identity.sign(&transcript);
    f[PKI_IDENT_SIG_OFFSET..PKI_CA_SIG_OFFSET].copy_from_slice(&sig);
    let ca_sig = identity.ca_signature();
    f[PKI_CA_SIG_OFFSET..].copy_from_slice(&ca_sig);
    f
}

/// 解析并认证一张 PKI 握手帧，执行 **版本/能力协商 + 证书与签名双重身份认证**。
///
/// 1. 长度校验（必须恰好 [`PKI_FRAME_LEN`] 字节）；
/// 2. 版本 / 能力协商：对端必须是本协议版本且具 [`CAP_PKI`] 能力；否则
///    [`HandshakeError::IncompatiblePeer`]；
/// 3. **CA 授权**：`verify_cert(trusted_root, identity_pub, ca_sig)` —— 帧内身份公钥必须
///    由 pin 的根 CA 签发（未受信身份 → [`HandshakeError::AuthenticationFailed`]）；
/// 4. **身份签名**：`verify_transcript(identity_pub, transcript, identity_sig)` ——
///    证明身份私钥持有者确实参与了本轮 DH 交换（MITM / 篡改 → 认证失败）。
pub fn parse_handshake_frame_pki(
    frame: &[u8],
    local_role: Role,
    trusted_root: &[u8; 32],
) -> Result<PkiHandshakeFrame, HandshakeError> {
    if frame.len() != PKI_FRAME_LEN {
        return Err(HandshakeError::BadPeerPayload(frame.len()));
    }
    let peer_role = match local_role {
        Role::Initiator => Role::Responder,
        Role::Responder => Role::Initiator,
    };
    let version = frame[0];
    let capabilities = frame[1];
    if version != PROTOCOL_VERSION || (capabilities & CAP_PKI) == 0 {
        return Err(HandshakeError::IncompatiblePeer {
            peer_version: version,
            capabilities,
            required: CAP_DIRECTIONAL_KEYS | CAP_PKI,
        });
    }
    let peer_public: [u8; 32] = frame[PKI_DH_OFFSET..PKI_SALT_OFFSET].try_into().expect("exact 32");
    let peer_salt: [u8; 32] = frame[PKI_SALT_OFFSET..PKI_IDENTITY_OFFSET].try_into().expect("exact 32");
    let identity: [u8; 32] = frame[PKI_IDENTITY_OFFSET..PKI_IDENT_SIG_OFFSET].try_into().expect("exact 32");
    let ident_sig: [u8; crate::pki::SIG_LEN] =
        frame[PKI_IDENT_SIG_OFFSET..PKI_CA_SIG_OFFSET].try_into().expect("exact 64");
    let ca_sig: [u8; crate::pki::SIG_LEN] = frame[PKI_CA_SIG_OFFSET..].try_into().expect("exact 64");

    // ① CA 授权：身份公钥必须由可信根 CA 签发。
    if !crate::pki::verify_cert(trusted_root, &identity, &ca_sig) {
        return Err(HandshakeError::AuthenticationFailed);
    }
    // ② 身份签名：绑定「以对端角色身份参与了本轮 DH 交换」。
    let transcript = crate::pki::handshake_transcript(peer_role, version, capabilities, &peer_public, &peer_salt);
    if !crate::pki::verify_transcript(&identity, &transcript, &ident_sig) {
        return Err(HandshakeError::AuthenticationFailed);
    }
    Ok(PkiHandshakeFrame {
        version,
        capabilities,
        peer_public,
        peer_salt,
        identity,
    })
}

/// 在任意满足 [`Transport`] 的信道上的 PKI 握手（单端视角）。
///
/// 与 [`negotiate`] 等价，但身份认证依赖 **Ed25519 证书 + 根 CA**，而非 PSK：
/// - 发送端含身份公钥 + 身份签名 + CA 叶子证书；
/// - 接收端以 pin 的根 CA 验证证书，再以身份公钥验证身份签名；
/// - 双重校验失败一律 [`HandshakeError::AuthenticationFailed`]，不会与未知/伪造身份建连。
///
/// `identity` 为端侧长期签名身份（由 [`crate::pki::RootCa::issue`] 签发），
/// `trusted_root` 为部署时 pin 到本端的根 CA 公钥（[`crate::pki::RootCa::trust_root`]）。
pub fn negotiate_pki<T: Transport>(
    role: Role,
    identity: &crate::pki::CertifiedIdentity,
    trusted_root: &[u8; 32],
    transport: &mut T,
) -> Result<HandshakeSession, HandshakeError> {
    let kp = DhKeyPair::generate();
    let salt = random_bytes_32();
    let outbound = outbound_frame_pki(&kp, &salt, role, identity);
    transport
        .reliable_write(&outbound)
        .map_err(|_| HandshakeError::Transport)?;
    let mut frame = [0u8; PKI_FRAME_LEN];
    transport
        .reliable_read_exact(&mut frame)
        .map_err(|_| HandshakeError::Transport)?;
    let peer = parse_handshake_frame_pki(&frame, role, trusted_root)?;
    let combined = match role {
        Role::Initiator => crypto::combine_session_salts(&salt, &peer.peer_salt),
        Role::Responder => crypto::combine_session_salts(&peer.peer_salt, &salt),
    };
    let (root_initiator_to_responder, root_responder_to_initiator) =
        kp.derive_directional_roots_with_salt(&peer.peer_public, &combined)?;
    Ok(HandshakeSession {
        keypair: kp,
        role,
        root_initiator_to_responder,
        root_responder_to_initiator,
        session_salt: salt,
    })
}