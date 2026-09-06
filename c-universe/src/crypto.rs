//! 密码学原语（V1.2 规范化改造）。
//!
//! 所有构造均采用标准化密码原语，严格区分盐 / 伪随机密钥 / 上下文信息：
//!
//! - 会话根种子：`S₀ = HKDF-SHA256(IKM=DH-secret, salt=会话盐, info="C-Universe-Session-Root-v1.2")`
//! - 单包密钥：`Kₙ = HKDF-SHA256(IKM=S₀, salt=coord-bytes, info="C-Universe-PacketKey-v1.2")`
//! - 加密 + 完整性：`ChaCha20-Poly1305`（AEAD），coord 编码进头部并作为 AAD 绑定，
//!   替换原白皮书旧版的独立 SHA256 二次校验。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::KEY_LEN;

/// 单包密钥派生的域分离标签。
pub const PACKET_KEY_INFO: &[u8] = b"C-Universe-PacketKey-v1.2";

/// 双向隔离：Initiator→Responder 方向的域分离标签。
///
/// 复用单一会话根种子 `S₀` + 同一 coord 会让双向密钥完全相同，
/// 攻击者可跨方向解密/重放。方向化根种子从共同 DH 派生，保证两方向密钥空间互斥。
pub const DIR_ROOT_INITIATOR_TO_RESPONDER: &[u8] =
    b"C-Universe-DirRoot-Initiator-To-Responder-v1.2";
/// 双向隔离：Responder→Initiator 方向的域分离标签。
pub const DIR_ROOT_RESPONDER_TO_INITIATOR: &[u8] =
    b"C-Universe-DirRoot-Responder-To-Initiator-v1.2";
/// 握手身份认证器（Key-Confirmation）的域分离标签。
///
/// 独立于 KDF 的 info，避免与根种子 / 包密钥派生共用标签。
pub const AUTH_INFO: &[u8] = b"C-Universe-Session-Auth-v1.3";
/// KeyUpdate 单向密钥棘轮的域分离标签。
///
/// 每次 `key_update` 用 `HKDF-SHA256(IKM=当前根种子, salt=新一代序号, info=UPDATE_INFO)`
/// 前向派生一把**新的**根种子；HKDF 的不可逆性保证旧根无法从新根回溯，
/// 一旦泄露当前密钥便无法解密历史报文（前向保密 / 前向机密性）。
pub const UPDATE_INFO: &[u8] = b"C-Universe-KeyUpdate-v1.4";
/// 头部保护（header protection）派生 HP 密钥的域分离标签。
///
/// HP 密钥**仅依赖方向根种子**、与 coord 无关，因此接收方在读到掩码后的 coord 之前
/// 就能算出掩码 —— 解决「掩码依赖密文、密文又依赖 coord」的先有鸡还是先有蛋问题
/// （与 QUIC TLS1.3 头部保护的思路一致）。
pub const HP_INFO: &[u8] = b"C-Universe-Header-Protection-v1.4";
/// 头部保护掩码的域分离前缀（HMAC 参与，hard-code 常量以隔离其他用途）。
const HP_MASK_PREFIX: &[u8] = b"C-Universe-HP-Mask-v1.4";
/// 头部保护取样的密文长度（字节）：掩码取自密文可见前缀样本，该前缀已被 AEAD 保护。
pub const HP_SAMPLE_LEN: usize = 16;
/// AEAD nonce 长度（ChaCha20-Poly1305 标准 12 字节）。
pub const NONCE_LEN: usize = 12;
/// nonce 前缀派生的域分离标签。
///
/// 前缀取自方向根种子（HKDF 派生），使 `coord = 0` 的首包 nonce 非全零，
/// 且不同会话（不同根种子）nonce 空间天然隔离，规避「全零 nonce + 固定后缀」的观感弱点。
pub const NONCE_PREFIX_INFO: &[u8] = b"C-Universe-Nonce-Prefix-v1.4.1";

/// 对握手帧内容做身份认证（Key-Confirmation）。
///
/// 返回 `HMAC-SHA256(key = identity, msg = AUTH_INFO ‖ version‖capabilities‖role ‖ public ‖ salt)`
/// 的 32 字节认证器。发送方将其附加在握手帧尾部，接收方用**同一把预共享身份密钥**
/// 重算并与帧内携带值做常数时间对比 —— 只有持有该身份密钥的对端才能产出有效的认证器，
/// 从而在 `negotiate` 内就把「无身份认证」的 MITM 关死：未知身份密钥的攻击者
/// 无法提交带有效认证器的握手帧。
pub fn authenticate_frame(
    identity: &[u8; KEY_LEN],
    version: u8,
    capabilities: u8,
    role: u8,
    public: &[u8; KEY_LEN],
    salt: &[u8; KEY_LEN],
) -> [u8; KEY_LEN] {
    // HMAC-SHA256 接受任意长度密钥；32 字节身份密钥必然合法。
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(identity)
        .expect("HMAC accepts any key length");
    mac.update(AUTH_INFO);
    mac.update(&[version, capabilities, role]);
    mac.update(public);
    mac.update(salt);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&tag[..KEY_LEN]);
    out
}

/// 常数时间比较两个 32 字节认证器，避免时序侧信道区分合法/伪造对端。
pub fn ct_eq(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..KEY_LEN {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// 由握手双方各自生成、交换后拼接而成的会话盐（64 字节：A || B）。
/// 每个会话唯一，参与根种子派生。
pub fn combine_session_salts(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(a);
    out[32..].copy_from_slice(b);
    out
}

/// 将 coord 编码为固定大端 8 字节（作为单包派生的盐）。
pub fn coord_to_be_bytes(coord: u64) -> [u8; 8] {
    coord.to_be_bytes()
}

/// 方向化会话根种子派生（双向隔离）：
/// 从共同 DH 秘密一次性派生 `(Initiator→Responder, Responder→Initiator)` 两个根。
///
/// 两个方向各自独立、互不相同，交由两端按角色分配到各自的 Sender/Receiver。
/// 由此即使两端复用同一 coord 序号空间，密钥也互不相同，杜绝跨方向解密/重放。
pub fn derive_directional_roots(
    dh_secret: &[u8; 32],
    session_salt: &[u8],
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let hk = Hkdf::<Sha256>::new(Some(session_salt), dh_secret);
    let mut ir = [0u8; KEY_LEN];
    let mut ri = [0u8; KEY_LEN];
    hk.expand(DIR_ROOT_INITIATOR_TO_RESPONDER, &mut ir)
        .expect("32 bytes always fits HKDF-SHA256");
    hk.expand(DIR_ROOT_RESPONDER_TO_INITIATOR, &mut ri)
        .expect("32 bytes always fits HKDF-SHA256");
    (ir, ri)
}

/// 单包密钥派生：
/// `Kₙ = HKDF-SHA256(IKM=S₀, salt=coord_be_bytes, info=PACKET_KEY_INFO, L=32)`。
pub fn derive_packet_key(root_seed: &[u8; KEY_LEN], coord: u64) -> [u8; KEY_LEN] {
    let salt = coord_to_be_bytes(coord);
    let hk = Hkdf::<Sha256>::new(Some(&salt), root_seed);
    let mut out = [0u8; KEY_LEN];
    hk.expand(PACKET_KEY_INFO, &mut out)
        .expect("32 bytes always fits HKDF-SHA256");
    out
}

/// 单向密钥棘轮：从当前时代根种子前向派生下一个时代 `next_era` 的根种子。
///
/// `R_{next} = HKDF-SHA256(IKM=R_cur, salt=next_era.be, info=UPDATE_INFO, L=32)`。
/// HKDF（KDF 摘要）单向，`R_cur` 无法从 `R_next` 反推，故泄露 `R_next` 不影响以
/// `R_0..R_cur` 加密的历史 —— 这是前向保密（KeyUpdate）的密码学基础。
pub fn ratchet(root_seed: &[u8; KEY_LEN], next_era: u64) -> [u8; KEY_LEN] {
    let salt = next_era.to_be_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt), root_seed);
    let mut out = [0u8; KEY_LEN];
    hk.expand(UPDATE_INFO, &mut out)
        .expect("32 bytes always fits HKDF-SHA256");
    out
}

/// 派生头部保护（HP）密钥。
///
/// HP 密钥仅依赖方向根种子、**不依赖 coord**：接收方在读到被掩码的 coord 之前即可
/// 计算掩码，从而解推出真实 coord。域分离标签独立于包密钥派生（`HP_INFO` ≠ `PACKET_KEY_INFO`），
/// 掩码泄露不反推包密钥。
pub fn derive_hp_key(root_seed: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, root_seed);
    let mut out = [0u8; KEY_LEN];
    hk.expand(HP_INFO, &mut out)
        .expect("32 bytes always fits HKDF-SHA256");
    out
}

/// 从密文前缀样本 + HP 密钥派生出 8 字节 coord 掩码。
///
/// `mask = HMAC-SHA256(key=HP密钥, msg=HP_MASK_PREFIX ‖ sample)[..8]`。样本取自
/// 已受 AEAD 保护的密文前缀，因此网络上的观察者无法仅凭密文推断掩码（采样受加密保护）。
/// 任何一位密文被篡改都会改变样本 → 掩码 → coord → 包密钥，连同 AEAD 完整性双重拦截。
pub fn header_mask(hp_key: &[u8; KEY_LEN], sample: &[u8]) -> [u8; 8] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hp_key)
        .expect("HMAC accepts any key length");
    mac.update(HP_MASK_PREFIX);
    mac.update(sample);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&tag[..8]);
    out
}

/// 用一个 8 字节掩码异或掩盖 coord 的大端编码（发送侧）。
pub fn mask_coord(coord: u64, mask: &[u8; 8]) -> [u8; 8] {
    let c = coord.to_be_bytes();
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = c[i] ^ mask[i];
    }
    out
}

/// 用一个 8 字节掩码解出被掩盖的 coord（接收侧）。
pub fn unmask_coord(masked: &[u8; 8], mask: &[u8; 8]) -> u64 {
    let mut c = [0u8; 8];
    for i in 0..8 {
        c[i] = masked[i] ^ mask[i];
    }
    u64::from_be_bytes(c)
}

/// 由方向根种子与 coord 确定性派生每包唯一 nonce（4 字节根派生前缀 + 8 字节大端 coord）。
///
/// - **非全零前缀**：前缀由根种子经 HKDF 派生，`coord = 0` 的首包 nonce 亦非全零；
///   不同会话（不同根种子）nonce 前缀互异，避免跨会话碰巧复用 identical 前缀的观感弱点。
/// - **唯一性**：同方向根种子里 coord 全局单向自增永不重复，故 nonce 对该密钥必然唯一，
///   无需在报文中额外传输。
///
/// 发送/接收均以同一 `era_root` 计算，天然一致。
pub fn derive_nonce(era_root: &[u8; KEY_LEN], coord: u64) -> [u8; NONCE_LEN] {
    // 4 字节前缀 = HKDF(era_root, info=NONCE_PREFIX_INFO)[..4]。
    let hk = Hkdf::<Sha256>::new(None, era_root);
    let mut pre = [0u8; 4];
    hk.expand(NONCE_PREFIX_INFO, &mut pre)
        .expect("4 bytes always fits HKDF-SHA256");
    let c = coord_to_be_bytes(coord);
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(&pre);
    nonce[NONCE_LEN - 8..].copy_from_slice(&c);
    nonce
}

/// 用 ChaCha20-Poly1305 加密并附加完整性标签。
/// `aad`（关联数据）参与校验，防头部/coord 篡改。
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .expect("encryption cannot fail")
}

/// 用 ChaCha20-Poly1305 解密 + 校验。
/// 任何密文/AAD 篡改都会导致 `Err`，返回的 `Vec` 为空即认证失败。
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| ())
}