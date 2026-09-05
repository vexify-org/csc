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
use sha2::Sha256;

use crate::KEY_LEN;

/// 会话根种子派生的域分离标签（把本协议密钥空间与其他用途隔离）。
pub const SESSION_ROOT_INFO: &[u8] = b"C-Universe-Session-Root-v1.2";
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
/// AEAD nonce 长度（ChaCha20-Poly1305 标准 12 字节）。
pub const NONCE_LEN: usize = 12;

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

/// 会话根种子派生：
/// `S₀ = HKDF-SHA256(IKM=raw-DH-secret, salt=session_salt, info=SESSION_ROOT_INFO, L=32)`。
pub fn derive_session_root(dh_secret: &[u8; 32], session_salt: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(session_salt), dh_secret);
    let mut out = [0u8; KEY_LEN];
    // HKDF 输出长度 32 恒不越界。
    hk.expand(SESSION_ROOT_INFO, &mut out)
        .expect("32 bytes always fits HKDF-SHA256");
    out
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

/// 由 coord 确定性派生每包唯一 nonce（4 字节零前缀 + 8 字节大端 coord）。
///
/// 因为同一 coord 只派生唯一密钥，且 coord 全局单向自增永不重复，
/// 因此以 coord 为基构造的 nonce 对该密钥必然唯一，无需在报文中额外传输。
pub fn coord_to_nonce(coord: u64) -> [u8; NONCE_LEN] {
    let c = coord_to_be_bytes(coord);
    let mut nonce = [0u8; NONCE_LEN];
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