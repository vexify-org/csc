//! 身份 PKI（公钥基础设施）——证书签发与握手签名（V1.4.1）。
//!
//! 在既有的 X25519 **临时** DH（负责密钥协商，保证前向保密）之上，引入**长期** Ed25519
//! 身份层：每个对端持有一把由自建根 CA 签发的**身份公钥**，握手时用身份**私钥**对 DH
//! 交换片段签名。验证方同时校验：
//!
//! 1. **签名有效性**：身份私钥确实与帧内身份公钥配套（证明持有签名秘密，且已对本轮
//!    DH 交换承诺）；
//! 2. **CA 授权**：帧内身份公钥由**可信根 CA**签发（证明该身份属于受信主体）。
//!
//! 两道校验任一不过即拒绝会话。攻击者（MITM）没有受 CA 授权的身份私钥，无法伪造一条
//! 能同时通过两道校验的握手 —— 即便能重放或发起自己的 DH，也会在身份层被拦截。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::handshake::Role;

/// 叶子证书主体的域分离标签（用于 CA 对身份公钥的签名输入，防止跨用途交叉签名）。
pub const PKI_SUBJECT: &[u8] = b"C-Universe identity leaf v1.4.1";

/// 一次 Ed25519 身份签名在握手帧中的字节数（`Signature::to_bytes` 固定 64）。
pub const SIG_LEN: usize = 64;
/// Ed25519 公钥字节数。
pub const PK_LEN: usize = 32;

/// 自建根 CA：持有签发证书用的 Ed25519 私钥（仅存在于签发端/离线环境）。
///
/// 部署时把 CA 的**公钥**（[`RootCa::trust_root`]）pin 到各对端，作为验证叶子身份的依据；
/// CA 私钥绝不放进握手、绝不上线。
pub struct RootCa {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl RootCa {
    /// 生成一把新的根 CA（签发端调用一次；此后长期保存私钥）。
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = VerifyingKey::from(&signing);
        RootCa { signing, verifying }
    }

    /// 从既存的 32 字节根 CA 私钥重建（用于签发端重启 / 备份恢复）。
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let verifying = VerifyingKey::from(&signing);
        RootCa { signing, verifying }
    }

    /// 根 CA 的公开验证密钥（`[u8; 32]`）。分发到各对端作为信任根。
    pub fn trust_root(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// 签发一把新的叶子身份：生成随机身份密钥对，并用根 CA 私钥对
    /// `PKI_SUBJECT ‖ 身份公钥` 签名，作为叶子证书。
    ///
    /// 产出的 [`CertifiedIdentity`] 部署到对端后即可在握手中使用；CA 私钥仍留在签发端。
    pub fn issue(&self) -> CertifiedIdentity {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = VerifyingKey::from(&signing);
        let ca_sig = self.sign_leaf(&verifying);
        CertifiedIdentity {
            signing,
            verifying,
            ca_signature: ca_sig,
        }
    }

    /// 对身份公钥签发证书：`CA_sig = Ed25519(CA_secret, PKI_SUBJECT ‖ verifying)`。
    fn sign_leaf(&self, verifying: &VerifyingKey) -> [u8; SIG_LEN] {
        let sig: Signature = self.signing.sign(&message_for_leaf(verifying));
        sig.to_bytes()
    }
}

/// 一份已由某根 CA 签发的身份（长期签名密钥对 + CA 证书）。
///
/// - `signing`：身份私钥，仅部署端持有，绝不发出；
/// - `verifying`：身份公钥（32 字节），随握手帧发出；
/// - `ca_signature`：根 CA 对本身份公钥的签名（叶子证书），随握手帧发出，
///   验证方用**可信根公钥**校验，证明该身份受信。
pub struct CertifiedIdentity {
    signing: SigningKey,
    verifying: VerifyingKey,
    ca_signature: [u8; SIG_LEN],
}

impl std::fmt::Debug for CertifiedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertifiedIdentity")
            .field("public", &self.verifying.to_bytes())
            .finish()
    }
}

impl CertifiedIdentity {
    /// 身份公钥（`[u8; 32]`，上线的公钥部分）。
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// 本身份所携带的 CA 叶子证书（对身份公钥的签名）。
    pub fn ca_signature(&self) -> [u8; SIG_LEN] {
        self.ca_signature
    }

    /// 对握手交换片段做身份签名：`sig = Ed25519(身份私钥, transcript)`。
    ///
    /// `transcript` 必须包含 `role ‖ version ‖ caps ‖ 本端 DH 公钥 ‖ 本端盐`，使签名
    /// 绑定「我以该角色身份，确认真实参与了本轮 DH 交换」，从而挡住 MITM 换钥。
    pub fn sign(&self, transcript: &[u8]) -> [u8; SIG_LEN] {
        let sig: Signature = self.signing.sign(transcript);
        sig.to_bytes()
    }
}

/// CA 对身份公钥的签名输入：`PKI_SUBJECT ‖ verifying`（固定长度，域分离）。
fn message_for_leaf(verifying: &VerifyingKey) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PKI_SUBJECT.len() + PK_LEN);
    msg.extend_from_slice(PKI_SUBJECT);
    msg.extend_from_slice(&verifying.to_bytes());
    msg
}

/// 校验一份 CA 叶子证书：`verify(root_pub, PKI_SUBJECT ‖ identity_pub, ca_sig)`。
///
/// 通过表示该 `identity_pub` 确已由可信根 CA 签发。`root_pub` 为部署时 pin 的根 CA 公钥。
pub fn verify_cert(
    root_pub: &[u8; 32],
    identity_pub: &[u8; 32],
    ca_sig: &[u8; SIG_LEN],
) -> bool {
    let Ok(root) = VerifyingKey::from_bytes(root_pub) else {
        return false;
    };
    let Ok(leaf) = VerifyingKey::from_bytes(identity_pub) else {
        return false;
    };
    let sig = Signature::from_bytes(ca_sig);
    root.verify(&message_for_leaf(&leaf), &sig).is_ok()
}

/// 校验握手身份签名：`verify(identity_pub, transcript, sig)`。
///
/// 通过表示帧内身份公钥的持有者确实签署了本轮交互，证明其掌握对应身份私钥。
pub fn verify_transcript(
    identity_pub: &[u8; 32],
    transcript: &[u8],
    sig: &[u8; SIG_LEN],
) -> bool {
    let Ok(identity) = VerifyingKey::from_bytes(identity_pub) else {
        return false;
    };
    let sig = Signature::from_bytes(sig);
    identity.verify(transcript, &sig).is_ok()
}

/// 构造身份签名的 transcript：`role.byte() ‖ version ‖ caps ‖ dh_public ‖ salt`。
///
/// 发送方以**自身角色**字节签名；验证方以**对端角色**（由本地角色反推）重建同样的
/// transcript 并校验，从而把「以何身份、向何方向、参与哪一轮 DH 交换」全部绑定进签名，
/// 封死角色混淆 / 换钥重放 / MITM 插值。
pub fn handshake_transcript(role: Role, version: u8, caps: u8, dh_public: &[u8; 32], salt: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(1 + 1 + 1 + 32 + 32);
    t.push(role.byte());
    t.push(version);
    t.push(caps);
    t.extend_from_slice(dh_public);
    t.extend_from_slice(salt);
    t
}