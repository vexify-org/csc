//! # C-Universe 混沌流式传输协议 (V1.2) — Rust 参考实现
//!
//! 本 crate 实现《C-Universe 混沌传输协议技术白皮书 V1.2》规定的密码学与协议核心：
//!
//! - **无阻塞流式传输**：发送方严格单向自增 coord，丢包绝不重传、绝不阻塞。
//! - **标准化 KDF**：HKDF-SHA256 派生会话根种子 `S₀` 与每包密钥 `Kₙ`，域分离标签 + 盐。
//! - **AEAD 加密 + 完整性**：ChaCha20-Poly1305，AAD 绑定 coord，封死伪造/篡改。
//! - **三层防重放**：核销表 / 30s 空缺窗口 / 50s 会话静默熔断。
//! - **QUIC-DH 握手**：复用 QUIC-TLS1.3 承载密钥交换，强制证书/公钥校验（见
//!   [`handshake`] 模块及 `Transport` 契约）。

pub mod crypto;
pub mod handshake;
pub mod packet;
pub mod receiver;
pub mod sender;

pub use packet::Packet;
pub use receiver::{ReceiveError, Receiver, SessionConfig};
pub use sender::Sender;

/// 协议版本常量。
pub const PROTOCOL_VERSION: u8 = 1;

/// 根种子 / 包密钥长度（字节）。
pub const KEY_LEN: usize = 32;