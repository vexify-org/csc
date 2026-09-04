//! C-Universe 混沌报文编码。
//!
//! 报文布局（部分可配置，最大限度保持轻量）：
//!
//! ```text
//! +----------+----------+-----------+
//! | version  |  coord   | ciphertext |
//! |  1 byte  |  8 bytes |  variable  |
//! +----------+----------+-----------+
//! ```
//!
//! - `version`：协议版本常量（见 [`crate::PROTOCOL_VERSION`]）。
//! - `coord`：8 字节大端，发送方严格单向自增。
//! - `ciphertext`：ChaCha20-Poly1305 输出（含 16 字节认证标签），AAD 绑定头部，防篡改头部。

use crate::crypto;
use crate::KEY_LEN;
use crate::PROTOCOL_VERSION;

/// 头部固定长度 = version(1) + coord(8)。
pub const HEADER_LEN: usize = 9;

/// 解析后的报文头部。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// 协议版本。
    pub version: u8,
    /// 混沌坐标。
    pub coord: u64,
}

/// 一个已编码的 C-Universe 业务报文。
#[derive(Debug, Clone)]
pub struct Packet {
    raw: Vec<u8>,
}

impl PacketHeader {
    /// 将头部编码为 9 字节（version + coord 大端）。
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1..HEADER_LEN].copy_from_slice(&self.coord.to_be_bytes());
        out
    }

    /// 从 9 字节解码头部。
    pub fn from_bytes(bytes: &[u8; HEADER_LEN]) -> Self {
        let version = bytes[0];
        let mut cb = [0u8; 8];
        cb.copy_from_slice(&bytes[1..HEADER_LEN]);
        let coord = u64::from_be_bytes(cb);
        PacketHeader { version, coord }
    }
}

impl Packet {
    /// 加密并编码一个业务数据包。
    ///
    /// 使用根种子派生该 coord 的包密钥，头部作为 AAD 参与 AEAD 认证。
    pub fn new(root_seed: &[u8; KEY_LEN], coord: u64, payload: &[u8]) -> Self {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            coord,
        }
        .to_bytes();
        let key = crypto::derive_packet_key(root_seed, coord);
        let nonce = crypto::coord_to_nonce(coord);
        let ct = crypto::seal(&key, &nonce, &header, payload);

        let mut raw = Vec::with_capacity(HEADER_LEN + ct.len());
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&ct);
        Packet { raw }
    }

    /// 使用原始字节构造（供接收侧解析）。
    pub fn from_bytes(raw: Vec<u8>) -> Self {
        Packet { raw }
    }

    /// 解码头部；长度不足视为畸形包。
    pub fn header(&self) -> Result<PacketHeader, ()> {
        if self.raw.len() < HEADER_LEN {
            return Err(());
        }
        let mut h = [0u8; HEADER_LEN];
        h.copy_from_slice(&self.raw[..HEADER_LEN]);
        Ok(PacketHeader::from_bytes(&h))
    }

    /// 用根种子解密校验；任一环节失败返回 `Err`（伪造 / 篡改 / 版本不符）。
    pub fn decrypt(&self, root_seed: &[u8; KEY_LEN]) -> Result<Vec<u8>, ()> {
        if self.raw.len() < HEADER_LEN {
            return Err(());
        }
        let header = self.header()?;
        if header.version != PROTOCOL_VERSION {
            return Err(());
        }
        let key = crypto::derive_packet_key(root_seed, header.coord);
        let nonce = crypto::coord_to_nonce(header.coord);
        let header_bytes = &self.raw[..HEADER_LEN];
        crypto::open(&key, &nonce, header_bytes, &self.raw[HEADER_LEN..])
    }

    /// 原始字节视图。
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// 原始字节长度。
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// 是否为空包。
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}