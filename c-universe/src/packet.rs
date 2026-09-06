//! C-Universe 混沌报文编码。
//!
//! 报文布局（部分可配置，最大限度保持轻量）：
//!
//! ```text
//! +----------+---------------------+-----------+
//! | version  | masked_coord (8-byte)| ciphertext |
//! |  1 byte  |  8 bytes            |  variable  |
//! +----------+---------------------+-----------+
//! ```
//!
//! - `version`：协议版本常量（明文，接收端据此路由）。
//! - `masked_coord`：**头部保护**后的 coord。发送方以「受 AEAD 保护的密文前缀样本」+
//!   HP 密钥（仅依赖方向根种子，与 coord 无关）算出 8 字节掩码，与真实 coord 大端异或。
//!   网络观察者**读不到明文 coord**（流量分析防护），需持有根种子派生的 HP 密钥才能解出。
//!   真实 coord（未掩码）以 AAD 绑定进 AEAD —— AEAD 用**真头**作关联数据，掩码是可逆的
//!   后处理变换，既不冲突又保证头部不可篡改（QUIC TLS1.3 头部保护同思路）。
//! - `ciphertext`：ChaCha20-Poly1305 输出（含 16 字节认证标签），AAD = 真头（version‖coord）。

use crate::crypto;
use crate::crypto::HP_SAMPLE_LEN;
use crate::KEY_LEN;
use crate::PROTOCOL_VERSION;

/// 头部长度 = version(1) + masked_coord(8)。
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
    /// 本地构造时已知的真实 coord（`new*` 时记录）；网络收包（`from_bytes`）为 `None`。
    ///
    /// 头部保护让**线上**字节不再携带明文 coord，因此网络中继/未解密侧无法读出 coord；
    /// 只有构造侧（发送端）或已完成解密的接收侧能通过 `header()`/解密获得真实 coord。
    coord: Option<u64>,
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
    /// 以指定时代的根种子加密并编码一个业务数据包（带头部保护）。
    ///
    /// `era` 是 KeyUpdate 时代序号，仅用于选择根种子的来源（发送端维护）；加密仍以
    /// 该时代根种子 + coord 派生包密钥。头部保护用该时代根种子派生的 HP 密钥掩盖 coord。
    pub fn new_in_era(root_seed: &[u8; KEY_LEN], _era: u64, coord: u64, payload: &[u8]) -> Self {
        // 真头（version || coord）作为 AEAD 的 AAD —— AEAD 先于掩码，故无循环依赖。
        let true_header = PacketHeader {
            version: PROTOCOL_VERSION,
            coord,
        }
        .to_bytes();
        let key = crypto::derive_packet_key(root_seed, coord);
        let nonce = crypto::derive_nonce(root_seed, coord);
        let ct = crypto::seal(&key, &nonce, &true_header, payload);

        // 头部保护：用受 AEAD 保护的密文前缀样本派生 8 字节掩码，掩盖 coord。
        let sample = &ct[..HP_SAMPLE_LEN];
        let mask = crypto::header_mask(&crypto::derive_hp_key(root_seed), sample);
        let masked_coord = crypto::mask_coord(coord, &mask);

        let mut raw = Vec::with_capacity(HEADER_LEN + ct.len());
        raw.push(PROTOCOL_VERSION);
        raw.extend_from_slice(&masked_coord);
        raw.extend_from_slice(&ct);
        Packet { raw, coord: Some(coord) }
    }

    /// 以方向根种子加密并编码一个**第 0 时代**的业务数据包。
    ///
    /// 等价于 [`new_in_era`](Self::new_in_era) 的 era=0 便捷形式；单时代部署（未触发
    /// KeyUpdate）即此路径。与 QUIC 实现一致，密钥时代默认从 0 开始。
    pub fn new(root_seed: &[u8; KEY_LEN], coord: u64, payload: &[u8]) -> Self {
        Self::new_in_era(root_seed, 0, coord, payload)
    }

    /// 使用原始字节构造（供接收侧解析）。真实 coord 未知（`None`），仅头部保护后掩码可读。
    pub fn from_bytes(raw: Vec<u8>) -> Self {
        Packet { raw, coord: None }
    }

    /// 解码头部。
    ///
    /// - 对本地构造的包：返回**真实 coord**（构造侧自然知道）。
    /// - 对网络收包（`from_bytes`）：在线 coord 已被掩盖，故返回的是**掩码后值**；
    ///   真实 coord 需通过 [`recover_coord`](Self::recover_coord) / 解密获得。
    ///
    /// 长度不足视为畸形包。
    pub fn header(&self) -> Result<PacketHeader, ()> {
        if self.raw.len() < HEADER_LEN {
            return Err(());
        }
        let version = self.raw[0];
        let coord = if let Some(c) = self.coord {
            c
        } else {
            // 网络包：未解密前，coord 字段即线上掩码字节（非真实值）。
            let mut cb = [0u8; 8];
            cb.copy_from_slice(&self.raw[1..HEADER_LEN]);
            u64::from_be_bytes(cb)
        };
        Ok(PacketHeader { version, coord })
    }

    /// 该校验时代根种子下的真实 coord（需持有该方向根种子，用于头部保护解掩）。
    ///
    /// 返回 `None`：报文过短（无足够密文样本）、版本不符或无法从网络字节恢复 coord。
    /// 供审计与演示使用；接收端解密内部已含此逻辑。
    pub fn recover_coord(&self, root_seed: &[u8; KEY_LEN]) -> Option<u64> {
        if self.raw.len() < HEADER_LEN + HP_SAMPLE_LEN {
            return None;
        }
        let ct = &self.raw[HEADER_LEN..];
        let mask = crypto::header_mask(&crypto::derive_hp_key(root_seed), &ct[..HP_SAMPLE_LEN]);
        let mut masked = [0u8; 8];
        masked.copy_from_slice(&self.raw[1..HEADER_LEN]);
        Some(crypto::unmask_coord(&masked, &mask))
    }

    /// 用指定时代根种子解密并校验（含头部保护解掩 + AEAD）。
    ///
    /// 成功后返回 `(真实coord, 明文)`。任一环节失败（密文/头部篡改、错钥/错时代）返回
    /// `None`。接收端对 **当前时代** 与 **前瞻一个时代** 各调用一次以支持 KeyUpdate。
    pub fn attempt_decrypt(&self, era_root: &[u8; KEY_LEN], _era: u64) -> Option<(u64, Vec<u8>)> {
        if self.raw.len() < HEADER_LEN + HP_SAMPLE_LEN {
            return None;
        }
        if self.raw[0] != PROTOCOL_VERSION {
            return None;
        }
        // 1) 头部保护：以密文样本解出真实 coord。
        let ct = &self.raw[HEADER_LEN..];
        let mask = crypto::header_mask(&crypto::derive_hp_key(era_root), &ct[..HP_SAMPLE_LEN]);
        let mut masked = [0u8; 8];
        masked.copy_from_slice(&self.raw[1..HEADER_LEN]);
        let coord = crypto::unmask_coord(&masked, &mask);

        // 2) 派包密钥，以真头作 AAD 解密校验。
        let key = crypto::derive_packet_key(era_root, coord);
        let nonce = crypto::derive_nonce(era_root, coord);
        let mut true_header = [0u8; HEADER_LEN];
        true_header[0] = PROTOCOL_VERSION;
        true_header[1..HEADER_LEN].copy_from_slice(&coord.to_be_bytes());
        match crypto::open(&key, &nonce, &true_header, ct) {
            Ok(plain) => Some((coord, plain)),
            Err(_) => None,
        }
    }

    /// 用根种子（按第 0 时代）解密校验。返回明文。
    ///
    /// 等价于 [`attempt_decrypt`](Self::attempt_decrypt) 的 era=0 便捷形式；
    /// 多时代场景请使用能枚举时代的接收端状态机（[`crate::Receiver`]）。
    pub fn decrypt(&self, root_seed: &[u8; KEY_LEN]) -> Result<Vec<u8>, ()> {
        self.attempt_decrypt(root_seed, 0)
            .map(|(_, plain)| plain)
            .ok_or(())
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