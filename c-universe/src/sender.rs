//! 发送方：严格单向自增 coord，丢包绝不重传、绝不阻塞。
//!
//! V1.4 加入 **KeyUpdate（前向保密）**：发送方持有「当前时代」的方向根种子，
//! `key_update()` 用单向 HKDF 棘轮前向派生新根种子并弃用旧根 —— 一旦当前密钥泄露，
//! 历史报文仍不可解密（前向机密性）。coord 与 header protection 由 [`Packet`] 承担。

use crate::crypto;
use crate::packet::Packet;
use crate::KEY_LEN;

/// C-Universe 发送端状态机。
///
/// 唯一职责：持有"当前时代"的会话方向根种子，并持续自增 coord 对外发包。
/// 不记录接收方反馈、不维护发送队列、不检测丢包 —— 丢包是协议允许的正常状态。
///
/// 每次 `key_update()` 会**永久前滚**到新一代（旧时代密钥立即弃用），从而提供前向保密。
#[derive(Debug)]
pub struct Sender {
    seed: [u8; KEY_LEN],
    next_coord: u64,
    /// KeyUpdate 时代序号（0 起）。仅用于在单方向密钥链中定位当前根种子来源，
    /// 便于接收端按「前瞻一个时代」校验；加密实际以 `seed`（该时代根）进行。
    era: u64,
}

impl Sender {
    /// 以方向根种子（第 0 时代）构造发送端，coord 从 0 开始。
    pub fn new(root_seed: &[u8; KEY_LEN]) -> Self {
        Sender {
            seed: *root_seed,
            next_coord: 0,
            era: 0,
        }
    }

    /// 立即加密并编码一个被 `coord = next_coord` 标记的报文，然后将 coord 自增。
    ///
    /// 调用方拿到字节即可直接投递；**不等待、不重传、不阻塞**。
    pub fn send(&mut self, payload: &[u8]) -> Packet {
        let coord = self.next_coord;
        self.next_coord = self.next_coord.wrapping_add(1);
        Packet::new_in_era(&self.seed, self.era, coord, payload)
    }

    /// 主动执行一次 **KeyUpdate**：朝前推导一个新时代的根种子并**立即弃用当前根**，
    /// 换取前向保密（当前密钥泄露不影响历史报文）。
    ///
    /// # 前向保密语义
    ///
    /// 新根 `R' = HKDF(R)`，HKDF 单向，`R` 无法从 `R'` 反推；旧根被直接丢弃后，
    /// 即便新根被攻破，用 `R`（及其更早时代）加密的历史报文仍不可解密。
    /// 接收端（[`crate::Receiver`]）会自动识别下一个时代并在确认后同样前滚。
    ///
    /// # 乱序代价
    ///
    /// 因旧根被弃用，跨越更新边界的乱序旧包将无法解密（如同 QUIC 对已确认密钥更新的
    /// 旧包拒绝）。高频调用会放大这一代价，建议仅在必要节点（如安全事件/轮换策略）触发。
    pub fn key_update(&mut self) {
        self.era = self.era.wrapping_add(1);
        self.seed = crypto::ratchet(&self.seed, self.era);
    }

    /// 当前 KeyUpdate 时代序号。
    pub fn era(&self) -> u64 {
        self.era
    }

    /// 当前将要使用的 coord（下一个包的序号）。
    pub fn next_coord(&self) -> u64 {
        self.next_coord
    }

    /// 已派发/自增计数（等于已 send 的包数量）。
    pub fn sent_count(&self) -> u64 {
        self.next_coord
    }

    /// 便捷方法：用**当前时代**根种子派生某一个给定 coord 的密钥（供外部工具验证用途）。
    pub fn packet_key(&self, coord: u64) -> [u8; KEY_LEN] {
        crypto::derive_packet_key(&self.seed, coord)
    }
}