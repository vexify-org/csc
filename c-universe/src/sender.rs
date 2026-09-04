//! 发送方：严格单向自增 coord，丢包绝不重传、绝不阻塞。

use crate::crypto;
use crate::packet::Packet;
use crate::KEY_LEN;

/// C-Universe 发送端状态机。
///
/// 唯一职责：持有会话根种子，并持续自增 coord 对外发包。
/// 不记录接收方反馈、不维护发送队列、不检测丢包 —— 丢包是协议允许的正常状态。
#[derive(Debug)]
pub struct Sender {
    seed: [u8; KEY_LEN],
    next_coord: u64,
}

impl Sender {
    /// 以会话根种子构造发送端，coord 从 0 开始。
    pub fn new(root_seed: &[u8; KEY_LEN]) -> Self {
        Sender {
            seed: *root_seed,
            next_coord: 0,
        }
    }

    /// 立即加密并编码一个被 `coord = next_coord` 标记的报文，然后将 coord 自增。
    ///
    /// 调用方拿到字节即可直接投递；**不等待、不重传、不阻塞**。
    pub fn send(&mut self, payload: &[u8]) -> Packet {
        let coord = self.next_coord;
        self.next_coord = self.next_coord.wrapping_add(1);
        Packet::new(&self.seed, coord, payload)
    }

    /// 当前将要使用的 coord（下一个包的序号）。
    pub fn next_coord(&self) -> u64 {
        self.next_coord
    }

    /// 已派发/自增计数（等于已 send 的包数量）。
    pub fn sent_count(&self) -> u64 {
        self.next_coord
    }

    /// 便捷方法：派生某一个给定 coord 的密钥（供外部工具验证用途）。
    pub fn packet_key(&self, coord: u64) -> [u8; KEY_LEN] {
        crypto::derive_packet_key(&self.seed, coord)
    }
}