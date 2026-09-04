//! 接收方：三层防重放闭环 + 乱序/迟到/重复包处理。
//!
//! 防御层级：
//! 1. **核销表**：已成功解密一次的 coord 终身拒绝（同序号重放）。
//! 2. **30 秒空缺窗口**：跳号时对缺失 coord 开启宽容窗口，超时永久作废。
//! 3. **50 秒会话熔断**：连续无业务包抵达 → 整个会话失效（封死停发重放漏洞）。

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::packet::Packet;
use crate::KEY_LEN;

/// 会话级可调参数。
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// 空缺坐标的合法迟到宽容窗口。
    pub gap_window: Duration,
    /// 全局会话静默熔断阈值。
    pub session_timeout: Duration,
    /// 单次向前跳号允许追踪的空缺数量上限（加固项）。
    ///
    /// 超过该跨度视为异常巨跳：远端空缺区整体置为永久作废（不逐 coord 枚举），
    /// 仅对靠近到达包的有限尾部开窗，从而把单包触发的 CPU/内存开销限制在常数级，
    /// 防止可信发送端 coord 异常跳变导致的拒绝服务。
    pub max_gap_span: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            gap_window: Duration::from_secs(30),
            session_timeout: Duration::from_secs(50),
            max_gap_span: 65_536,
        }
    }
}

/// 接收处理错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiveError {
    /// 报文太短无法解析。
    #[error("malformed packet")]
    Malformed,
    /// 该 coord 已被核销，重放丢弃。
    #[error("replay detected for coord {0}")]
    Replay(u64),
    /// 该 coord 空缺窗口已超时，永久作废。
    #[error("coord {0} voided after gap-window timeout")]
    Voided(u64),
    /// AEAD 解密/校验失败（伪造或篡改）。
    #[error("authentication failed (forged or tampered)")]
    AuthenticationFailed,
    /// 全局会话静默熔断已触发，需要重新握手。
    #[error("session expired (silent fuse tripped)")]
    SessionExpired,
}

/// C-Universe 接收端状态机。
pub struct Receiver {
    seed: [u8; KEY_LEN],
    cfg: SessionConfig,
    /// 核销表：一生只接收一次的 coord。
    used: HashSet<u64>,
    /// 空缺等待窗口：coord -> 截止时刻。
    pending: HashMap<u64, Instant>,
    /// 空缺窗口已超时、被永久作废的 coord（墓碑，防 retain 清理后复活）。
    voided: HashSet<u64>,
    /// 异常巨跳的整体作废前缀：所有 `c < voided_prefix` 且未核销的 coord 一律作废。
    /// 用于 O(1) 巩固数千万元素的大跨度区间，避免逐 coord 枚举。
    voided_prefix: u64,
    /// 已连续收到的最大 coord（无缺口的边界）。
    last_contiguous: i128,
    /// 最近一次成功解密业务包的时刻（50s 熔断计时基准）。
    last_received: Option<Instant>,
}

impl Receiver {
    /// 以会话根种子与配置构造接收端。
    pub fn new(root_seed: &[u8; KEY_LEN], cfg: SessionConfig) -> Self {
        Receiver {
            seed: *root_seed,
            cfg,
            used: HashSet::new(),
            pending: HashMap::new(),
            voided: HashSet::new(),
            voided_prefix: 0,
            last_contiguous: -1,
            last_received: None,
        }
    }

    /// 以默认配置（30s / 50s）构造。
    pub fn with_defaults(root_seed: &[u8; KEY_LEN]) -> Self {
        Self::new(root_seed, SessionConfig::default())
    }

    fn now() -> Instant {
        Instant::now()
    }

    /// 推进连续边界：只要下一个 coord 已核销则推进。
    fn advance_contiguous(&mut self) {
        while self.used.contains(&((self.last_contiguous + 1) as u64)) {
            self.last_contiguous += 1;
        }
    }

    /// 检测全局会话静默熔断。返回 `Err(SessionExpired)` 时，调用方应销毁本会话、
    /// 丢弃全部密钥并重新握手。
    pub fn check_session_alive(&self) -> Result<(), ReceiveError> {
        if let Some(lr) = self.last_received {
            if Self::now().duration_since(lr) > self.cfg.session_timeout {
                return Err(ReceiveError::SessionExpired);
            }
        }
        Ok(())
    }

    /// 处理一个收到的报文。任何防御层拦截返回对应错误，调用方可据此打点/丢弃。
    pub fn recv(&mut self, packet: &Packet) -> Result<Vec<u8>, ReceiveError> {
        let now = Self::now();

        // 第三层：50s 静默熔断。
        if let Some(lr) = self.last_received {
            if now.duration_since(lr) > self.cfg.session_timeout {
                return Err(ReceiveError::SessionExpired);
            }
        }

        // 解析头部。
        let header = packet.header().map_err(|_| ReceiveError::Malformed)?;
        let coord = header.coord;

        // 第一层：核销表，同 coord 终身拒绝重放。
        if self.used.contains(&coord) {
            return Err(ReceiveError::Replay(coord));
        }

        // 墓碑：曾开窗口已超时作废的 coord，或异常巨跳整体作废前缀内的 coord，
        //  永久拒绝（即使已从 pending 清理）。
        if self.voided.contains(&coord) || coord < self.voided_prefix {
            return Err(ReceiveError::Voided(coord));
        }

        // 第二层：空缺窗口已超时的 coord 永久作废。
        if let Some(deadline) = self.pending.get(&coord) {
            if *deadline <= now {
                self.voided.insert(coord);
                self.pending.remove(&coord);
                return Err(ReceiveError::Voided(coord));
            }
        }

        // 密码学：AEAD 解密 + 完整性校验。任何伪造/篡改在此被拦截。
        let plaintext = packet
            .decrypt(&self.seed)
            .map_err(|_| ReceiveError::AuthenticationFailed)?;

        // —— 至此包合法，进入核销与窗口维护 ——

        // 第一层落核销表。
        self.used.insert(coord);
        self.last_received = Some(now);

        // 维护空缺窗口与连续边界。
        if coord as i128 == self.last_contiguous + 1 {
            self.last_contiguous = coord as i128;
            self.advance_contiguous();
        } else if coord as i128 > self.last_contiguous + 1 {
            self.open_gap_window(coord, now);
        }

        // 清理已到的 pending 条目。
        self.pending.remove(&coord);
        // 过期窗口移入墓碑；清理低于连续边界的旧数据（其已被 `used` 覆盖）。
        self.evict_expired(now);

        Ok(plaintext)
    }

    /// 为跳号产生的空缺坐标开启 30s 宽容窗口。
    ///
    /// 若单次向前跨度超过 `max_gap_span`，视为异常巨跳：
    /// - 远端空缺区通过 `voided_prefix` **整体永久作废**（O(1)，不逐 coord 枚举）；
    /// - 仅对靠近到达包的有限尾部开窗。
    /// 由此保证单包触发的 CPU/内存开销为常数级，杜绝 coord 巨跳导致的拒绝服务。
    fn open_gap_window(&mut self, coord: u64, now: Instant) {
        let cont_plus1 = self.last_contiguous + 1; // i128
        let cap = self.cfg.max_gap_span.max(1) as i128;
        let gap_len = coord as i128 - cont_plus1;

        let start = if gap_len > cap { coord as i128 - cap } else { cont_plus1 };

        if gap_len > cap {
            // 异常巨跳：把 [cont_plus1, coord-cap) 整体作废。
            let far_end = start;
            self.voided_prefix = self.voided_prefix.max(far_end as u64);
        }

        // 仅对 [start, coord) 开窗（正常跳号即 [last_contiguous+1, coord)）。
        for missing in start..(coord as i128) {
            let m = missing as u64;
            if !self.used.contains(&m) {
                self.pending.entry(m).or_insert(now + self.cfg.gap_window);
            }
        }
    }

    /// 把已过期的空缺窗口移入墓碑（永久作废），并按连续边界收缩老旧数据。
    fn evict_expired(&mut self, now: Instant) {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(&c, _)| c)
            .collect();
        for c in expired {
            self.voided.insert(c);
            self.pending.remove(&c);
        }
        // coord <= last_contiguous 的必已被 `used` 收纳，墓碑/pending 从此刻可释放。
        let bound = self.last_contiguous;
        self.voided.retain(|&c| c > bound as u64);
        self.pending.retain(|&c, _| c > bound as u64);
    }
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("used_count", &self.used.len())
            .field("pending_gaps", &self.pending.len())
            .field("last_contiguous", &self.last_contiguous)
            .field("has_last_received", &self.last_received.is_some())
            .finish()
    }
}