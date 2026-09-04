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
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            gap_window: Duration::from_secs(30),
            session_timeout: Duration::from_secs(50),
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

        // 墓碑：曾开窗口、已超时作废的 coord，永久拒绝（即使已从 pending 清理）。
        if self.voided.contains(&coord) {
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
            // 跳号：为中间所有缺失 coord 开启 30s 宽容窗口。
            for missing in (self.last_contiguous + 1)..(coord as i128) {
                let m = missing as u64;
                if !self.used.contains(&m) {
                    self.pending.entry(m).or_insert(now + self.cfg.gap_window);
                }
            }
        }

        // 清理已到的 pending 条目。
        self.pending.remove(&coord);
        // 过期窗口移入墓碑；清理低于连续边界的旧数据（其已被 `used` 覆盖）。
        self.evict_expired(now);

        Ok(plaintext)
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