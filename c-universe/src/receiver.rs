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

/// 认证洪水熔断阈值：连续认证失败（伪造/错钥）达到该次数即触发全局 shed。
///
/// 这是「先认证后查状态」抗侧信道（漏洞侧信道修复）与「认证放大 CPU DoS」
/// （漏洞 G）之间的可用性平衡点：单一伪造坐标不会触发，只有全局持续洪水才触发，
/// 且触发不依赖任何逐 coord 内部状态，避免重新引入侧信道。
const AUTH_FAILURE_SHED_THRESHOLD: u64 = 1_024;
/// 触发认证洪水熔断后，拒绝新报文（不做 AEAD）的持续时间。
const AUTH_SHED_WINDOW: Duration = Duration::from_secs(5);

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
    /// 认证洪水熔断：短时间内伪造/错钥包过多，接收端进入按时间的全局 shed，
    /// 以此换取 O(1) 拒绝持续认证放大攻击（`AuthenticationFailed` 不复用为状态侧信道）。
    ///
    /// 这是「先认证后查状态」抗侧信道策略下、对**全局探测性洪水**的可用性兜底：
    /// 触发条件仅依赖全局认证失败计数（不随 coord/会话内部状态变化），因此
    /// 不会向攻击者泄露「哪些 coord 已核销/已作废」这类逐 coord 状态。
    #[error("authentication flood (admission shed active)")]
    DoSLimit,
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
    /// 会话建立（本接收端创建）时刻 —— 首包到达前的静默熔断计时基准。
    started: Instant,
    /// 最近一次成功解密业务包的时刻（50s 熔断计时基准）。
    last_received: Option<Instant>,
    /// 认证洪水熔断（漏洞 G）：累计连续认证失败次数。
    auth_failures: u64,
    /// 认证洪水熔断（漏洞 G）：shed 持续到该时刻为止，期间 O(1) 拒绝不做 AEAD。
    shed_until: Option<Instant>,
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
            started: Self::now(),
            last_received: None,
            auth_failures: 0,
            shed_until: None,
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
    ///
    /// 计时基准为「最近成功解密业务包」；若首包从未到达，则退化为会话建立时刻，
    /// 保证握手后长期空闲的会话密钥同样会在 `session_timeout` 后失效。
    pub fn check_session_alive(&self) -> Result<(), ReceiveError> {
        let anchor = self.last_received.unwrap_or(self.started);
        if Self::now().duration_since(anchor) > self.cfg.session_timeout {
            return Err(ReceiveError::SessionExpired);
        }
        Ok(())
    }

    /// 暴露内部记账规模（心电监控 / 内存有界性验证用）= `pending` 空缺窗口数 + `voided` 墓碑数。
    ///
    /// 漏洞 H 修复后，持续受控跳号下该值应稳定在 `O(max_gap_span)` 量级，
    /// 而非随丢包/跳号次数线性增长；攻击者可据此验证接收端不会 OOM。
    pub fn bookkeeping_len(&self) -> usize {
        self.pending.len() + self.voided.len()
    }

    /// 处理一个收到的报文。任何防御层拦截返回对应错误，调用方可据此打点/丢弃。
    ///
    /// # 顺序（抗侧信道）
    ///
    /// 1. 结构性解析 → `Malformed`；
    /// 2. **先做 AEAD 认证**：无法解密的报文一律返回 `AuthenticationFailed`；
    /// 3. 认证通过后才协商内部状态（会话过期 / 重放 / 作废）。
    ///
    /// 由此，未持有会话密钥的攻击者（伪造 / 随机报文）只能得到统一的
    /// `AuthenticationFailed`，无法通过错误类型差异区分 coord 是否已被使用、
    /// 是否被作废、会话是否已经过期 —— 这些状态只对能成功解密的合法对端可见。
    pub fn recv(&mut self, packet: &Packet) -> Result<Vec<u8>, ReceiveError> {
        let now = Self::now();

        // 认证洪水熔断（漏洞 G）：shed 持续期内 O(1) 整体拒绝，省去逐包 AEAD，
        //   杜绝攻击者以「已核销 coord 的伪造包仍需完整 ChaCha20-Poly1305 解密」
        //   进行认证放大 CPU DoS。判决仅依赖全局时间窗 + 全局失败计数，
        //   不随 coord/会话内部状态变化，因此不构成逐 coord 状态侧信道。
        if let Some(until) = self.shed_until {
            if now < until {
                return Err(ReceiveError::DoSLimit);
            }
            // shed 窗口已过：复位计数，允许合法流量自愈。
            self.shed_until = None;
            self.auth_failures = 0;
        }

        // 第一步：结构性解析（不依赖会话状态，不构成侧信道）。
        let header = packet.header().map_err(|_| ReceiveError::Malformed)?;
        let coord = header.coord;

        // 第二步：先密码学认证 —— 伪造/篡改/错钥在这里被统一拦截，
        //  绝不因网关前置检查把内部状态泄露给无密钥的攻击者。
        //  任一合法包即复位连续失败计数（自愈）：唯有连续 1024 次认证失败
        //  才会触发 `DoSLimit` 全局 shed。
        let plaintext = match packet.decrypt(&self.seed) {
            Ok(p) => {
                self.auth_failures = 0;
                p
            }
            Err(_) => {
                self.auth_failures += 1;
                if self.auth_failures >= AUTH_FAILURE_SHED_THRESHOLD {
                    self.shed_until = Some(now + AUTH_SHED_WINDOW);
                    self.auth_failures = 0;
                }
                return Err(ReceiveError::AuthenticationFailed);
            }
        };

        // 第三层：50s 静默熔断（首包前退化为会话建立时刻起算）。
        let anchor = self.last_received.unwrap_or(self.started);
        if now.duration_since(anchor) > self.cfg.session_timeout {
            return Err(ReceiveError::SessionExpired);
        }

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

        // —— 至此包通过认证且状态有效，进入核销与窗口维护 ——

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
        // —— 通用回收 ①：`voided_prefix` 之下的一切永久作废，且已由 recv 的
        //   `coord < voided_prefix` O(1) 前缀判拒覆盖 —— 逐 coord 的墓碑/pending
        //   记账自此冗余，可安全回收。回收不改变任何判拒语义，仅回收内存：
        //   杜绝「低 coord 永久丢失时 voided 集合永不清理」的无界线性增长（漏洞 H/OOM）。
        self.voided.retain(|&c| c >= self.voided_prefix);
        self.pending.retain(|&c, _| c >= self.voided_prefix);

        // —— 通用回收 ②：已建立连续前缀时，`<= last_contiguous` 的 coord 必已被
        //   `used` 收纳。仅在 last_contiguous >= 0 时收紧：首包若为 coord>0，
        //   last_contiguous 仍为 -1，此时 `(-1 as u64)` 是 u64::MAX，若直接
        //   retain `c > bound` 会把空缺窗口与墓碑全部清空且**不落作废**，导致
        //   低序号 coord 永不作废、可无限重放（漏洞 A）。故此时禁止收紧，
        //   让空缺窗口存活到期，转入 `voided` 后经由①的前缀判拒与回收释放。
        if self.last_contiguous >= 0 {
            let bound = self.last_contiguous as u64;
            self.voided.retain(|&c| c > bound);
            self.pending.retain(|&c, _| c > bound);
        }
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