//! 对 C-Universe V1.2 的攻击尝试（自带证明的攻击测试）。
//!
//! 目标：用真实可复现的方式击破某条安全承诺，而非泛泛而谈。

use std::time::Duration;

use c_universe::crypto;
use c_universe::handshake::{random_bytes_32, HandshakeError};
use c_universe::packet::Packet;
use c_universe::{ReceiveError, Receiver, SessionConfig};

/// 攻击 ① —— 永久作废绕过。
///
/// 白皮书承诺：空缺 coord 超过 30s 窗口**永久作废、终身拒绝**。
/// 攻击序列：
/// 1. 先投递 coord 0（确立 last_contiguous=0）；
/// 2. 投递 coord 5，触发系统为缺失的 1..4 开启 30s 窗口；
/// 3. 等待窗口过期（>gap_window）；
/// 4. 投递一个中间的合法包 coord 7 —— 此时接收端内部的
///    `pending.retain(...)` 会把已过期的 1..4 从表中清掉；
/// 5. 再投递神秘的"迟到"合法包 coord 1。
///
/// 结论断言：coord 1 的窗口早已过期，必须被 `Voided` 拒绝。
/// 若当前实现接受的它，则该防御层可被绕过。
#[test]
fn attack_bypass_permanent_void_via_retain_prune() {
    let root = random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_millis(120),
        session_timeout: Duration::from_secs(50),
        max_gap_span: 65_536,
    };
    let mut rx = Receiver::new(&root, cfg);

    let ok = |c: u64| Packet::new(&root, c, b"payload");

    // 1) 让接收端看见 coord 0 与 coord 5（后者为 1..4 开启窗口）。
    assert_eq!(rx.recv(&ok(0)).unwrap(), b"payload");
    assert_eq!(rx.recv(&ok(5)).unwrap(), b"payload");

    // 2) 让窗口过期。
    std::thread::sleep(Duration::from_millis(200));

    // 3) 一个合法中间包 coord 7 触发内部 retain 清理，抹掉已过期的 1..4。
    assert_eq!(rx.recv(&ok(7)).unwrap(), b"payload");

    // 4) 迟到的 coord 1 此刻被判定为"从未见过"→ 被接受（漏洞）；应当被 Voided 拒绝。
    let outcome = rx.recv(&ok(1));
    assert_eq!(
        outcome.unwrap_err(),
        ReceiveError::Voided(1),
        "漏洞：空缺窗口已过期的 coord 被重新接受，永久作废承诺被绕过"
    );
}

/// 攻击 ② —— 密码学层对照：确认无法伪造/篡改/重放。
/// 这一组同时用来锚定"攻不破"的部分，避免审计失真。
#[test]
fn attack_confirm_blocked_surface() {
    use c_universe::{Sender, SessionConfig as Cfg};
    let root = random_bytes_32();
    let mut tx = Sender::new(&root);
    let mut rx = Receiver::new(&root, Cfg::default());

    // 拿到一份合法包。
    let legit = tx.send(b"secret");

    // 篡改密文 → AEAD 认证失败（coord 0 尚未核销，走认证分支）。
    {
        let mut raw = legit.as_bytes().to_vec();
        let mid = c_universe::packet::HEADER_LEN + raw.len() / 2;
        raw[mid] ^= 0x01;
        assert_eq!(
            rx.recv(&Packet::from_bytes(raw)).unwrap_err(),
            ReceiveError::AuthenticationFailed
        );
    }

    // 改 coord 头部（伪造新序号）→ AAD 绑定失败。
    {
        let mut raw = legit.as_bytes().to_vec();
        raw[1..9].copy_from_slice(&(9999u64).to_be_bytes());
        assert_eq!(
            rx.recv(&Packet::from_bytes(raw)).unwrap_err(),
            ReceiveError::AuthenticationFailed
        );
    }

    // 真包首次到达 → 正常核销接受。
    assert_eq!(rx.recv(&legit).unwrap(), b"secret");

    // 原样重放 → 已被核销，拒绝。
    assert_eq!(rx.recv(&legit).unwrap_err(), ReceiveError::Replay(0));
}

/// 攻击 ③ —— coord 巨跳 DoS（加固验证）。
///
/// 可信发送端若被攻陷/故障，可能把 coord 从低位直接跳到 2^48 级。
/// 加固后：单次调用不应枚举/分配千万级元素，远端空缺区被整体作废；
/// 同时不破坏正常小跨度的 30s 窗口。
#[test]
fn hardened_mega_coord_jump_is_bounded() {
    let root = random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_secs(30),
        session_timeout: Duration::from_secs(50),
        // 刻意调小，便于在测试里触发并观察巨跳分支。
        max_gap_span: 8,
    };
    let mut rx = Receiver::new(&root, cfg);

    // 建立基线：coord 0。
    assert!(rx.recv(&Packet::new(&root, 0, b"base")).is_ok());

    // 触发一次异常巨跳：0 → 1_000_000。不应卡死 / OOM。
    let t = std::time::Instant::now();
    assert!(rx.recv(&Packet::new(&root, 1_000_000, b"mega")).is_ok());
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "巨跳处理超时，疑似被逐 coord 枚举拖垮"
    );

    // 位于被整体作废区间的 coord（500_000，未核销）必须被永久拒绝。
    assert_eq!(
        rx.recv(&Packet::new(&root, 500_000, b"far")).unwrap_err(),
        ReceiveError::Voided(500_000)
    );
}

/// 攻击 ④ —— 握手层低阶点注入（破解密钥磋商）。
///
/// 若能向密钥磋商注入 X25519 **低阶点**公钥（如 `u=0` / `u=1`），
/// 双方会派生出**全零共享密钥** `S₀=[0;32]`，攻击者据此可预测整条会话，
/// 重放 / 伪造任意报文。这正是上次加固（RFC 7748 校验）要封死的口子。
///
/// 断言：`derive_directional_roots_with_salt` 遇到低阶点公钥必须返回
/// `WeakDhSecret`，而不是静默产出可预测密钥。
#[test]
fn attack_low_order_point_injection_rejected() {
    use c_universe::handshake::DhKeyPair;
    use c_universe::crypto;

    let kp = DhKeyPair::generate();
    let my_salt = random_bytes_32();
    let peer_salt = random_bytes_32();
    let combined = crypto::combine_session_salts(&my_salt, &peer_salt);

    // 已知低阶点：u=0（全零公钥），RFC 7748 标准 X25519 下共享密钥恒为零。
    let low_order_zero = [0u8; 32];
    let err = kp
        .derive_directional_roots_with_salt(&low_order_zero, &combined)
        .unwrap_err();
    assert_eq!(err, HandshakeError::WeakDhSecret);

    // 已知低阶点：u=1（序号=1 的低阶点），输出同样被解算为零。
    let mut low_order_one = [0u8; 32];
    low_order_one[0] = 1;
    let err = kp
        .derive_directional_roots_with_salt(&low_order_one, &combined)
        .unwrap_err();
    assert_eq!(err, HandshakeError::WeakDhSecret);

    // 对照：正常公钥必须仍能派生出两组非零方向根，证明校验只拦低阶点。
    let legit_pub = DhKeyPair::generate().public_key();
    let (ir, ri) = kp
        .derive_directional_roots_with_salt(&legit_pub, &combined)
        .unwrap();
    assert_ne!(ir, [0u8; 32]);
    assert_ne!(ri, [0u8; 32]);
    assert_ne!(ir, ri);
}

/// 攻击 ⑤ —— 握手 panic DoS（RST 崩溃服务）。
///
/// 若 `negotiate` 对底层通道读写用 `expect`，攻击者以 RST/断开流中止握手，
/// 进程会直接 panic。断言：传输失败时返回 `HandshakeError::Transport`（可处理），
/// 而非崩溃。
#[test]
fn attack_transport_failure_does_not_panic() {
    use c_universe::handshake::{negotiate, IdentityKey, Role};

    let key = IdentityKey::generate();

    struct FailingTransport;
    impl c_universe::handshake::Transport for FailingTransport {
        type Error = std::io::Error;
        fn reliable_write(&mut self, _: &[u8]) -> Result<(), Self::Error> {
            Err(std::io::Error::other("connection reset"))
        }
        fn reliable_read_exact(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
            Err(std::io::Error::other("connection reset"))
        }
    }

    let err = negotiate(Role::Initiator, &key, &mut FailingTransport).unwrap_err();
    assert_eq!(err, HandshakeError::Transport);

    // 读取方向同样不 panic。
    struct ReadFail;
    impl c_universe::handshake::Transport for ReadFail {
        type Error = std::io::Error;
        fn reliable_write(&mut self, _: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
        fn reliable_read_exact(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
            Err(std::io::Error::other("rst"))
        }
    }
    let err = negotiate(Role::Responder, &key, &mut ReadFail).unwrap_err();
    assert_eq!(err, HandshakeError::Transport);
}

/// 攻击 ⑥ —— 双向通信密钥重用 / 跨方向重放。
///
/// 复用单一根种子会让 A→B 与 B→A 在相同 coord 下密钥完全一致，可跨方向解密。
/// 断言：方向化根种子下，只有同方向的接收端能解出，反方向端一律认证失败。
#[test]
fn attack_directional_keys_are_isolated() {
    use c_universe::handshake::DhKeyPair;
    use c_universe::handshake::{IdentityKey, Role};
    use c_universe::crypto;
    use c_universe::{Sender, SessionConfig as Cfg};

    let key = IdentityKey::generate();
    let ka = DhKeyPair::generate();
    let kb = DhKeyPair::generate();
    let sa = random_bytes_32();
    let sb = random_bytes_32();
    let (pa, _) = c_universe::handshake::parse_peer_frame(
        &ka.outbound_frame(&sa, &key, Role::Initiator),
    )
    .unwrap();
    let (pb, _) = c_universe::handshake::parse_peer_frame(
        &kb.outbound_frame(&sb, &key, Role::Responder),
    )
    .unwrap();
    let combined = crypto::combine_session_salts(&sa, &sb);
    let (ir, ri) = ka.derive_directional_roots_with_salt(&pb, &combined).unwrap();
    let (ir_b, ri_b) = kb.derive_directional_roots_with_salt(&pa, &combined).unwrap();
    assert_eq!(ir, ir_b);
    assert_eq!(ri, ri_b);

    // Initiator 发送端用 ir（等价的 A→B 方向密钥）。
    let mut tx = Sender::new(&ir);
    let pkt = tx.send(b"hop");
    assert_eq!(pkt.header().unwrap().coord, 0);

    // 同方向（B 收到 A→B 用 ir）能解出。
    let mut rx_correct = Receiver::new(&ir, Cfg::default());
    assert_eq!(rx_correct.recv(&pkt).unwrap(), b"hop");

    // 反方向（B→A 用 ri）收到同 coord 包必须认证失败 —— 满足跨方向密钥隔离。
    let mut rx_wrong = Receiver::new(&ri, Cfg::default());
    assert_eq!(rx_wrong.recv(&pkt).unwrap_err(), ReceiveError::AuthenticationFailed);
}

/// 攻击 ⑦ —— 首包丢包 → 空缺窗口被清除（regression）。
///
/// 首包即 coord>0 时，连续边界仍为 -1；旧实现的 `evict_expired` 以
/// `(-1u64 as u64)==u64::MAX` 收紧，会清空全部空缺窗口且不落作废，
/// 导致低序号 coord 永不作废、可无限重放。
/// 断言：空缺窗口存活到期，迟到的低序号 coord 必须被 `Voided` 拒绝。
#[test]
fn attack_first_packet_gap_survives_eviction() {
    let root = random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_millis(120),
        session_timeout: Duration::from_secs(50),
        max_gap_span: 65_536,
    };
    let mut rx = Receiver::new(&root, cfg);
    let ok = |c: u64| Packet::new(&root, c, b"pay");

    // 首包就是 coord=5（0..4 被网络丢弃）—— 此时尚未建立连续前缀。
    assert_eq!(rx.recv(&ok(5)).unwrap(), b"pay");
    // 再来一个高 coord，强制内部走一次 evict_expired（含收紧逻辑）。
    assert_eq!(rx.recv(&ok(9)).unwrap(), b"pay");

    // 空缺窗口过期。
    std::thread::sleep(Duration::from_millis(200));

    // 迟到的低序号合法包 coord=1 必须被永久作废，不得复活。
    let outcome = rx.recv(&ok(1));
    assert_eq!(
        outcome.unwrap_err(),
        ReceiveError::Voided(1),
        "首包缺口被 evict 清空，低序号 coord 未作废、可重新接受（可重放）"
    );
}

/// 攻击 ⑧ —— 侧信道信息泄露。
///
/// 若在解密前按状态返回不同错误（Replay/Voided/SessionExpired），
/// 未持有密钥的攻击者也能通过错误类型探测 coord 使用情况/会话活性。
/// 断言：无法解密的报文一律得到统一的 `AuthenticationFailed`，
/// 无论该 coord 是否已被核销、是否已被作废。
#[test]
fn attack_side_channel_unified_on_unauthenticated() {
    let root = random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_millis(120),
        session_timeout: Duration::from_secs(50),
        max_gap_span: 65_536,
    };
    let mut rx = Receiver::new(&root, cfg);
    let ok = |c: u64, p: &[u8]| Packet::new(&root, c, p);

    // 合法打点：coord 0 已核销。
    assert_eq!(rx.recv(&ok(0, b"a")).unwrap(), b"a");
    // 让 coord 1..4 开窗后过期（作废）。
    assert_eq!(rx.recv(&ok(5, b"b")).unwrap(), b"b");
    std::thread::sleep(Duration::from_millis(200));
    // 过期扫描：收 coord 6 触发 evict，把 1..4 移入墓碑。
    assert!(rx.recv(&ok(6, b"c")).is_ok());

    // 攻击者用错误密钥伪造：
    //  - 针对已核销 coord 0、已作废 coord 1、未用过的 coord 999 的伪造包，
    //    都必须返回统一的 AuthenticationFailed，不得暴露 Replay/Voided。
    let forge = |c: u64| Packet::new(&[1u8; 32], c, b"evil");
    for c in [0u64, 1, 999] {
        let err = rx.recv(&forge(c)).unwrap_err();
        assert_eq!(
            err,
            ReceiveError::AuthenticationFailed,
            "伪造包不应暴露出 Replay/Voided 等状态，coord={c}"
        );
    }

    // 对照：真正的合法重放（能解密）才应被核销层拒绝 —— 状态只对合法对端可见。
    assert_eq!(
        rx.recv(&ok(0, b"a")).unwrap_err(),
        ReceiveError::Replay(0)
    );
}

/// 攻击 ⑨ —— 首包前会话无超时。
///
/// 旧实现 `last_received=None` 时跳过熔断检查，握手后长期空闲的会话密钥永远有效。
/// 断言：会话从建立即计时，首包永远不来的会话也会自动熔断。
#[test]
fn attack_session_times_out_before_first_packet() {
    use c_universe::Sender;
    let root = random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_secs(30),
        session_timeout: Duration::from_millis(120),
        max_gap_span: 65_536,
    };
    let mut rx = Receiver::new(&root, cfg);
    // 立即判定：尚未超时。
    assert!(rx.check_session_alive().is_ok());

    std::thread::sleep(Duration::from_millis(200)); // 首包从未到达，仅静默超时。

    // 即使发来一个完全合法的首包，也因会话已熔断而拒绝。
    let mut tx = Sender::new(&root);
    let err = rx.recv(&tx.send(b"first")).unwrap_err();
    assert_eq!(err, ReceiveError::SessionExpired);
}

/// 攻击 ⑩ —— H：`voided` 内存泄漏 / OOM。
///
/// 修复漏洞 A 时对 `evict_expired` 的收紧加上了 `last_contiguous >= 0` 门槛；
/// 若 coord 0 永久丢失（首包即便重试也到不了），连续边界永不建立，墓碑 `voided`
/// 随每次巨跳线性累积且从不回收 → 持续丢包即 OOM。
///
/// 断言：修复后内部记账规模（pending + voided）始终处于 `O(max_gap_span)`，
/// 即使做 2000 次巨跳也只稳定在常数级，而非随时间线性增长。
#[test]
fn attack_voided_bookkeeping_is_bounded() {
    use c_universe::packet::Packet;
    let root = random_bytes_32();
    // 刻意小 `max_gap_span`，放大「每跳开一窗、窗口落入前缀下方必须被回收」的区分度。
    let cfg = SessionConfig {
        gap_window: Duration::from_secs(30),
        session_timeout: Duration::from_secs(50),
        max_gap_span: 8,
    };
    let mut rx = Receiver::new(&root, cfg);

    // 序 0 永不投递 → last_contiguous 恒为 -1（漏洞 A 场景的核心触发条件）。
    let mut peak = 0usize;
    for i in 0..2000u64 {
        let coord = 10_000 + i * 1_000; // 每跳跨度都远超 cap，必然推进 voided_prefix
        rx.recv(&Packet::new(&root, coord, b"pay")).unwrap();
        peak = peak.max(rx.bookkeeping_len());
    }

    // 有界断言：正常流（丢包/错序）下记账量随 cap=8 有限，绝不线性扩张。
    assert!(
        peak <= 64,
        "bookkeeping grew to {peak}: voided memory leak / OOM (vuln H) regressed"
    );
}

/// 攻击 ⑪ —— G：认证放大 CPU DoS。
///
/// 抗侧信道要求「先 Auth 后查状态」，因此已核销 coord 的伪造包也需完整 AEAD 解密，
/// 攻击者可借此放大 CPU 开销。断言：连续认证洪水越过阈值后，接受端进入 O(1) 的
/// 全局 shed（`DoSLimit`），不再为后续伪造包付出逐包解密成本；且此判决仅依赖全局
/// 状态，不泄露 per-coord 状态（不破坏抗侧信道）。
#[test]
fn attack_authentication_flood_triggers_o1_shed() {
    use c_universe::packet::Packet;
    let mut rx = Receiver::with_defaults(&[3u8; 32]);

    // 用错钥连续投递伪造包（永远 AuthenticationFailed）。
    let mut shed_reached = false;
    for i in 0..4096u64 {
        let forged = Packet::new(&[9u8; 32], i, b"evil");
        match rx.recv(&forged) {
            Err(ReceiveError::DoSLimit) => {
                shed_reached = true;
                break;
            }
            Err(ReceiveError::AuthenticationFailed) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }
    assert!(
        shed_reached,
        "authentication flood did not trigger O(1) admission shed (vuln G)"
    );
}

/// 攻击 ⑫ —— I：握手无能力协商（可降级 / 混版本互操作失败）。
///
/// 旧握手帧仅 `pubkey || salt`，无版本/能力字段，旧客户端可静默降级回单一 root 模式。
/// 断言：V1.2 帧携带版本与能力位图；缺失方向化能力（或旧 64 字节格式）的对端
/// 必须被 `IncompatiblePeer` / `BadPeerPayload` 拒绝，绝不降级。
#[test]
fn attack_handshake_capability_negotiation_blocks_downgrade() {
    use c_universe::handshake::{
        parse_handshake_frame, parse_peer_frame, DhKeyPair, IdentityKey, Role, PROTOCOL_VERSION,
        REQUIRED_CAPABILITIES,
    };

    let key = IdentityKey::generate();
    let kp = DhKeyPair::generate();
    let salt = random_bytes_32();
    // 帧按「对端」视角构造（Responder），由本地以 Initiator 身份解析并认证。
    let frame = kp.outbound_frame(&salt, &key, Role::Responder);

    // 正常 V1.2 帧：版本与必需能力位齐全，身份认证通过。
    let hf = parse_handshake_frame(&frame, &key, Role::Initiator).unwrap();
    assert_eq!(hf.version, PROTOCOL_VERSION);
    assert_eq!(hf.capabilities & REQUIRED_CAPABILITIES, REQUIRED_CAPABILITIES);
    // 公钥 / 盐按新帧布局解析一致。
    let (pub_, salt_) = parse_peer_frame(&frame).unwrap();
    assert_eq!(pub_, kp.public_key());
    assert_eq!(salt_, salt);

    // 降级对端：方向化能力位缺失 → 拒绝（封死旧客户端降级到单一 root 模式）。
    let mut downgraded = frame;
    downgraded[1] = 0;
    let err = parse_handshake_frame(&downgraded, &key, Role::Initiator).unwrap_err();
    assert!(
        matches!(err, HandshakeError::IncompatiblePeer { .. }),
        "missing-directional-capability frame must be rejected, got {err:?}"
    );

    // 旧格式（64 字节，无版本/能力头）→ 帧长不符 → 拒绝，而非清白解析后降级。
    let legacy = &frame[..64];
    let err = parse_handshake_frame(legacy, &key, Role::Initiator).unwrap_err();
    assert_eq!(err, HandshakeError::BadPeerPayload(64));
}

/// 攻击 ⑬ —— 无身份认证 / MITM（未知身份密钥插值）。
///
/// 若无身份认证，攻击者 M 可插在被攻击双方 A、B 之间，各做一次独立 DH，
/// 冒充 B 与 A、冒充 A 与 B。现在 `negotiate` 强制 Key-Confirmation：
/// M 不持有双方共享的身份密钥，无法产出让 A（或 B）认证通过的握手帧。
///
/// 断言：
/// 1. 正确身份密钥 → 解析通过（正控制）；
/// 2. 未知（攻击者）身份密钥产出的握手帧 → `AuthenticationFailed`；
/// 3. 合法帧被单字节篡改 → `AuthenticationFailed`（认证器同时保完整）。
#[test]
fn attack_unknown_identity_key_is_rejected() {
    use c_universe::handshake::{parse_handshake_frame, AUTH_OFFSET, DhKeyPair, IdentityKey, Role};

    // A、B 双方共享同一身份密钥；攻击者 M 持另一把（随机生成、几乎必然不同）。
    let key_ab = IdentityKey::generate();
    let key_attacker = IdentityKey::generate();

    // 合法对端 B（Responder）用共享密钥产帧。
    let bob = DhKeyPair::generate();
    let bob_salt = random_bytes_32();
    let bob_frame = bob.outbound_frame(&bob_salt, &key_ab, Role::Responder);

    // A 以正确密钥解析 → 应通过（正控制）。
    let hf = parse_handshake_frame(&bob_frame, &key_ab, Role::Initiator).unwrap();
    assert_eq!(hf.peer_public, bob.public_key());

    // 攻击者 M 冒名 Responder 但持错误身份密钥 → 认证失配，会话被拒。
    let mallory = DhKeyPair::generate();
    let mallory_salt = random_bytes_32();
    let mallory_frame = mallory.outbound_frame(&mallory_salt, &key_attacker, Role::Responder);
    let err = parse_handshake_frame(&mallory_frame, &key_ab, Role::Initiator).unwrap_err();
    assert_eq!(
        err,
        HandshakeError::AuthenticationFailed,
        "unknown-identity handshake must be rejected, got {err:?}"
    );

    // 合法帧被篡改一个字节 → 认证器验证失败（完整性由认证器担保）。
    let mut tampered = bob_frame;
    tampered[AUTH_OFFSET] ^= 0x01;
    let err = parse_handshake_frame(&tampered, &key_ab, Role::Initiator).unwrap_err();
    assert_eq!(err, HandshakeError::AuthenticationFailed);
}

/// 攻击 ⑭ —— 前向保密（KeyUpdate）：泄露当前密钥不回溯历史。
///
/// 发送方 `key_update()` 用单向 HKDF 棘轮前滚并**弃用旧根**。若实现无法前向保密，
/// 持有「当前时代」根种子的攻击者应能解密早期时代的历史报文。
/// 断言：只持当前根 R2 的接收端无法解密用 R0 加密的历史包（HKDF 单向，旧根不可回溯）。
#[test]
fn attack_forward_secrecy_old_traffic_not_recoverable_from_current_key() {
    use c_universe::Sender;
    let root = random_bytes_32();
    let mut tx = Sender::new(&root);

    // 时代 0 的历史包（R0 加密）。
    let hist_pkt = tx.send(b"historical-secret");
    // 前滚到时代 1、再前滚到时代 2 → 旧根 R0/R1 被弃用。
    tx.key_update();
    let era1_pkt = tx.send(b"era-1");
    tx.key_update();
    // 攻击者此刻只窃取了"当前"根 R2 = ratchet(ratchet(R0,1),2)。
    let current_root = crypto::ratchet(&crypto::ratchet(&root, 1), 2);
    let mut attacker_rx = Receiver::new(&current_root, SessionConfig::default());

    // 只持 R2 无法解密 R0 加密的历史包（前向保密）。
    let err = attacker_rx.recv(&hist_pkt).unwrap_err();
    assert_eq!(
        err,
        ReceiveError::AuthenticationFailed,
        "前向保密失效：仅持当前根种子即可解密历史时代报文"
    );

    // 对照：合法接收端从 R0 出发，逐代 ratchet 前瞻，各时代包都能解密（密钥链未断）。
    let mut honest_rx = Receiver::with_defaults(&root);
    assert_eq!(honest_rx.recv(&hist_pkt).unwrap(), b"historical-secret");
    assert_eq!(honest_rx.recv(&era1_pkt).unwrap(), b"era-1");
    let era2_pkt = tx.send(b"era-2-fresh");
    assert_eq!(honest_rx.recv(&era2_pkt).unwrap(), b"era-2-fresh");
}

/// 攻击 ⑮ —— KeyUpdate 前滚一致性：接收端自动识别下一时代并解密，确认后旧钥被弃。
///
/// 跨 KeyUpdate 边界的乱序旧包（旧时代密钥加密、超前调用）必须被拒绝 ——
/// 一旦接收端确认 `key_update` 便弃用旧根（与 QUIC 一致）。
#[test]
fn attack_key_update_roundtrip_and_old_key_dropped() {
    use c_universe::Sender;
    let root = random_bytes_32();
    let mut tx = Sender::new(&root);
    let mut rx = Receiver::with_defaults(&root);

    // 时代 0 正常收发。
    let p0 = tx.send(b"pre-update");
    assert_eq!(rx.recv(&p0).unwrap(), b"pre-update");

    // 主动 key_update → 时代 1；新包被接收端自动识别（ratchet 前瞻命中）。
    tx.key_update();
    let p1 = tx.send(b"post-update");
    assert_eq!(rx.recv(&p1).unwrap(), b"post-update");
    assert_eq!(tx.era(), 1);

    // 跨边界旧时代包（era0 加密、此前未投递）→ 旧钥已弃用 → 认证失败。
    let late_old = Packet::new(&root, 999, b"late-old-era");
    assert_eq!(
        rx.recv(&late_old).unwrap_err(),
        ReceiveError::AuthenticationFailed,
        "前滚后旧时代密钥未被弃用（前向保密缺失）"
    );

    // 新时代的正常包继续可解（密钥链未断）。
    let p1b = tx.send(b"post-update-2");
    assert_eq!(rx.recv(&p1b).unwrap(), b"post-update-2");
}

/// 攻击 ⑯ —— 头部保护：coord 不以明文出现在线上字节。
///
/// 若 coord 明文暴露，观察者即可获得流量序号，做流量分析/相关性攻击。
/// 断言：线上字节中的 coord 区段 ≠ 真实 coord 大端；未持密钥的观察者读不到真实 coord，
/// 只有持有方向根种子（派 HP 密钥）才能恢复。
#[test]
fn attack_header_protection_hides_coord() {
    use c_universe::Sender;
    let root = random_bytes_32();
    let mut tx = Sender::new(&root);
    let pkt = tx.send(b"some-observable-payload-data"); // coord = 0

    let raw = pkt.as_bytes();
    // ① 版本仍明文（协议标识，供路由）。
    assert_eq!(raw[0], c_universe::PROTOCOL_VERSION);
    // ② coord=0 的真实大端是 [0;8]；线上字节不得与之相同（被 HP 掩码掩盖）。
    let real = 0u64.to_be_bytes();
    assert_ne!(&raw[1..9], &real, "coord 以明文出现在线上字节，违反头部保护");
    // ③ 从网络字节重构（观察者视角）读出的 coord ≠ 真实 coord。
    let net = Packet::from_bytes(raw.to_vec());
    assert_ne!(net.header().unwrap().coord, 0, "观察者可读出明文 coord");
    // ④ 持根种子者可恢复真实 coord（唯一合法读取方式）。
    assert_eq!(net.recover_coord(&root), Some(0));
    // ⑤ 持错误根种子的观察者无法恢复（乱猜必错）。
    assert_ne!(net.recover_coord(&[0xAA; 32]), Some(0));
}