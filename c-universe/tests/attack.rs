//! 对 C-Universe V1.2 的攻击尝试（自带证明的攻击测试）。
//!
//! 目标：用真实可复现的方式击破某条安全承诺，而非泛泛而谈。

use std::time::Duration;

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
/// 断言：`derive_session_root_with_salt` 遇到低阶点公钥必须返回
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
        .derive_session_root_with_salt(&low_order_zero, &combined)
        .unwrap_err();
    assert_eq!(err, HandshakeError::WeakDhSecret);

    // 已知低阶点：u=1（序号=1 的低阶点），输出同样被解算为零。
    let mut low_order_one = [0u8; 32];
    low_order_one[0] = 1;
    let err = kp
        .derive_session_root_with_salt(&low_order_one, &combined)
        .unwrap_err();
    assert_eq!(err, HandshakeError::WeakDhSecret);

    // 对照：正常公钥必须仍能派生出非零根种子，证明校验只拦低阶点。
    let legit_pub = DhKeyPair::generate().public_key();
    let root = kp
        .derive_session_root_with_salt(&legit_pub, &combined)
        .unwrap();
    assert_ne!(root, [0u8; 32]);
}

/// 攻击 ⑤ —— 握手 panic DoS（RST 崩溃服务）。
///
/// 若 `negotiate` 对底层通道读写用 `expect`，攻击者以 RST/断开流中止握手，
/// 进程会直接 panic。断言：传输失败时返回 `HandshakeError::Transport`（可处理），
/// 而非崩溃。
#[test]
fn attack_transport_failure_does_not_panic() {
    use c_universe::handshake::{negotiate, Role};

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

    let err = negotiate(Role::Initiator, &mut FailingTransport).unwrap_err();
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
    let err = negotiate(Role::Responder, &mut ReadFail).unwrap_err();
    assert_eq!(err, HandshakeError::Transport);
}

/// 攻击 ⑥ —— 双向通信密钥重用 / 跨方向重放。
///
/// 复用单一根种子会让 A→B 与 B→A 在相同 coord 下密钥完全一致，可跨方向解密。
/// 断言：方向化根种子下，只有同方向的接收端能解出，反方向端一律认证失败。
#[test]
fn attack_directional_keys_are_isolated() {
    use c_universe::handshake::DhKeyPair;
    use c_universe::crypto;
    use c_universe::{Sender, SessionConfig as Cfg};

    let ka = DhKeyPair::generate();
    let kb = DhKeyPair::generate();
    let sa = random_bytes_32();
    let sb = random_bytes_32();
    let (pa, _) = c_universe::handshake::parse_peer_frame(&ka.outbound_frame(&sa)).unwrap();
    let (pb, _) = c_universe::handshake::parse_peer_frame(&kb.outbound_frame(&sb)).unwrap();
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