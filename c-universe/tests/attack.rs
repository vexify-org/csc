//! 对 C-Universe V1.2 的攻击尝试（自带证明的攻击测试）。
//!
//! 目标：用真实可复现的方式击破某条安全承诺，而非泛泛而谈。

use std::time::Duration;

use c_universe::handshake::random_bytes_32;
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