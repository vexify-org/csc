//! C-Universe V1.2 协议核心集成测试。

use std::time::Duration;

use c_universe::crypto;
use c_universe::handshake::DhKeyPair;
use c_universe::packet::Packet;
use c_universe::{ReceiveError, Receiver, SessionConfig, Sender};

/// 握手两端能够得到一致的会话根种子。
#[test]
fn handshake_reaches_common_root() {
    // 双方各自生成 DH 密钥对与会话盐，并各自发出握手帧。
    let (ka, salt_a) = {
        let kp = DhKeyPair::generate();
        let s = c_universe::handshake::random_bytes_32();
        (kp, s)
    };
    let (kb, salt_b) = {
        let kp = DhKeyPair::generate();
        let s = c_universe::handshake::random_bytes_32();
        (kp, s)
    };

    let frame_a = ka.outbound_frame(&salt_a);
    let frame_b = kb.outbound_frame(&salt_b);
    // 从帧中解析对端公钥（等价于网络上交换）。
    let (pub_a, _) = c_universe::handshake::parse_peer_frame(&frame_a).unwrap();
    let (pub_b, _) = c_universe::handshake::parse_peer_frame(&frame_b).unwrap();

    // 双方以固定顺序拼接各自盐（A||B），保证派生一致。
    let combined_a = crypto::combine_session_salts(&salt_a, &salt_b);
    let combined_b = crypto::combine_session_salts(&salt_a, &salt_b);

    let root_a = ka.derive_session_root_with_salt(&pub_b, &combined_a).unwrap();
    let root_b = kb.derive_session_root_with_salt(&pub_a, &combined_b).unwrap();

    assert_eq!(root_a, root_b);
    assert_ne!(root_a, [0u8; 32]);
}

/// 上行收发一一对应（正常流）。
#[test]
fn send_recv_roundtrip_in_order() {
    let seed = c_universe::handshake::random_bytes_32();
    let mut tx = Sender::new(&seed);
    let mut rx = Receiver::with_defaults(&seed);

    for i in 0..100u64 {
        let payload = format!("msg-{i}");
        let pkt = tx.send(payload.as_bytes());
        let got = rx.recv(&pkt).unwrap();
        assert_eq!(got, payload.as_bytes());
    }
}

/// 第一次解密成功的 coord，再次收到被核销表拦截（同序号重放）。
#[test]
fn replay_is_rejected_once_processed() {
    let seed = c_universe::handshake::random_bytes_32();
    let mut tx = Sender::new(&seed);
    let mut rx = Receiver::with_defaults(&seed);

    let pkt = tx.send(b"hello");
    assert!(rx.recv(&pkt).is_ok());
    let err = rx.recv(&pkt).unwrap_err();
    assert_eq!(err, ReceiveError::Replay(0));
}

/// 篡改密文任意一个字节都会触发 AEAD 认证失败。
#[test]
fn tampered_packet_is_rejected() {
    let seed = c_universe::handshake::random_bytes_32();
    let mut tx = Sender::new(&seed);
    let mut rx = Receiver::with_defaults(&seed);

    let pkt = tx.send(b"secret");
    // 翻转密文区的一个字节。
    let n = pkt.len();
    let idx = c_universe::packet::HEADER_LEN + (n - c_universe::packet::HEADER_LEN) / 2;
    let mut raw = pkt.as_bytes().to_vec();
    raw[idx] ^= 0x40;
    let forged = Packet::from_bytes(raw);

    let err = rx.recv(&forged).unwrap_err();
    assert_eq!(err, ReceiveError::AuthenticationFailed);
}

/// 伪造 coord 也会因为密钥不匹配而认证失败（coord 绑定进 AAD）。
#[test]
fn forged_header_coord_is_rejected() {
    let seed = c_universe::handshake::random_bytes_32();
    let mut tx = Sender::new(&seed);
    let mut rx = Receiver::with_defaults(&seed);

    let pkt = tx.send(b"x");
    let mut raw = pkt.as_bytes().to_vec();
    // coord=0 -> 改为 coord=99，改的是 aad 字节，但密文未重算，必然失败。
    raw[1..9].copy_from_slice(&99u64.to_be_bytes());
    let forged = Packet::from_bytes(raw);
    let err = rx.recv(&forged).unwrap_err();
    assert_eq!(err, ReceiveError::AuthenticationFailed);
}

/// 乱序 + 迟到（窗口内）包被正常接收。
#[test]
fn out_of_order_and_late_within_window_accepted() {
    let seed = c_universe::handshake::random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_secs(5),
        session_timeout: Duration::from_secs(50),
        max_gap_span: 65_536,
    };
    let mut tx = Sender::new(&seed);
    let mut rx = Receiver::new(&seed, cfg);

    let p0 = tx.send(b"zero");
    let p1 = tx.send(b"one");
    let p2 = tx.send(b"two");

    // 顺序打乱：0、2、1；1 是“迟到”但仍在窗口内。
    assert_eq!(rx.recv(&p0).unwrap(), b"zero");
    assert_eq!(rx.recv(&p2).unwrap(), b"two"); // 为缺失的 coord 1 开启窗口
    assert_eq!(rx.recv(&p1).unwrap(), b"one"); // 迟到但窗口未过，接受
}

/// 空缺窗口超时后，该 coord 永久作废（30s 语义的缩短验证）。
#[test]
fn gap_window_timeout_voids_coord() {
    let seed = c_universe::handshake::random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_millis(120),
        session_timeout: Duration::from_secs(50),
        max_gap_span: 65_536,
    };
    let mut tx = Sender::new(&seed);
    let mut rx = Receiver::new(&seed, cfg);

    let p0 = tx.send(b"zero");
    let p1 = tx.send(b"one");
    let p2 = tx.send(b"two");

    rx.recv(&p0).unwrap();
    rx.recv(&p2).unwrap(); // 开启 coord 1 的窗口

    std::thread::sleep(Duration::from_millis(200)); // 窗口过期
    let err = rx.recv(&p1).unwrap_err();
    assert_eq!(err, ReceiveError::Voided(1));
}

/// 全局会话静默熔断：超过阈值不再接收任何包。
#[test]
fn session_silent_timeout_expires() {
    let seed = c_universe::handshake::random_bytes_32();
    let cfg = SessionConfig {
        gap_window: Duration::from_secs(30),
        session_timeout: Duration::from_millis(120),
        max_gap_span: 65_536,
    };
    let mut tx = Sender::new(&seed);
    let mut rx = Receiver::new(&seed, cfg);

    rx.recv(&tx.send(b"first")).unwrap();

    std::thread::sleep(Duration::from_millis(200)); // 静默超过阈值
    let err = rx.recv(&tx.send(b"second")).unwrap_err();
    assert_eq!(err, ReceiveError::SessionExpired);
    // 会话已熔断，旧的合法新包也不被接受。
    assert!(rx.check_session_alive().is_err());
}

/// 长度不足的畸形包被拒绝。
#[test]
fn malformed_packet_rejected() {
    let seed = c_universe::handshake::random_bytes_32();
    let mut rx = Receiver::with_defaults(&seed);
    let short = Packet::from_bytes(vec![0u8; 3]);
    assert_eq!(rx.recv(&short).unwrap_err(), ReceiveError::Malformed);
}

/// 不同密钥（不同会话）之间互不通用。
#[test]
fn mismatched_session_root_cannot_decrypt() {
    let seed_a = c_universe::handshake::random_bytes_32();
    let seed_b = c_universe::handshake::random_bytes_32();
    let mut tx = Sender::new(&seed_a);
    let mut rx = Receiver::with_defaults(&seed_b);

    let pkt = tx.send(b"hello");
    assert_eq!(rx.recv(&pkt).unwrap_err(), ReceiveError::AuthenticationFailed);
}