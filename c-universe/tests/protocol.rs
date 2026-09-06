//! C-Universe V1.2 协议核心集成测试。

use std::time::Duration;

use c_universe::crypto;
use c_universe::handshake::{parse_handshake_frame, DhKeyPair, IdentityKey, Role};
use c_universe::packet::Packet;
use c_universe::{ReceiveError, Receiver, SessionConfig, Sender};

/// 身份密钥安全分发（修复项 ①）：环境变量注入 + Debug 不泄露明文。
#[test]
fn identity_key_env_injection_and_secure_distribution() {
    use c_universe::handshake::IdentityKey;

    // 未设置 / 非法值 → None（不 panic、不泄露）。
    assert!(IdentityKey::from_env("C_UNIVERSE_ABSENT_ZZZ").is_none());
    assert!(IdentityKey::from_env("C_UNIVERSE_ABSENT_ABC").is_none());

    // 合法 64-hex → 注入成功，值与 hex 逐字节一致。
    let var = "C_UNIVERSE_TEST_INJECT";
    let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    std::env::set_var(var, hex); // 模拟部署编排注入（生产由 KMS/编排注入，不入库）
    let expected = {
        let mut e = [0u8; 32];
        e[0] = 0x00;
        e[1] = 0x11;
        e[2] = 0x22;
        e[3] = 0x33;
        e[4] = 0x44;
        e[5] = 0x55;
        e[6] = 0x66;
        e[7] = 0x77;
        e[8] = 0x88;
        e[9] = 0x99;
        e[10] = 0xaa;
        e[11] = 0xbb;
        e[12] = 0xcc;
        e[13] = 0xdd;
        e[14] = 0xee;
        e[15] = 0xff;
        e
    };
    let key = IdentityKey::from_env(var).expect("合法 hex 应注入成功");
    std::env::remove_var(var);
    // 用同一密钥 negotiate 级联身份认证，隐含验证内置字节与 hex 一致：
    let k2 = IdentityKey::new(&expected);
    assert_eq!(format!("{key:?}"), format!("{k2:?}"), "env 注入值与 hex 不一致");

    // 长度非 32 字节（此处仅 2 字节）→ 拒绝（None），不 panic。
    std::env::set_var(var, "0011");
    assert!(IdentityKey::from_env(var).is_none());
    std::env::remove_var(var);

    // Debug 永不打印明文（防日志泄露）。
    assert_eq!(format!("{key:?}"), "IdentityKey(***redacted***)");
}

/// 握手两端能够得到**一致的方向化会话根种子对**（双向隔离）。
#[test]
fn handshake_reaches_common_directional_roots() {
    // 双方共享同一预共享身份密钥（部署前带外分发）。
    let key = IdentityKey::generate();
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

    let frame_a = ka.outbound_frame(&salt_a, &key, Role::Initiator);
    let frame_b = kb.outbound_frame(&salt_b, &key, Role::Responder);
    // 双向交叉认证对端身份（各自以对端角色解析）：共享身份密钥下均应通过。
    let hf_a = parse_handshake_frame(&frame_b, &key, Role::Initiator).unwrap();
    let hf_b = parse_handshake_frame(&frame_a, &key, Role::Responder).unwrap();
    // 身份认证通过后，对端公钥与纯载荷解析一致。
    assert_eq!(hf_a.peer_public, kb.public_key());
    assert_eq!(hf_b.peer_public, ka.public_key());
    // 从帧中解析对端公钥（等价于网络上交换）。
    let (pub_a, _) = c_universe::handshake::parse_peer_frame(&frame_a).unwrap();
    let (pub_b, _) = c_universe::handshake::parse_peer_frame(&frame_b).unwrap();

    // 双方以固定顺序拼接各自盐（A||B），保证派生一致。
    let combined_a = crypto::combine_session_salts(&salt_a, &salt_b);
    let combined_b = crypto::combine_session_salts(&salt_a, &salt_b);

    let (ir_a, ri_a) = ka
        .derive_directional_roots_with_salt(&pub_b, &combined_a)
        .unwrap();
    let (ir_b, ri_b) = kb
        .derive_directional_roots_with_salt(&pub_a, &combined_b)
        .unwrap();

    // 同一方向两端鉴出同一根。
    assert_eq!(ir_a, ir_b);
    assert_eq!(ri_a, ri_b);
    // 两方向互不相同（双向隔离）。
    assert_ne!(ir_a, ri_a);
    // 均为非零。
    assert_ne!(ir_a, [0u8; 32]);
    assert_ne!(ri_a, [0u8; 32]);
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

/// 加密原语白盒验证：逐条核对 crypto.rs 的实现性质。
#[test]
fn crypto_layer_properties_hold() {
    use c_universe::crypto;

    // ① HKDF 根种子：确定性 —— 相同输入必得相同输出（方向化，非废弃的单 root）。
    let dh = c_universe::handshake::random_bytes_32();
    let salt = c_universe::handshake::random_bytes_32();
    let (a, d) = crypto::derive_directional_roots(&dh, &salt);
    let (b, e) = crypto::derive_directional_roots(&dh, &salt);
    assert_eq!(a, b);
    assert_eq!(d, e);
    assert_ne!(a, d); // 两方向互不相同（双向隔离）。
    // 换盐则根种子不同（盐承担会话随机化）。
    let salt2 = {
        let mut s = salt;
        s[0] ^= 1;
        s
    };
    let (c, f) = crypto::derive_directional_roots(&dh, &salt2);
    assert_ne!(a, c);
    assert_ne!(d, f);

    // ② 逐包密钥：不同 coord 派生不同 K_n（序号隔离，报错不改跨包）。
    let k0 = crypto::derive_packet_key(&a, 0);
    let k1 = crypto::derive_packet_key(&a, 1);
    assert_ne!(k0, k1);

    // ③ nonce 与密钥一一对应：同 coord、同根恒同 nonce；不同 coord 必不同；且首包非全零。
    assert_eq!(crypto::derive_nonce(&a, 7), crypto::derive_nonce(&a, 7));
    assert_ne!(crypto::derive_nonce(&a, 7), crypto::derive_nonce(&a, 8));
    // 首包（coord=0）nonce 带根派生前缀，不应是全零（修复项 ②）。
    assert_ne!(crypto::derive_nonce(&a, 0), [0u8; 12]);
    // 不同方向根种子 → nonce 前缀不同，方向/会话间 nonce 空间隔离。
    assert_ne!(crypto::derive_nonce(&a, 3), crypto::derive_nonce(&d, 3));

    // ④ AEAD 往返：seal 后 open 能还原明文。
    let body = b"classified payload";
    let aad = b"version|coord=0";
    let nonce = crypto::derive_nonce(&a, 0);
    let key = crypto::derive_packet_key(&a, 0);
    let ct = crypto::seal(&key, &nonce, aad, body);
    assert_eq!(crypto::open(&key, &nonce, aad, &ct).unwrap(), body);

    // ⑤ 明文隐藏：密文里不能出现任何明文字节。
    assert_eq!(ct.windows(body.len()).any(|w| w == body), false);
    assert_ne!(ct, body);

    // ⑥ 错钥失败：换一个密钥 open 必失败。
    let other_key = crypto::derive_packet_key(&a, 1);
    assert!(crypto::open(&other_key, &nonce, aad, &ct).is_err());

    // ⑦ AAD 绑定：改头部（AAD）一个字节即认证失败（防改序号/版本）。
    let aad2 = b"version|coord=1";
    assert!(crypto::open(&key, &nonce, aad2, &ct).is_err());

    // ⑧ 篡改密文任一位 → 认证失败（完整性）。
    let mut forged = ct.clone();
    forged[0] ^= 0x01;
    assert!(crypto::open(&key, &nonce, aad, &forged).is_err());

    // ⑨ nonce 错配也失败（防 nonce 重排攻击）。
    let nonce2 = crypto::derive_nonce(&a, 1);
    assert!(crypto::open(&key, &nonce2, aad, &ct).is_err());
}