//! C-Universe 混沌协议端到端演示。
//!
//! 模拟一段**丢包 + 乱序 + 篡改 + 重放**的链路，展示协议四大核心：
//! 1. 发送方无阻塞不间断发包；
//! 2. 丢包/乱序不影响后续包（迟到的合法包在 30s 窗口内仍被收取）；
//! 3. 核销表拦截同 coord 重放；
//! 4. 篡改包被 AEAD 认证拦截。
//!
//! 运行：`cargo run --example chaos_demo`

use std::collections::HashSet;

use c_universe::handshake::random_bytes_32;
use c_universe::packet::Packet;
use c_universe::{ReceiveError, Receiver, Sender};

/// 一个内存“有损链路”：按投递顺序随机丢弃一小部分包。
struct LossyLink {
    drop_rate: f64,
    rng: u64,
    delivered: Vec<Vec<u8>>,
    dropped: usize,
}

impl LossyLink {
    fn new(drop_rate: f64, seed: u64) -> Self {
        LossyLink {
            drop_rate,
            rng: seed,
            delivered: Vec::new(),
            dropped: 0,
        }
    }

    fn transmit(&mut self, pkt: &Packet) {
        self.rng = self.rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let r = ((self.rng >> 32) as f64) / (u32::MAX as f64);
        if r < self.drop_rate {
            self.dropped += 1;
        } else {
            self.delivered.push(pkt.as_bytes().to_vec());
        }
    }

    /// 随机洗乱投递顺序，模拟网络乱序。
    fn reshuffle(&mut self) {
        for i in 0..self.delivered.len() {
            self.rng = self.rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = ((self.rng >> 32) as usize) % self.delivered.len();
            self.delivered.swap(i, j);
        }
    }
}

fn main() {
    let root = random_bytes_32();
    let n_pkts = 10_000u64;
    let drop_rate = 0.12;

    let mut tx = Sender::new(&root);
    let mut rx = Receiver::with_defaults(&root);
    let mut link = LossyLink::new(drop_rate, 2026);

    let t = std::time::Instant::now();

    // 1) 发送方无阻塞连续发包（0..N 全部一股脑发出，丢包不重传）。
    for i in 0..n_pkts {
        let payload = format!("payload-{i}");
        let pkt = tx.send(payload.as_bytes());
        link.transmit(&pkt);
    }
    link.reshuffle();

    println!(
        "[*] 已无阻塞发出 {n_pkts} 包，丢包率 {:.0}%，发送耗时 {} us",
        drop_rate * 100.0,
        t.elapsed().as_micros()
    );

    // 2) 接收端处理有损乱序流，统计命中各防御层。
    let mut accepted = 0usize;
    let mut voided = 0usize;
    let mut replayed = 0usize;
    let mut tampered = 0usize;
    let mut received = HashSet::new();

    for bytes in &link.delivered {
        let pkt = Packet::from_bytes(bytes.clone());

        // 模拟攻击者：对一小部分包翻转密文做篡改。
        let victim = if bytes.len() > c_universe::packet::HEADER_LEN
            && bytes[c_universe::packet::HEADER_LEN] % 16 == 7
        {
            let mut raw = bytes.clone();
            let mid = c_universe::packet::HEADER_LEN + raw.len() / 2;
            raw[mid] ^= 0x01;
            Packet::from_bytes(raw)
        } else {
            pkt
        };

        match rx.recv(&victim) {
            Ok(_plain) => {
                accepted += 1;
                if let Ok(h) = victim.header() {
                    received.insert(h.coord);
                }
            }
            Err(ReceiveError::Replay(_)) => replayed += 1,
            Err(ReceiveError::Voided(_)) => voided += 1,
            Err(ReceiveError::AuthenticationFailed) => tampered += 1,
            Err(ReceiveError::SessionExpired) => {
                println!("[!] 会话熔断（演示全程有包，正常不会触发）");
                break;
            }
            Err(ReceiveError::DoSLimit) => {
                println!("[!] 认证洪水熔断（安全演示不会触发）");
                break;
            }
            Err(ReceiveError::Malformed) => unreachable!("demo packets are well-formed"),
        }
    }

    // 3) 演示核销表拦截重放：取一个已成功收取的 coord，构造其同序号副本并重放。
    let replay_coord = received.iter().min().copied().unwrap_or(0);
    let replay_pkt = c_universe::packet::Packet::new(&root, replay_coord, b"replayed-copy");
    match rx.recv(&replay_pkt) {
        Err(ReceiveError::Replay(c)) => println!("[*] 重放拦截：coord {c} 已被核销，副本被丢弃"),
        _ => println!("[?] 重放未被拦截（异常）"),
    }

    println!("---");
    println!("  发出总数   : {n_pkts}");
    println!("  链路丢弃   : {}", link.dropped);
    println!("  到达接收端 : {}", link.delivered.len());
    println!("  成功收取   : {accepted}");
    println!("  空缺作废   : {voided} (30s 窗口超时后永久作废)");
    println!("  重放拦截   : {replayed}");
    println!("  篡改拦截   : {tampered} (AEAD 认证失败)");

    println!("  去重 coord 已收取: {}", received.len());
}