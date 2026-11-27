use crate::cbor::{self, Value};
use crate::wire::*;
use crate::{auth, control, file_protocol, forwarding, hello, terminal};

// Fixed seed for repeatable sampling. This generator is only used in this test.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn index(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn mutate(&mut self, bytes: &mut Vec<u8>) {
        let end = bytes.len();
        let pos = self.index(end + 1);
        match self.index(5) {
            0 => bytes.truncate(pos),
            1 => bytes.insert(pos, self.next() as u8),
            2 if pos < end => {
                bytes.remove(pos);
            }
            3 if pos < end => bytes[pos] ^= 1 << self.index(8),
            _ if pos < end => bytes[pos] = self.next() as u8,
            _ => bytes.push(self.next() as u8),
        }
    }
}

fn corpus() -> Vec<Message> {
    use Value::{Array, Bytes, Uint};
    let client = hello::ClientHello {
        versions: vec![hello::WIRE_VERSION],
        capabilities: vec![(crate::files::CAPABILITY, crate::files::parameters(8))],
        limits: Default::default(),
    };
    vec![
        client.to_message(),
        hello::ServerHello::answer(&client).unwrap().to_message(),
        auth::AuthRequest {
            method: hello::AUTH_PUBLICKEY_ED25519,
            account: "test".into(),
            key: [1; 32],
            signature: [2; 64],
        }
        .to_message(),
        auth::result_message(true),
        Message::new(SESSION_LIST, vec![(0, Uint(24))]),
        terminal::Size {
            columns: 80,
            rows: 24,
            width: 0,
            height: 0,
        }
        .resize_message(),
        terminal::data(TERMINAL_DATA, b"sample"),
        terminal::Exit::Code(0).to_message(),
        Message::new(
            FILE_REQUEST,
            vec![
                (0, Uint(1)),
                (1, Uint(1)),
                (
                    2,
                    Array(vec![Uint(0), Array(vec![Bytes(b"sample".to_vec())])]),
                ),
            ],
        ),
        forwarding::Rule {
            mode: 2,
            target: None,
            bind: Some("127.0.0.1:0".parse().unwrap()),
        }
        .message(),
    ]
}

fn parse_body(m: &Message) -> Option<bool> {
    Some(match m.kind {
        CLIENT_HELLO => hello::ClientHello::from_message(m).is_ok(),
        SERVER_HELLO => hello::ServerHello::from_message(m).is_ok(),
        AUTH_REQUEST => auth::AuthRequest::from_message(m).is_ok(),
        AUTH_RESULT => auth::result_from_message(m).is_ok(),
        SESSION_LIST => control::request_id(m).is_ok(),
        TERMINAL_RESIZE => terminal::Size::from_resize(m).is_ok(),
        TERMINAL_DATA => terminal::data_of(m).is_ok(),
        TERMINAL_EXIT => terminal::Exit::from_message(m).is_ok(),
        FILE_REQUEST => file_protocol::Request::parse(m).is_ok(),
        CHANNEL_OPEN => {
            control::channel_kind(m) == Ok(forwarding::RULE) && forwarding::Rule::parse(m).is_ok()
        }
        _ => return None,
    })
}

#[test]
#[ignore = "repeatable release parser fuzz campaign"]
fn release_parser_fuzz() {
    let seeds = corpus();
    let encoded: Vec<_> = seeds.iter().map(Message::encode).collect();
    for seed in &seeds {
        assert_eq!(parse_body(seed), Some(true));
    }
    let mut rng = Generator(0x5354_5054_0000_0002);
    let (mut values, mut envelopes, mut accepted, mut rejected) = (0, 0, 0, 0);
    for case in 0..100_000 {
        let index = rng.index(seeds.len());
        let bytes = match case % 3 {
            0 => (0..rng.index(257)).map(|_| rng.next() as u8).collect(),
            1 => {
                let mut bytes = encoded[index].clone();
                for _ in 0..=rng.index(4) {
                    rng.mutate(&mut bytes);
                }
                bytes
            }
            _ => {
                let mut m = seeds[index].clone();
                let field = rng.index(m.body.len());
                match rng.index(4) {
                    0 => {
                        m.body.remove(field);
                    }
                    1 => m.body[field].1 = Value::Uint(rng.next()),
                    2 => m.body[field].1 = Value::Null,
                    _ => m.body[field].1 = Value::Array(vec![Value::Bool(true)]),
                }
                m.encode()
            }
        };
        let value = cbor::decode(&bytes);
        if let Ok(v) = &value {
            values += 1;
            assert_eq!(cbor::encode(v), bytes, "CBOR round trip at case {case}");
        }
        let expected_envelope = matches!(&value, Ok(Value::Array(items))
            if matches!(items.as_slice(), [Value::Uint(_), Value::Map(fields)]
                if fields.iter().all(|(key, _)| key.is_int())));
        let message = Message::decode(&bytes);
        assert_eq!(
            message.is_ok(),
            expected_envelope,
            "envelope at case {case}"
        );
        if let Ok(m) = message {
            envelopes += 1;
            assert_eq!(m.encode(), bytes, "message round trip at case {case}");
            match parse_body(&m) {
                Some(true) => accepted += 1,
                Some(false) => rejected += 1,
                None => (),
            }
        }
    }
    assert!(accepted > 0 && rejected > 0);
    println!(
        "100000 cases: {values} CBOR values, {envelopes} envelopes, {accepted} bodies accepted, {rejected} bodies rejected"
    );
}
