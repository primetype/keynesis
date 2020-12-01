#![feature(test)]

extern crate test;
use test::Bencher;

use snow::{params::NoiseParams, Builder};

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

#[bench]
fn ik(b: &mut Bencher) {
    let pattern: NoiseParams = PATTERN.parse().unwrap();
    let initiator = Builder::new(pattern.clone());
    let responder = Builder::new(pattern.clone());
    let initiator_key = initiator.generate_keypair().unwrap();
    let responder_key = responder.generate_keypair().unwrap();

    let (mut read_buf, mut first_msg, mut second_msg) = ([0u8; 1024], [0u8; 1024], [0u8; 1024]);

    b.iter(|| {
        let initiator = Builder::new(pattern.clone());
        let responder = Builder::new(pattern.clone());
        let mut initiator = initiator
            .local_private_key(&initiator_key.private)
            .remote_public_key(&responder_key.public)
            .build_initiator()
            .unwrap();
        let mut responder = responder
            .local_private_key(&responder_key.private)
            .build_responder()
            .unwrap();

        // -> e, es, s, ss
        let len = initiator.write_message(&[], &mut first_msg).unwrap();

        // responder processes the first message...
        responder
            .read_message(&first_msg[..len], &mut read_buf)
            .unwrap();

        // <- e, ee, se
        let len = responder.write_message(&[], &mut second_msg).unwrap();

        // initiator processes the response...
        initiator
            .read_message(&second_msg[..len], &mut read_buf)
            .unwrap();
    });
}
