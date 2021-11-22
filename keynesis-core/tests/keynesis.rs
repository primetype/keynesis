#![cfg(feature = "nightly")]
#![feature(test)]

extern crate test;
use cryptoxide::blake2s::Blake2s;
use keynesis::{
    key::{curve25519::SecretKey, Dh as _},
    noise::IK,
    Seed,
};
use test::Bencher;

#[bench]
fn ik(b: &mut Bencher) {
    let mut rng = rand::thread_rng();
    let seed1 = Seed::generate(&mut rng);
    let seed2 = Seed::generate(&mut rng);
    let mut rng1 = seed1.into_rand_chacha();
    let mut rng2 = seed2.into_rand_chacha();

    let initiator_secret_key = SecretKey::new(&mut rng);
    let responder_secret_key = SecretKey::new(&mut rng);

    let (mut first_msg, mut second_msg) = (Vec::with_capacity(1024), Vec::with_capacity(1024));

    b.iter(|| {
        let initiator = IK::<_, Blake2s, _, _>::new(&mut rng1, &[]);
        let responder = IK::<_, Blake2s, _, _>::new(&mut rng2, &[]);

        // -> e, es, s, ss
        let initiator = initiator
            .initiate(
                &initiator_secret_key,
                responder_secret_key.public(),
                &mut first_msg,
            )
            .unwrap();

        // responder processes the first message...
        let responder = responder
            .receive(&responder_secret_key, first_msg.as_ref())
            .unwrap();

        // <- e, ee, se
        responder.reply(&mut second_msg).unwrap();

        // initiator processes the response...
        initiator
            .receive(&initiator_secret_key, second_msg.as_ref())
            .unwrap();

        first_msg.clear();
        second_msg.clear();
    });
}
