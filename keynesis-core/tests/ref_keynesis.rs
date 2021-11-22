use cryptoxide::blake2s::Blake2s;
use keynesis::{
    key::{curve25519::SecretKey, Dh as _},
    noise::IK,
    Seed,
};
use noiseexplorer_ik as noise;

#[test]
fn ref_talk_to_keynesis() {
    let mut rng = rand::thread_rng();
    let seed = Seed::generate(&mut rng);
    let mut rng = seed.into_rand_chacha();

    let initiator_key = noise::types::Keypair::default();

    let responder_key = SecretKey::new(&mut rng);
    let responder_public = responder_key.public().to_string().parse().unwrap();

    let responder = IK::<_, Blake2s, _, _>::new(rng, &[]);

    let mut initiator = noise::noisesession::NoiseSession::init_session(
        true,
        &[],
        initiator_key,
        Some(responder_public),
    );

    let mut first_msg = [0u8; 64 + 32];
    let mut second_msg = Vec::with_capacity(1024);

    // -> e, es, s, ss
    initiator.send_message(&mut first_msg).unwrap();

    // responder processes the first message...
    let responder = responder.receive(&responder_key, &first_msg).unwrap();

    // <- e, ee, se
    let responder = responder.reply(&mut second_msg).unwrap();

    // initiator processes the response...
    initiator.recv_message(&mut second_msg).unwrap();

    let responder_session = responder.noise_session();
    let initiator_session = initiator.get_handshake_hash().unwrap();

    assert_eq!(
        initiator_session,
        responder_session.as_ref(),
        "both the responder and the initiator are expected to have the same hash session at the end"
    );
}
