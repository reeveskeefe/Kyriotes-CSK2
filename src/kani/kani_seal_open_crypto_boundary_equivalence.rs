#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CryptoBinding {
    object_id: u8,
    rights: u8,
    policy_hash: u8,
    epoch: u8,
    authority_root: u8,
    revocation_root: u8,
    transparency_root: u8,
    capability_stamp: u8,
    temporal_policy: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContractCiphertext {
    key: u8,
    nonce: u8,
    aad_digest: u8,
    mac: u8,
    plaintext: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContractWrapper {
    epoch: u8,
    binding_digest: u8,
    kem_ciphertext: u8,
    wrap_nonce: u8,
    wrapped_dek: ContractCiphertext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContractObject {
    seal_epoch: u8,
    temporal_policy: u8,
    payload_nonce: u8,
    payload_ciphertext: ContractCiphertext,
    wrapper: ContractWrapper,
}

fn binding_digest(binding: CryptoBinding) -> u8 {
    binding.object_id
        ^ binding.rights
        ^ binding.policy_hash
        ^ binding.epoch
        ^ binding.authority_root
        ^ binding.revocation_root
        ^ binding.transparency_root
        ^ binding.capability_stamp
        ^ binding.temporal_policy
}

fn payload_aad_digest(binding: CryptoBinding) -> u8 {
    0x11 ^ binding.object_id ^ binding.rights ^ binding.policy_hash ^ binding.epoch
}

fn authority_aad_digest(binding: CryptoBinding, kem_ciphertext: u8) -> u8 {
    0x22 ^ binding_digest(binding)
        ^ binding.authority_root
        ^ binding.revocation_root
        ^ binding.transparency_root
        ^ kem_ciphertext
}

fn contract_mac(key: u8, nonce: u8, aad_digest: u8, plaintext: [u8; 4]) -> u8 {
    0xA9 ^ key ^ nonce ^ aad_digest ^ plaintext[0] ^ plaintext[1] ^ plaintext[2] ^ plaintext[3]
}

fn contract_encrypt(key: u8, nonce: u8, aad_digest: u8, plaintext: [u8; 4]) -> ContractCiphertext {
    ContractCiphertext {
        key,
        nonce,
        aad_digest,
        mac: contract_mac(key, nonce, aad_digest, plaintext),
        plaintext,
    }
}

fn contract_decrypt(
    key: u8,
    nonce: u8,
    aad_digest: u8,
    ciphertext: ContractCiphertext,
) -> Option<[u8; 4]> {
    if ciphertext.key != key {
        return None;
    }
    if ciphertext.nonce != nonce {
        return None;
    }
    if ciphertext.aad_digest != aad_digest {
        return None;
    }
    if ciphertext.mac != contract_mac(key, nonce, aad_digest, ciphertext.plaintext) {
        return None;
    }
    Some(ciphertext.plaintext)
}

fn contract_kem_encaps(recipient_public: u8) -> (u8, u8) {
    let shared_secret = recipient_public ^ 0xC7;
    let kem_ciphertext = recipient_public ^ 0x71;
    (kem_ciphertext, shared_secret)
}

fn contract_kem_decaps(recipient_secret: u8, kem_ciphertext: u8) -> Option<u8> {
    let recipient_public = kem_ciphertext ^ 0x71;
    if recipient_secret != recipient_public {
        return None;
    }
    Some(recipient_public ^ 0xC7)
}

fn contract_hkdf(shared_secret: u8, binding: CryptoBinding, context_digest: u8) -> u8 {
    shared_secret ^ binding_digest(binding) ^ context_digest ^ 0x3D
}

fn required_epoch(temporal_policy: u8, open_epoch: u8, seal_epoch: u8) -> Option<u8> {
    match temporal_policy {
        0 => {
            if open_epoch == seal_epoch {
                Some(open_epoch)
            } else {
                None
            }
        }
        1 => Some(seal_epoch),
        _ => None,
    }
}

fn select_required_wrapper(object: ContractObject, open_epoch: u8) -> Option<ContractWrapper> {
    let epoch = required_epoch(object.temporal_policy, open_epoch, object.seal_epoch)?;
    if object.wrapper.epoch == epoch {
        Some(object.wrapper)
    } else {
        None
    }
}

fn contract_seal(
    recipient_public: u8,
    binding: CryptoBinding,
    dek: u8,
    payload_nonce: u8,
    wrap_nonce: u8,
    message: [u8; 4],
) -> ContractObject {
    let (kem_ciphertext, shared_secret) = contract_kem_encaps(recipient_public);
    let context_digest = binding_digest(binding);
    let kek = contract_hkdf(shared_secret, binding, context_digest);
    let wrapped_dek = contract_encrypt(
        kek,
        wrap_nonce,
        authority_aad_digest(binding, kem_ciphertext),
        [dek; 4],
    );
    ContractObject {
        seal_epoch: binding.epoch,
        temporal_policy: binding.temporal_policy,
        payload_nonce,
        payload_ciphertext: contract_encrypt(
            dek,
            payload_nonce,
            payload_aad_digest(binding),
            message,
        ),
        wrapper: ContractWrapper {
            epoch: binding.epoch,
            binding_digest: context_digest,
            kem_ciphertext,
            wrap_nonce,
            wrapped_dek,
        },
    }
}

fn contract_open(
    recipient_secret: u8,
    binding: CryptoBinding,
    open_epoch: u8,
    object: ContractObject,
) -> Option<[u8; 4]> {
    let wrapper = select_required_wrapper(object, open_epoch)?;
    if wrapper.binding_digest != binding_digest(binding) {
        return None;
    }
    let shared_secret = contract_kem_decaps(recipient_secret, wrapper.kem_ciphertext)?;
    let kek = contract_hkdf(shared_secret, binding, wrapper.binding_digest);
    let dek_bytes = contract_decrypt(
        kek,
        wrapper.wrap_nonce,
        authority_aad_digest(binding, wrapper.kem_ciphertext),
        wrapper.wrapped_dek,
    )?;
    let dek = dek_bytes[0];
    contract_decrypt(
        dek,
        object.payload_nonce,
        payload_aad_digest(binding),
        object.payload_ciphertext,
    )
}

fn sample_binding() -> CryptoBinding {
    CryptoBinding {
        object_id: 11,
        rights: 7,
        policy_hash: 19,
        epoch: 3,
        authority_root: 23,
        revocation_root: 29,
        transparency_root: 31,
        capability_stamp: 37,
        temporal_policy: 0,
    }
}

#[kani::proof]
fn crypto_boundary_payload_aad_binds_policy_hash() {
    let binding = sample_binding();
    let mut altered = binding;
    altered.policy_hash ^= 1;

    assert!(payload_aad_digest(binding) != payload_aad_digest(altered));
}

#[kani::proof]
fn crypto_boundary_authority_aad_binds_kem_ciphertext() {
    let binding = sample_binding();
    let kem_ciphertext: u8 = kani::any();

    assert!(
        authority_aad_digest(binding, kem_ciphertext)
            != authority_aad_digest(binding, kem_ciphertext ^ 1)
    );
}

#[kani::proof]
fn crypto_boundary_wrapper_selection_returns_required_epoch() {
    let binding = sample_binding();
    let message: [u8; 4] = kani::any();
    let object = contract_seal(5, binding, 42, 9, 10, message);

    let wrapper = select_required_wrapper(object, binding.epoch);
    assert!(wrapper.is_some());
    assert!(wrapper.unwrap().epoch == binding.epoch);
}

#[kani::proof]
fn crypto_boundary_wrapper_selection_rejects_missing_epoch() {
    let binding = sample_binding();
    let message: [u8; 4] = kani::any();
    let mut object = contract_seal(5, binding, 42, 9, 10, message);
    object.wrapper.epoch = binding.epoch + 1;

    assert!(select_required_wrapper(object, binding.epoch).is_none());
}

#[kani::proof]
fn crypto_boundary_aead_roundtrip_contract_returns_plaintext() {
    let key: u8 = kani::any();
    let nonce: u8 = kani::any();
    let aad_digest: u8 = kani::any();
    let message: [u8; 4] = kani::any();
    let ciphertext = contract_encrypt(key, nonce, aad_digest, message);

    assert!(contract_decrypt(key, nonce, aad_digest, ciphertext) == Some(message));
}

#[kani::proof]
fn crypto_boundary_aead_rejects_tampered_aad() {
    let key: u8 = kani::any();
    let nonce: u8 = kani::any();
    let aad_digest: u8 = kani::any();
    let message: [u8; 4] = kani::any();
    let ciphertext = contract_encrypt(key, nonce, aad_digest, message);

    assert!(contract_decrypt(key, nonce, aad_digest ^ 1, ciphertext).is_none());
}

#[kani::proof]
fn crypto_boundary_dek_wrap_contract_roundtrip() {
    let binding = sample_binding();
    let dek: u8 = kani::any();
    let recipient_public = 5;
    let (kem_ciphertext, shared_secret) = contract_kem_encaps(recipient_public);
    let context_digest = binding_digest(binding);
    let kek = contract_hkdf(shared_secret, binding, context_digest);
    let wrapped = contract_encrypt(
        kek,
        10,
        authority_aad_digest(binding, kem_ciphertext),
        [dek; 4],
    );

    assert!(
        contract_decrypt(
            kek,
            10,
            authority_aad_digest(binding, kem_ciphertext),
            wrapped
        ) == Some([dek; 4])
    );
}

#[kani::proof]
fn crypto_boundary_kem_hkdf_contract_is_deterministic() {
    let binding = sample_binding();
    let recipient_public: u8 = kani::any();
    let first = contract_kem_encaps(recipient_public);
    let second = contract_kem_encaps(recipient_public);
    let context_digest = binding_digest(binding);

    assert!(first == second);
    assert!(
        contract_hkdf(first.1, binding, context_digest)
            == contract_hkdf(second.1, binding, context_digest)
    );
}

#[kani::proof]
fn crypto_semantic_contract_seal_open_returns_message() {
    let binding = sample_binding();
    let message: [u8; 4] = kani::any();
    let recipient_public = 5;
    let recipient_secret = 5;
    let object = contract_seal(recipient_public, binding, 42, 9, 10, message);

    assert!(contract_open(recipient_secret, binding, binding.epoch, object) == Some(message));
}

#[kani::proof]
fn crypto_semantic_contract_rejects_payload_ciphertext_tamper() {
    let binding = sample_binding();
    let message: [u8; 4] = kani::any();
    let recipient_public = 5;
    let recipient_secret = 5;
    let mut object = contract_seal(recipient_public, binding, 42, 9, 10, message);
    object.payload_ciphertext.plaintext[0] ^= 1;

    assert!(contract_open(recipient_secret, binding, binding.epoch, object).is_none());
}
