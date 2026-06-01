#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelBinding {
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
struct ModelRecipient {
    public: u8,
    secret: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelPayloadCiphertext {
    tag: u8,
    binding_digest: u8,
    dek: u8,
    mac: u8,
    plaintext: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelWrappedDek {
    tag: u8,
    binding_digest: u8,
    recipient_public: u8,
    dek: u8,
    mac: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelSealedObject {
    binding: ModelBinding,
    epoch: u8,
    recipient_public: u8,
    payload_ciphertext: ModelPayloadCiphertext,
    wrapped_dek: ModelWrappedDek,
}

fn binding_digest(binding: ModelBinding) -> u8 {
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

fn message_mac(binding: ModelBinding, dek: u8, message: [u8; 4]) -> u8 {
    0xA5 ^ binding_digest(binding) ^ dek ^ message[0] ^ message[1] ^ message[2] ^ message[3]
}

fn wrapper_mac(binding: ModelBinding, recipient_public: u8, dek: u8) -> u8 {
    0x5A ^ binding_digest(binding) ^ recipient_public ^ dek
}

fn model_dek(binding: ModelBinding, recipient_public: u8) -> u8 {
    binding_digest(binding) ^ recipient_public ^ 0xC3
}

fn model_encrypt_payload(
    binding: ModelBinding,
    dek: u8,
    message: [u8; 4],
) -> ModelPayloadCiphertext {
    ModelPayloadCiphertext {
        tag: 0xE1,
        binding_digest: binding_digest(binding),
        dek,
        mac: message_mac(binding, dek, message),
        plaintext: message,
    }
}

fn model_decrypt_payload(
    binding: ModelBinding,
    dek: u8,
    ciphertext: ModelPayloadCiphertext,
) -> Option<[u8; 4]> {
    if ciphertext.tag != 0xE1 {
        return None;
    }
    if ciphertext.binding_digest != binding_digest(binding) {
        return None;
    }
    if ciphertext.dek != dek {
        return None;
    }
    if ciphertext.mac != message_mac(binding, dek, ciphertext.plaintext) {
        return None;
    }
    Some(ciphertext.plaintext)
}

fn model_wrap_dek(binding: ModelBinding, recipient_public: u8, dek: u8) -> ModelWrappedDek {
    ModelWrappedDek {
        tag: 0xD7,
        binding_digest: binding_digest(binding),
        recipient_public,
        dek,
        mac: wrapper_mac(binding, recipient_public, dek),
    }
}

fn model_unwrap_dek(
    binding: ModelBinding,
    recipient_secret: u8,
    wrapped: ModelWrappedDek,
) -> Option<u8> {
    if wrapped.tag != 0xD7 {
        return None;
    }
    if wrapped.binding_digest != binding_digest(binding) {
        return None;
    }
    if wrapped.recipient_public != recipient_secret {
        return None;
    }
    if wrapped.mac != wrapper_mac(binding, wrapped.recipient_public, wrapped.dek) {
        return None;
    }
    Some(wrapped.dek)
}

fn model_seal(
    recipient: ModelRecipient,
    binding: ModelBinding,
    message: [u8; 4],
) -> ModelSealedObject {
    let dek = model_dek(binding, recipient.public);
    ModelSealedObject {
        binding,
        epoch: binding.epoch,
        recipient_public: recipient.public,
        payload_ciphertext: model_encrypt_payload(binding, dek, message),
        wrapped_dek: model_wrap_dek(binding, recipient.public, dek),
    }
}

fn model_open(
    recipient_secret: u8,
    expected_binding: ModelBinding,
    expected_epoch: u8,
    sealed: ModelSealedObject,
) -> Option<[u8; 4]> {
    if expected_epoch != sealed.epoch {
        return None;
    }
    if expected_binding != sealed.binding {
        return None;
    }
    let dek = model_unwrap_dek(expected_binding, recipient_secret, sealed.wrapped_dek)?;
    model_decrypt_payload(expected_binding, dek, sealed.payload_ciphertext)
}

fn sample_binding() -> ModelBinding {
    ModelBinding {
        object_id: 11,
        rights: 7,
        policy_hash: 19,
        epoch: 3,
        authority_root: 23,
        revocation_root: 29,
        transparency_root: 31,
        capability_stamp: 37,
        temporal_policy: 41,
    }
}

fn sample_recipient() -> ModelRecipient {
    ModelRecipient {
        public: 5,
        secret: 5,
    }
}

#[kani::proof]
fn model_crypto_seal_open_roundtrip_returns_message() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);

    assert!(model_open(recipient.secret, binding, binding.epoch, sealed) == Some(message));
}

#[kani::proof]
fn model_crypto_open_rejects_wrong_recipient_secret() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);

    assert!(model_open(6, binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_altered_context() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);
    let mut altered_binding = binding;
    altered_binding.object_id ^= 1;

    assert!(model_open(recipient.secret, altered_binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_altered_object_id() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);
    let mut altered_binding = binding;
    altered_binding.object_id ^= 1;

    assert!(model_open(recipient.secret, altered_binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_altered_policy_hash() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);
    let mut altered_binding = binding;
    altered_binding.policy_hash ^= 1;

    assert!(model_open(recipient.secret, altered_binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_altered_capability_stamp() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);
    let mut altered_binding = binding;
    altered_binding.capability_stamp ^= 1;

    assert!(model_open(recipient.secret, altered_binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_altered_authority_root() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);
    let mut altered_binding = binding;
    altered_binding.authority_root ^= 1;

    assert!(model_open(recipient.secret, altered_binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_altered_payload_ciphertext() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let mut sealed = model_seal(recipient, binding, message);
    sealed.payload_ciphertext.plaintext[0] ^= 1;

    assert!(model_open(recipient.secret, binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_altered_wrapper_binding() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let mut sealed = model_seal(recipient, binding, message);
    sealed.wrapped_dek.binding_digest ^= 1;

    assert!(model_open(recipient.secret, binding, binding.epoch, sealed).is_none());
}

#[kani::proof]
fn model_crypto_open_rejects_wrong_epoch_wrapper_selection() {
    let message: [u8; 4] = kani::any();
    let recipient = sample_recipient();
    let binding = sample_binding();
    let sealed = model_seal(recipient, binding, message);

    assert!(model_open(recipient.secret, binding, binding.epoch + 1, sealed).is_none());
}
