// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: original

use ssh_key::{
    LineEnding, PrivateKey,
    getrandom::SysRng,
    private::Ed25519Keypair,
    rand_core::{TryCryptoRng, TryRng},
};
use zeroize::Zeroizing;

use crate::{
    credential_write_validation::{
        CredentialCreateType, SensitiveBytes, ValidatedCredentialCreate,
    },
    errors::ApiError,
};

const GENERATED_SECRET_LENGTH: usize = 32;
const ASCII_ALPHANUMERIC: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

struct GeneratedCredentialSecrets {
    secret: SensitiveBytes,
    private_key: SensitiveBytes,
}

pub(crate) async fn generate_credential_secrets(
    request: &mut ValidatedCredentialCreate,
) -> Result<(), ApiError> {
    if !request.autogenerate {
        return Ok(());
    }

    let credential_type = request.credential_type;
    let generated =
        tokio::task::spawn_blocking(move || generate_with_rng(&mut SysRng, credential_type))
            .await
            .map_err(|_| ApiError::ControlFailure)??;
    request.secret = generated.secret;
    request.private_key = generated.private_key;
    Ok(())
}

fn generate_with_rng<R>(
    rng: &mut R,
    credential_type: CredentialCreateType,
) -> Result<GeneratedCredentialSecrets, ApiError>
where
    R: TryCryptoRng + ?Sized,
{
    let secret = random_ascii_alphanumeric(rng)?;
    match credential_type {
        CredentialCreateType::Up => Ok(GeneratedCredentialSecrets {
            secret,
            private_key: SensitiveBytes::from_bytes(Vec::new()),
        }),
        CredentialCreateType::Usk => {
            let mut seed = Zeroizing::new([0_u8; 32]);
            rng.try_fill_bytes(seed.as_mut())
                .map_err(|_| ApiError::ControlFailure)?;
            let private_key = PrivateKey::from(Ed25519Keypair::from_seed(&seed))
                .encrypt(rng, secret.as_bytes())
                .map_err(|_| ApiError::ControlFailure)?
                .to_openssh(LineEnding::LF)
                .map_err(|_| ApiError::ControlFailure)?;
            Ok(GeneratedCredentialSecrets {
                secret,
                private_key: SensitiveBytes::from_bytes(private_key.as_bytes().to_vec()),
            })
        }
    }
}

fn random_ascii_alphanumeric<R>(rng: &mut R) -> Result<SensitiveBytes, ApiError>
where
    R: TryRng + ?Sized,
{
    let mut secret = Vec::with_capacity(GENERATED_SECRET_LENGTH);
    while secret.len() < GENERATED_SECRET_LENGTH {
        let mut byte = [0_u8; 1];
        rng.try_fill_bytes(&mut byte)
            .map_err(|_| ApiError::ControlFailure)?;
        // 248 is the largest multiple of 62 below 256. Rejecting the
        // remaining eight values makes the modulo operation unbiased.
        if byte[0] < 248 {
            secret.push(ASCII_ALPHANUMERIC[(byte[0] % 62) as usize]);
        }
    }
    Ok(SensitiveBytes::from_bytes(secret))
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt};

    use ssh_key::rand_core::{TryCryptoRng, TryRng};

    use super::*;

    #[derive(Debug)]
    struct RngFailure;

    impl fmt::Display for RngFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected random-source failure")
        }
    }

    impl Error for RngFailure {}

    struct FailingRng;

    impl TryRng for FailingRng {
        type Error = RngFailure;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(RngFailure)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(RngFailure)
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            Err(RngFailure)
        }
    }

    impl TryCryptoRng for FailingRng {}

    #[test]
    fn credential_generation_fails_closed_when_random_source_fails() {
        assert!(matches!(
            generate_with_rng(&mut FailingRng, CredentialCreateType::Up),
            Err(ApiError::ControlFailure)
        ));
        assert!(matches!(
            generate_with_rng(&mut FailingRng, CredentialCreateType::Usk),
            Err(ApiError::ControlFailure)
        ));
    }
}
