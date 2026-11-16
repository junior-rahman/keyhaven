// apps/desktop/src-tauri/src/hello.rs
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use windows::Security::Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::core::{HSTRING, Result, factory};
use windows_future::IAsyncOperation;

/// Shows the Windows Hello dialog over the Keyhaven window and returns true only for a real
/// fingerprint, face or PIN. `message` appears inside the dialog, so you see what you approve.
/// Call it from a worker thread: `join` blocks until the dialog closes.
pub fn verify_presence(window: HWND, message: &str) -> Result<bool> {
    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let message = HSTRING::from(message);
    // SAFETY: `window` is the caller's top-level window handle; Windows only uses it to parent the dialog
    // and fails the call (rather than misbehaving) if the handle is not a valid window. `message` is an
    // owned HSTRING that outlives the call.
    let pending: IAsyncOperation<UserConsentVerificationResult> =
        unsafe { interop.RequestVerificationForWindowAsync(window, &message)? };
    Ok(pending.join()? == UserConsentVerificationResult::Verified)
}

/// Quick unlock: Windows Hello signs a fixed random challenge with a key that never leaves the
/// TPM, and the signature is the seed for the key that wraps the vault key on this device.
/// No gesture, no signature, no vault key.
pub fn hello_signature(challenge: &[u8]) -> Result<Option<Vec<u8>>> {
    let name = HSTRING::from("Keyhaven quick unlock");
    let mut found = KeyCredentialManager::OpenAsync(&name)?.join()?;
    if found.Status()? == KeyCredentialStatus::NotFound {
        found = KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::FailIfExists)?.join()?;
    }
    if found.Status()? != KeyCredentialStatus::Success {
        return Ok(None); // Hello is not set up, or you cancelled
    }
    let data = CryptographicBuffer::CreateFromByteArray(challenge)?;
    let signed = found.Credential()?.RequestSignAsync(&data)?.join()?;
    if signed.Status()? != KeyCredentialStatus::Success {
        return Ok(None);
    }
    let mut signature = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&signed.Result()?, &mut signature)?;
    Ok(Some(signature.to_vec()))
}
