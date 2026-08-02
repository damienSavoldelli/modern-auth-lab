import { createPasskeyCredential } from './passkey-enrollment.js';

const CHALLENGE_ENDPOINT = '/account/security/passkeys/enroll/challenge';
const VERIFY_ENDPOINT = '/account/security/passkeys/enroll/verify';

export function initPasskeyEnrollmentUi(
  documentRef = typeof document === 'undefined' ? null : document,
  {
    fetchImpl = typeof fetch === 'undefined' ? null : fetch,
    createCredential = createPasskeyCredential,
    reload = () => {
      if (typeof window !== 'undefined') {
        window.location.reload();
      }
    },
    globalObject = typeof globalThis === 'undefined' ? undefined : globalThis,
  } = {},
) {
  if (documentRef === null) {
    return null;
  }

  const form = documentRef.getElementById('passkey-enrollment-form');

  if (form === null) {
    return null;
  }

  const handler = (event) => {
    event.preventDefault();
    void submitEnrollment(form, {
      fetchImpl,
      createCredential,
      reload,
      globalObject,
    });
  };

  form.addEventListener('submit', handler);

  return handler;
}

export async function submitEnrollment(
  form,
  { fetchImpl, createCredential, reload, globalObject },
) {
  clearErrorMessage(form);

  const nameInput = form.querySelector('#passkey-name');
  const name = nameInput ? String(nameInput.value ?? '').trim() : '';

  if (name === '') {
    showErrorMessage(form, 'Passkey name is required.');
    return;
  }

  try {
    const challengeResponse = await fetchImpl(CHALLENGE_ENDPOINT, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });

    if (!challengeResponse.ok) {
      showErrorMessage(form, 'Passkey enrollment is not available.');
      return;
    }

    const challengePayload = await challengeResponse.json();
    const publicKeyOptions = challengePayload.publicKey;

    if (!publicKeyOptions) {
      showErrorMessage(form, 'Passkey enrollment options are missing.');
      return;
    }

    const credential = await createCredential(publicKeyOptions, globalObject);

    const verifyResponse = await fetchImpl(VERIFY_ENDPOINT, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ credential, name }),
    });

    if (!verifyResponse.ok) {
      showErrorMessage(form, 'Passkey enrollment failed. Please try again.');
      return;
    }

    reload();
  } catch {
    showErrorMessage(form, 'Passkey enrollment could not be completed.');
  }
}

function showErrorMessage(form, message) {
  let errorNode = form.querySelector('[data-passkey-enrollment-error]');

  if (errorNode === null) {
    errorNode = form.ownerDocument.createElement('p');
    errorNode.setAttribute('role', 'alert');
    errorNode.setAttribute('data-passkey-enrollment-error', '');
    form.appendChild(errorNode);
  }

  errorNode.textContent = message;
}

function clearErrorMessage(form) {
  const errorNode = form.querySelector('[data-passkey-enrollment-error]');

  if (errorNode !== null) {
    errorNode.textContent = '';
  }
}
