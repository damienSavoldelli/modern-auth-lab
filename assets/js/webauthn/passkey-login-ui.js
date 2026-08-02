import { getPasskeyAssertion } from './passkey-authentication.js';

const CHALLENGE_ENDPOINT = '/login/passkey/challenge';
const VERIFY_ENDPOINT = '/login/passkey/verify';

export function initPasskeyLoginUi(
  documentRef = typeof document === 'undefined' ? null : document,
  {
    fetchImpl = typeof fetch === 'undefined' ? null : fetch,
    getAssertion = getPasskeyAssertion,
    navigateTo = (target) => {
      if (typeof window !== 'undefined') {
        window.location.assign(target);
      }
    },
    globalObject = typeof globalThis === 'undefined' ? undefined : globalThis,
  } = {},
) {
  if (documentRef === null) {
    return null;
  }

  const trigger = documentRef.getElementById('passkey-login-trigger');

  if (trigger === null) {
    return null;
  }

  const status = documentRef.getElementById('passkey-login-status');

  const handler = () => {
    void runPasskeyLogin({
      fetchImpl,
      getAssertion,
      navigateTo,
      globalObject,
      status,
    });
  };

  trigger.addEventListener('click', handler);

  return handler;
}

export async function runPasskeyLogin({
  fetchImpl,
  getAssertion,
  navigateTo,
  globalObject,
  status,
}) {
  setStatus(status, '');

  try {
    const challengeResponse = await fetchImpl(CHALLENGE_ENDPOINT, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });

    if (!challengeResponse.ok) {
      setStatus(status, 'Passkey login is not available.');
      return;
    }

    const challengePayload = await challengeResponse.json();
    const publicKeyOptions = challengePayload.publicKey;

    if (!publicKeyOptions) {
      setStatus(status, 'Passkey login options are missing.');
      return;
    }

    const assertion = await getAssertion(publicKeyOptions, globalObject);

    const verifyResponse = await fetchImpl(VERIFY_ENDPOINT, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ credential: assertion }),
    });

    if (!verifyResponse.ok) {
      setStatus(status, 'Passkey login failed. Please try again.');
      return;
    }

    const verifyPayload = await verifyResponse.json();
    navigateTo(verifyPayload.redirect ?? '/account');
  } catch {
    setStatus(status, 'Passkey login could not be completed.');
  }
}

function setStatus(node, message) {
  if (node !== null && node !== undefined) {
    node.textContent = message;
  }
}
