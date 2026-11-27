"use strict";

(() => {
  const fromBase64URL = value => {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    return Uint8Array.from(binary, character => character.charCodeAt(0)).buffer;
  };
  const toBase64URL = value => {
    const bytes = new Uint8Array(value);
    let binary = "";
    bytes.forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const prepareOptions = options => {
    const publicKey = { ...options };
    publicKey.challenge = fromBase64URL(publicKey.challenge);
    if (publicKey.user) publicKey.user = { ...publicKey.user, id: fromBase64URL(publicKey.user.id) };
    for (const key of ["allowCredentials", "excludeCredentials"]) {
      if (publicKey[key]) publicKey[key] = publicKey[key].map(item => ({ ...item, id: fromBase64URL(item.id) }));
    }
    return publicKey;
  };
  const serialize = credential => {
    const response = {};
    for (const key of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"])
      if (credential.response[key]) response[key] = toBase64URL(credential.response[key]);
    return {
      id: credential.id,
      rawId: toBase64URL(credential.rawId),
      type: credential.type,
      response,
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment
    };
  };
  const postJSON = async (url, payload, csrf) => {
    const headers = { "Content-Type": "application/json", "Accept": "application/json" };
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(url, { method: "POST", credentials: "same-origin", headers, body: JSON.stringify(payload) });
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || "Passkey request failed");
    return result.data;
  };
  const status = document.getElementById("passkey-status");
  const registration = document.getElementById("passkey-register");
  let pendingPasskeyID = "";
  if (registration) registration.addEventListener("submit", async event => {
    event.preventDefault();
    if (!window.PublicKeyCredential || !navigator.credentials) { status.textContent = registration.dataset.unsupported || "Passkey registration is unavailable."; return; }
    const values = new FormData(registration);
    const csrf = values.get("csrf_token");
    const password = values.get("current_password");
    try {
      status.textContent = registration.dataset.waiting || "Waiting for your authenticator…";
      const setup = await postJSON(registration.dataset.setup, { action: "setup", current_password: password }, csrf);
      const credential = await navigator.credentials.create({ publicKey: prepareOptions(setup.publicKey) });
      const result = await postJSON(registration.dataset.register, { action: "register", challenge_id: setup.challenge_id, credential: serialize(credential), current_password: password, name: values.get("name") }, csrf);
      if (result.requires_saved_confirmation && Array.isArray(result.recovery_keys)) {
        pendingPasskeyID = result.id;
        const section = document.getElementById("passkey-recovery");
        const list = document.getElementById("passkey-recovery-list");
        list.replaceChildren(...result.recovery_keys.map(code => { const item = document.createElement("li"); const value = document.createElement("code"); value.textContent = code; item.append(value); return item; }));
        section.hidden = false;
        status.textContent = registration.dataset.saveKeys || "Save these recovery keys before continuing.";
      } else window.location.reload();
    } catch (_) { status.textContent = registration.dataset.failed || "Passkey registration failed."; }
  });
  const saved = document.getElementById("passkey-recovery-saved");
  const activate = document.getElementById("passkey-activate");
  if (saved && activate && registration) {
    saved.addEventListener("change", () => { activate.disabled = !saved.checked; });
    activate.addEventListener("click", async () => {
      if (!saved.checked || !pendingPasskeyID) return;
      const values = new FormData(registration);
      try {
        activate.disabled = true;
        const csrf = values.get("csrf_token");
        await postJSON(registration.dataset.register, { action: "confirm", passkey_id: pendingPasskeyID, recovery_keys_saved: true, current_password: values.get("current_password") }, csrf);
        window.location.reload();
      } catch (_) { status.textContent = registration.dataset.activationFailed || registration.dataset.failed || "Passkey activation failed."; activate.disabled = false; }
    });
  }
  const login = document.getElementById("passkey-login");
  if (login) login.addEventListener("submit", async event => {
    event.preventDefault();
    if (!window.PublicKeyCredential || !navigator.credentials) { status.textContent = login.dataset.unsupported || "Passkey sign in is unavailable."; return; }
    try {
      status.textContent = login.dataset.waiting || "Waiting for your authenticator…";
      const start = await postJSON(login.action, { username: new FormData(login).get("username") });
      const assertion = await navigator.credentials.get({ publicKey: prepareOptions(start.publicKey) });
      const result = await postJSON(login.dataset.verify, { challenge_id: start.challenge_id, credential: serialize(assertion), browser: true });
      window.location.assign(result.requires_2fa ? "/server/auth/2fa" : "/");
    } catch (_) { status.textContent = login.dataset.failed || "Passkey sign in failed."; }
  });
})();
