import React, { useMemo, useState } from "react";

type EncryptedPayload = {
  v: 1;
  algo: "AES-GCM";
  iter: number;
  salt_b64: string;
  iv_b64: string;
  ct_b64: string;
};

function b64ToU8(b64: string): Uint8Array {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function deriveKey(password: string, salt: Uint8Array, iter: number) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptPayload(payload: EncryptedPayload, password: string): Promise<string> {
  const salt = b64ToU8(payload.salt_b64);
  const iv = b64ToU8(payload.iv_b64);
  const ct = b64ToU8(payload.ct_b64);

  const key = await deriveKey(password, salt, payload.iter);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(ptBuf);
}

export default function EncryptedArticle(props: {
  payload: EncryptedPayload;
  hint?: string;
  rememberKey?: string; // localStorage key
}) {
  const { payload, hint, rememberKey = "enc_doc_pw" } = props;
  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const storedPw = useMemo(() => {
    try { return localStorage.getItem(rememberKey) ?? ""; } catch { return ""; }
  }, [rememberKey]);

  // 可选：自动填充已记住的密码
  React.useEffect(() => {
    if (!pw && storedPw) setPw(storedPw);
  }, [storedPw]);

  async function onDecrypt() {
    setErr(null);
    setLoading(true);
    try {
      const out = await decryptPayload(payload, pw);
      setHtml(out);
      try { localStorage.setItem(rememberKey, pw); } catch {}
    } catch (e) {
      setErr("密码不对或内容已损坏");
      setHtml(null);
      try { localStorage.removeItem(rememberKey); } catch {}
    } finally {
      setLoading(false);
    }
  }

  if (html) {
    return <article dangerouslySetInnerHTML={{ __html: html }} />;
  }

  return (
    <section style={{ maxWidth: 720, margin: "0 auto" }}>
      <h2>此内容已加密</h2>
      {hint ? <p>{hint}</p> : null}
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          placeholder="输入密码"
          style={{ flex: 1, padding: 10, borderRadius: 10 }}
        />
        <button onClick={onDecrypt} disabled={loading || !pw} style={{ padding: "10px 14px", borderRadius: 10 }}>
          {loading ? "解密中…" : "解密"}
        </button>
      </div>
      {err ? <p style={{ color: "red" }}>{err}</p> : null}
    </section>
  );
}
