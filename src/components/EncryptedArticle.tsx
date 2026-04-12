import { useEffect, useMemo, useState } from "react";

export type EncryptedPayload = {
  v: 1;
  algo: "AES-GCM";
  iter: number;
  salt_b64: string;
  iv_b64: string;
  ct_b64: string;
};

type UnlockStage = "locked" | "verifying" | "revealing" | "unlocked" | "bad";

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function b64ToU8(b64: string): Uint8Array {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export async function deriveKey(password: string, salt: Uint8Array, iter: number) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

export async function decryptEncryptedPayload(
  payload: EncryptedPayload,
  password: string,
): Promise<string> {
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
  rememberKey?: string;
  autoDecrypt?: boolean;
}) {
  const { payload, hint, rememberKey = "enc_doc_pw", autoDecrypt = false } = props;

  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [stage, setStage] = useState<UnlockStage>("locked");
  const [statusLine, setStatusLine] = useState("WAITING FOR KEY SIGNAL");
  const [progress, setProgress] = useState(0);
  const [glitchSeed, setGlitchSeed] = useState(0);
  const [loading, setLoading] = useState(false);

  const glitchLabel = useMemo(
    () => `NOISE-${glitchSeed.toString(16).toUpperCase().padStart(2, "0")} // ACCESS REJECTED`,
    [glitchSeed],
  );

  useEffect(() => {
    try {
      const stored = localStorage.getItem(rememberKey) ?? "";
      if (stored) setPw(stored);
    } catch {
      // ignore browser storage failures
    }
  }, [rememberKey]);

  useEffect(() => {
    if (!autoDecrypt) return;
    if (!pw) return;
    if (html) return;
    if (loading) return;
    void onDecrypt();
  }, [autoDecrypt, html, loading, pw]);

  async function onDecrypt() {
    const password = pw.trim();
    if (!password) return;

    setErr(null);
    setLoading(true);
    setStage("verifying");
    setStatusLine("KEY SIGNAL RECEIVED");
    setProgress(16);

    try {
      await wait(180);
      setStatusLine("VERIFYING PBKDF2 SIGNATURE");
      setProgress(38);

      const out = await decryptEncryptedPayload(payload, password);

      setStatusLine("REDUCING CHANNEL NOISE");
      setProgress(72);
      await wait(220);

      setHtml(out);
      setStage("revealing");
      setStatusLine("ARCHIVE UNSEALED");
      setProgress(100);

      try {
        localStorage.setItem(rememberKey, password);
      } catch {
        // ignore browser storage failures
      }

      await wait(460);
      setStage("unlocked");
    } catch {
      setStage("bad");
      setStatusLine("UNAUTHORIZED SIGNAL");
      setErr("密钥不正确，未授权访问。");
      setProgress(7);
      setHtml(null);
      setGlitchSeed((value) => value + 1);

      try {
        localStorage.removeItem(rememberKey);
      } catch {
        // ignore browser storage failures
      }
    } finally {
      setLoading(false);
    }
  }

  function resetSignal(nextValue: string) {
    setPw(nextValue);
    setErr(null);
    setStage("locked");
    setStatusLine("WAITING FOR KEY SIGNAL");
    setProgress(0);
  }

  if (stage === "unlocked" && html) {
    return (
      <section className="mx-auto max-w-[76rem] pb-12">
        <div className="mb-6 overflow-hidden rounded-[1.6rem] border border-slate-200/15 bg-[#05070a]/85 panel-grid panel-noise glow-frame">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 px-6 py-4">
            <div>
              <div className="text-[0.72rem] font-benderBold tracking-[0.35em] text-white/45">SEALED ARCHIVE</div>
              <div className="mt-2 text-[1.5rem] font-benderBold tracking-[0.08em] text-white">Archive Unsealed</div>
            </div>
            <div className="rounded-full border border-slate-200/20 bg-slate-200/10 px-4 py-2 text-[0.72rem] font-benderBold tracking-[0.32em] text-slate-100">
              ACCESS // VERIFIED
            </div>
          </div>

          <article className="px-6 py-7" dangerouslySetInnerHTML={{ __html: html }} />
        </div>
      </section>
    );
  }

  return (
    <section className="mx-auto max-w-[58rem] pb-12">
      <div
        className={[
          "relative overflow-hidden rounded-[2rem] border border-slate-200/14 bg-[#05070a]/88 px-6 py-6 panel-grid panel-noise glow-frame backdrop-blur-md transition-all duration-300",
          stage === "verifying" || stage === "revealing" ? "scanlines" : "",
          stage === "bad" ? "border-rose-300/25" : "",
        ].join(" ")}
      >
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(255,255,255,0.08),transparent_32%),radial-gradient(circle_at_bottom_right,rgba(148,163,184,0.12),transparent_30%)]" />
        <div
          className={`absolute inset-0 transition-opacity duration-300 ${
            stage === "bad" ? "opacity-100" : "opacity-0"
          }`}
          style={{
            backgroundImage:
              "linear-gradient(90deg, rgba(244,63,94,0) 0%, rgba(244,63,94,0.16) 30%, rgba(255,255,255,0.05) 50%, rgba(244,63,94,0.12) 75%, rgba(244,63,94,0) 100%)",
            transform: `translateX(${glitchSeed % 2 === 0 ? "-1.5%" : "1.5%"})`,
          }}
        />

        <div className="relative">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="text-[0.72rem] font-benderBold tracking-[0.38em] text-white/45">SEALED ENTRY</div>
              <div className="mt-3 text-[2rem] font-benderBold tracking-[0.08em] text-white portrait:text-[1.55rem]">
                Access Control Chamber
              </div>
              <p className="mt-4 max-w-[38rem] text-[1rem] leading-8 text-white/72">
                输入密钥后会进行本地校验、退噪和解封，再落正文。这里仍是前端弱加密，只承担入口控制，不承担真正保密。
              </p>
            </div>

            <div className="rounded-full border border-slate-200/20 bg-slate-200/10 px-4 py-2 text-[0.72rem] font-benderBold tracking-[0.32em] text-slate-100">
              {stage === "bad" ? glitchLabel : statusLine}
            </div>
          </div>

          <div className="mt-8 rounded-[1.4rem] border border-white/10 bg-black/30 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="text-[0.72rem] font-benderBold tracking-[0.34em] text-white/45">UNSEAL PROGRESS</div>
              <div className="text-[0.72rem] font-benderBold tracking-[0.28em] text-white/55">{String(progress).padStart(2, "0")}%</div>
            </div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/8">
              <div
                className={`h-full rounded-full transition-all duration-300 ${
                  stage === "bad" ? "bg-rose-300" : "bg-gradient-to-r from-sky-300 via-cyan-300 to-slate-100"
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="mt-4 text-[0.9rem] leading-7 text-white/68">
              {hint ?? "输入密码后开始解封。"}
            </div>
          </div>

          <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
            <input
              type="password"
              value={pw}
              onChange={(event) => resetSignal(event.target.value)}
              placeholder="输入密钥"
              className="h-[3.5rem] flex-1 rounded-[1.1rem] border border-white/10 bg-black/40 px-4 text-white outline-none transition-colors duration-300 focus:border-sky-300/35"
              onKeyDown={(event) => {
                if (event.key !== "Enter") return;
                event.preventDefault();
                void onDecrypt();
              }}
            />

            <button
              type="button"
              onClick={() => void onDecrypt()}
              disabled={loading || !pw.trim()}
              className="h-[3.5rem] rounded-[1.1rem] border border-sky-300/20 bg-sky-300/12 px-5 text-[0.82rem] font-benderBold tracking-[0.28em] text-sky-100 transition-colors duration-300 hover:bg-sky-300/20 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? "UNSEALING..." : "BEGIN UNSEAL"}
            </button>
          </div>

          {err && <div className="mt-4 text-[0.9rem] text-rose-200">{err}</div>}
        </div>
      </div>
    </section>
  );
}
