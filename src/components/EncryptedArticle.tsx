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

function stripHtmlTags(value: string) {
  return value
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function chunkText(value: string, size: number) {
  const chunks: string[] = [];
  for (let index = 0; index < value.length; index += size) {
    chunks.push(value.slice(index, index + size));
  }
  return chunks.filter(Boolean);
}

function scrambleLine(line: string, revealRatio: number) {
  const glyphs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>/[]{}#*%$";
  return line
    .split("")
    .map((char, index) => {
      if (char === " ") return " ";
      const threshold = index / Math.max(1, line.length - 1);
      if (threshold < revealRatio) return char;
      return glyphs[(index * 7 + Math.floor(revealRatio * 31)) % glyphs.length];
    })
    .join("");
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
  const { payload, hint } = props;

  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [stage, setStage] = useState<UnlockStage>("locked");
  const [statusLine, setStatusLine] = useState("WAITING FOR KEY");
  const [progress, setProgress] = useState(0);
  const [loading, setLoading] = useState(false);
  const [warningSeed, setWarningSeed] = useState(0);
  const [scrambleLines, setScrambleLines] = useState<string[]>([]);

  const plainPreview = useMemo(() => stripHtmlTags(html ?? ""), [html]);

  useEffect(() => {
    if (stage !== "revealing" || !html) return undefined;

    const sourceLines = chunkText(plainPreview, 28).slice(0, 7);
    if (sourceLines.length === 0) {
      setStage("unlocked");
      return undefined;
    }

    let tick = 0;
    const totalTicks = 14;

    setScrambleLines(sourceLines.map((line) => scrambleLine(line, 0)));

    const timer = window.setInterval(() => {
      tick += 1;
      const ratio = Math.min(1, tick / totalTicks);
      setScrambleLines(sourceLines.map((line) => scrambleLine(line, ratio)));

      if (tick >= totalTicks) {
        window.clearInterval(timer);
        setStage("unlocked");
      }
    }, 70);

    return () => window.clearInterval(timer);
  }, [html, plainPreview, stage]);

  async function onDecrypt() {
    const password = pw.trim();
    if (!password) return;

    setErr(null);
    setLoading(true);
    setStage("verifying");
    setStatusLine("HASHING KEY SIGNAL");
    setProgress(18);

    try {
      await wait(160);
      setStatusLine("VERIFYING ARCHIVE SIGNATURE");
      setProgress(41);

      const out = await decryptEncryptedPayload(payload, password);

      setStatusLine("REDUCING VISUAL NOISE");
      setProgress(73);
      await wait(180);

      setHtml(out);
      setStage("revealing");
      setStatusLine("RESTORING TEXT LAYERS");
      setProgress(100);
    } catch {
      setStage("bad");
      setStatusLine("UNAUTHORIZED");
      setErr("档案无权查看");
      setProgress(6);
      setWarningSeed((value) => value + 1);
      setHtml(null);
    } finally {
      setLoading(false);
    }
  }

  function resetSignal(nextValue: string) {
    setPw(nextValue);
    setErr(null);
    setStage("locked");
    setStatusLine("WAITING FOR KEY");
    setProgress(0);
    setScrambleLines([]);
  }

  if (stage === "unlocked" && html) {
    return (
      <section className="mx-auto max-w-[78rem] pb-12">
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

          <article className="sealed-article-body px-6 py-7" dangerouslySetInnerHTML={{ __html: html }} />
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
          className={`absolute inset-0 transition-opacity duration-300 ${stage === "bad" ? "opacity-100" : "opacity-0"}`}
          style={{
            animation: stage === "bad" ? "contaminated .55s ease forwards" : undefined,
            backgroundImage:
              "repeating-linear-gradient(180deg, rgba(244,63,94,0.18) 0, rgba(244,63,94,0.18) 2px, transparent 2px, transparent 10px), linear-gradient(90deg, rgba(244,63,94,0) 0%, rgba(244,63,94,0.2) 35%, rgba(34,211,238,0.1) 58%, rgba(244,63,94,0.16) 80%, rgba(244,63,94,0) 100%)",
          }}
        />

        {stage === "revealing" && (
          <div className="absolute inset-0 pointer-events-none overflow-hidden">
            <div className="absolute inset-y-0 left-[-20%] w-[22%] bg-[linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent)]" style={{ animation: "decode-sweep .9s ease-out forwards" }} />
          </div>
        )}

        <div className="relative">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="text-[0.72rem] font-benderBold tracking-[0.38em] text-white/45">SEALED ENTRY</div>
              <div className="mt-3 text-[2rem] font-benderBold tracking-[0.08em] text-white portrait:text-[1.55rem]">
                Access Control Chamber
              </div>
            </div>

            <div className="rounded-full border border-slate-200/20 bg-slate-200/10 px-4 py-2 text-[0.72rem] font-benderBold tracking-[0.32em] text-slate-100">
              {statusLine}
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
              {hint ?? "输入密码后开始验证。"}
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

          {stage === "revealing" && (
            <div className="mt-6 rounded-[1.2rem] border border-white/10 bg-black/35 p-4">
              <div className="mb-3 text-[0.66rem] font-benderBold tracking-[0.3em] text-white/38">RESTORING TEXT</div>
              <div className="space-y-2 font-mono text-[0.82rem] leading-6 text-sky-100/75">
                {scrambleLines.map((line, index) => (
                  <div key={`${index}-${line.slice(0, 6)}`} style={{ animation: "scramble-blink 1.2s ease-in-out infinite" }}>
                    {line}
                  </div>
                ))}
              </div>
            </div>
          )}

          {stage === "bad" && (
            <div
              className="mt-6 rounded-[1.2rem] border border-rose-300/30 bg-rose-400/8 px-4 py-4 text-center"
              key={warningSeed}
              style={{ animation: "warning-pulse .45s ease forwards" }}
            >
              <div className="font-benderBold tracking-[0.35em] text-rose-100">---⚠⚠⚠--- WARNING --- 档案无权查看 ---</div>
            </div>
          )}

          {err && <div className="mt-4 text-[0.9rem] text-rose-200">{err}</div>}
        </div>
      </div>
    </section>
  );
}
