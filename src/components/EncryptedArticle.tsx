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

function decodeHtmlEntities(value: string) {
  const textarea = document.createElement("textarea");
  textarea.innerHTML = value;
  return textarea.value;
}

function stripHtmlTags(value: string) {
  return decodeHtmlEntities(
    value
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<(br|\/p|\/li|\/h[1-6]|\/blockquote)[^>]*>/gi, "\n")
      .replace(/<[^>]+>/g, " ")
      .replace(/[ \t]+\n/g, "\n")
      .replace(/\n{3,}/g, "\n\n")
      .replace(/[ \t]{2,}/g, " ")
      .trim(),
  );
}

function wrapPlainText(value: string, width: number) {
  const lines: string[] = [];
  const paragraphs = value.split(/\n+/).map((item) => item.trim()).filter(Boolean);

  paragraphs.forEach((paragraph, paragraphIndex) => {
    let current = "";
    let currentWidth = 0;

    Array.from(paragraph).forEach((char) => {
      const charWidth = /[\u0000-\u00ff]/.test(char) ? 1 : 2;

      if (currentWidth + charWidth > width && current) {
        lines.push(current.trimEnd());
        current = char;
        currentWidth = charWidth;
        return;
      }

      current += char;
      currentWidth += charWidth;
    });

    if (current) {
      lines.push(current.trimEnd());
    }

    if (paragraphIndex !== paragraphs.length - 1) {
      lines.push("");
    }
  });

  return lines.length > 0 ? lines : [value];
}

function scrambleLine(line: string, revealRatio: number, salt: number) {
  const glyphs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>/[]{}#*%$&@";

  return line
    .split("")
    .map((char, index) => {
      if (char === " ") return " ";
      if (revealRatio >= 1 || index / Math.max(1, line.length - 1) < revealRatio) return char;
      return glyphs[(index * 17 + salt * 11) % glyphs.length];
    })
    .join("");
}

function createGlitchBlocks(seed: number) {
  const palette = [
    "rgba(255,0,90,.88)",
    "rgba(0,245,255,.82)",
    "rgba(255,224,0,.86)",
    "rgba(130,0,255,.82)",
    "rgba(255,255,255,.94)",
  ];

  return Array.from({ length: 18 }, (_, index) => {
    const left = (seed * 17 + index * 29) % 92;
    const top = (seed * 11 + index * 19) % 82;
    const width = 8 + ((seed + index * 7) % 18);
    const height = 4 + ((seed * 3 + index * 5) % 12);
    const color = palette[(seed + index) % palette.length];

    return {
      id: `${seed}-${index}`,
      style: {
        left: `${left}%`,
        top: `${top}%`,
        width: `${width}%`,
        height: `${height}%`,
        background: color,
        animationDelay: `${(index % 7) * 0.03}s`,
        animationDuration: `${0.22 + (index % 4) * 0.08}s`,
      },
    };
  });
}

export function b64ToU8(b64: string): Uint8Array {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) u8[i] = bin.charCodeAt(i);
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

export async function decryptEncryptedPayload(payload: EncryptedPayload, password: string): Promise<string> {
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
  const [html, setHtml] = useState<string | null>(null);
  const [stage, setStage] = useState<UnlockStage>("locked");
  const [statusLine, setStatusLine] = useState("WAITING");
  const [progress, setProgress] = useState(0);
  const [loading, setLoading] = useState(false);
  const [warningSeed, setWarningSeed] = useState(0);
  const [sourceLines, setSourceLines] = useState<string[]>([]);
  const [displayLines, setDisplayLines] = useState<string[]>([]);

  const glitchBlocks = useMemo(() => createGlitchBlocks(warningSeed), [warningSeed]);

  useEffect(() => {
    if (stage !== "revealing" || sourceLines.length === 0) return undefined;

    let tick = 0;
    let settleTimer: number | undefined;
    const total = sourceLines.length;

    setDisplayLines(sourceLines.map((line, index) => scrambleLine(line, 0, index * 3 + warningSeed)));

    const timer = window.setInterval(() => {
      tick += 1;
      const revealLine = Math.min(total, tick * 2);

      setDisplayLines(
        sourceLines.map((line, index) => {
          if (index > revealLine) {
            return scrambleLine(line, 0, tick + index * 5);
          }

          const revealRatio = Math.min(1, Math.max(0, (tick - index * 0.34) / 4.2));
          return scrambleLine(line, revealRatio, tick + index * 7);
        }),
      );

      if (revealLine >= total) {
        window.clearInterval(timer);
        settleTimer = window.setTimeout(() => {
          setStage("unlocked");
          setStatusLine("VERIFIED");
        }, 220);
      }
    }, 36);

    return () => {
      window.clearInterval(timer);
      if (settleTimer) window.clearTimeout(settleTimer);
    };
  }, [sourceLines, stage, warningSeed]);

  function resetSignal(nextValue: string) {
    setPw(nextValue);
    setStage("locked");
    setStatusLine("WAITING");
    setProgress(0);
    setDisplayLines([]);
  }

  async function onDecrypt() {
    const password = pw.trim();
    if (!password) return;

    setLoading(true);
    setStage("verifying");
    setStatusLine("CHECKING");
    setProgress(18);

    try {
      await wait(120);
      setStatusLine("MATCHING");
      setProgress(44);

      const out = await decryptEncryptedPayload(payload, password);
      const previewLines = wrapPlainText(stripHtmlTags(out), 38);

      setStatusLine("DECODING");
      setProgress(82);
      await wait(160);

      setHtml(out);
      setSourceLines(previewLines);
      setStage("revealing");
      setProgress(100);
    } catch {
      setStage("bad");
      setStatusLine("LOCKED OUT");
      setProgress(4);
      setHtml(null);
      setSourceLines([]);
      setDisplayLines([]);
      setWarningSeed((value) => value + 1);
    } finally {
      setLoading(false);
    }
  }

  if (stage === "unlocked" && html) {
    return (
      <section className="mx-auto max-w-[82rem] pb-12">
        <div className="overflow-hidden rounded-[1.8rem] border border-slate-200/15 bg-[#05070a]/92 panel-grid panel-noise glow-frame">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 px-6 py-4">
            <div>
              <div className="text-[0.72rem] font-benderBold tracking-[0.35em] text-white/45">SEALED ARCHIVE</div>
              <div className="mt-2 text-[1.4rem] font-benderBold tracking-[0.08em] text-white">{"\u6863\u6848\u89e3\u5c01"}</div>
            </div>
            <div className="rounded-full border border-slate-200/20 bg-slate-200/10 px-4 py-2 text-[0.72rem] font-benderBold tracking-[0.32em] text-slate-100">
              ACCESS // VERIFIED
            </div>
          </div>

          <article className="sealed-article-body px-6 py-7 animate-[article-fade-in_.45s_ease]" dangerouslySetInnerHTML={{ __html: html }} />
        </div>
      </section>
    );
  }

  return (
    <>
      <section className="mx-auto max-w-[74rem] pb-12">
        <div
          className={[
            "relative overflow-hidden rounded-[2rem] border border-slate-200/14 bg-[#05070a]/92 px-6 py-6 panel-grid panel-noise glow-frame backdrop-blur-md transition-all duration-300",
            stage === "verifying" || stage === "revealing" ? "scanlines" : "",
            stage === "bad" ? "archive-shake border-rose-300/30" : "",
          ].join(" ")}
        >
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_16%,rgba(255,255,255,.08),transparent_24%),radial-gradient(circle_at_76%_22%,rgba(255,255,255,.05),transparent_20%),linear-gradient(180deg,rgba(255,255,255,.02),rgba(2,6,23,.18)_30%,rgba(2,6,23,.5))]" />

          {stage === "revealing" && (
            <div className="pointer-events-none absolute inset-0 overflow-hidden">
              <div className="absolute inset-y-0 left-[-18%] w-[20%] bg-[linear-gradient(90deg,transparent,rgba(255,255,255,.32),transparent)]" style={{ animation: "decode-sweep 1.1s ease-out forwards" }} />
            </div>
          )}

          <div className="relative">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="text-[0.72rem] font-benderBold tracking-[0.38em] text-white/45">SEALED ENTRY</div>
                <div className="mt-3 text-[2rem] font-benderBold tracking-[0.08em] text-white portrait:text-[1.55rem]">
                  {"\u6863\u6848\u9a8c\u8bc1"}
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
              <div className="mt-4 text-[0.9rem] leading-7 text-white/68">{hint ?? "\u8f93\u5165\u5bc6\u7801\u540e\u5f00\u59cb\u9a8c\u8bc1\u3002"}</div>
            </div>

            <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
              <input
                type="password"
                value={pw}
                onChange={(event) => resetSignal(event.target.value)}
                placeholder="\u8f93\u5165\u5bc6\u94a5"
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
              <div className="mt-8 overflow-hidden rounded-[1.45rem] border border-white/10 bg-black/42">
                <div className="border-b border-white/10 px-5 py-4">
                  <div className="text-[0.66rem] font-benderBold tracking-[0.3em] text-white/38">TEXT RESTORE</div>
                </div>
                <div className="relative overflow-hidden px-5 py-5">
                  <div className="absolute inset-0 panel-grid opacity-[0.08]" />
                  <div className="relative space-y-1 font-mono text-[0.84rem] leading-6 text-sky-100/78">
                    {displayLines.map((line, index) => (
                      <div
                        key={`${index}-${line.slice(0, 12)}`}
                        className="origin-left transition-all duration-300"
                        style={{ animation: "decode-line-in .28s ease" }}
                      >
                        {line || "\u00A0"}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {stage === "bad" && (
        <>
          <div className="pointer-events-none fixed inset-0 z-[70] overflow-hidden">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(255,255,255,.04),transparent_42%)] opacity-50" />
            {glitchBlocks.map((block) => (
              <span key={block.id} className="gpu-glitch-block absolute" style={block.style} />
            ))}
          </div>

          <div key={warningSeed} className="pointer-events-none fixed inset-x-0 top-1/2 z-[80] -translate-y-1/2">
            <div className="warning-banner mx-auto flex min-h-[11rem] w-full max-w-none items-center justify-center border-y border-white/20 bg-[linear-gradient(90deg,rgba(0,0,0,.72),rgba(17,24,39,.82),rgba(0,0,0,.72))] px-6 py-5 text-center backdrop-blur-md">
              <div className="space-y-1 font-benderBold text-rose-100">
                <div className="text-[1.15rem] tracking-[0.5em]">---⚠⚠⚠---</div>
                <div className="text-[1.05rem] tracking-[0.42em]">---warning---</div>
                <div className="text-[2rem] tracking-[0.18em] portrait:text-[1.45rem]">---{"\u6863\u6848\u65e0\u6743\u67e5\u770b"}---</div>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  );
}
