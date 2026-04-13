import { useEffect, useMemo, useRef, useState, type MutableRefObject } from "react";

export type EncryptedPayload = {
  v: 1;
  algo: "AES-GCM";
  iter: number;
  salt_b64: string;
  iv_b64: string;
  ct_b64: string;
};

type UnlockStage = "locked" | "verifying" | "revealing" | "unlocked" | "bad";
type Presentation = "page" | "panel";

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

    if (current) lines.push(current.trimEnd());
    if (paragraphIndex !== paragraphs.length - 1) lines.push("");
  });

  return lines.length > 0 ? lines : [value];
}

function scrambleLine(line: string, revealRatio: number, salt: number) {
  const glyphs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>/[]{}#*%$&@";

  return Array.from(line)
    .map((char, index) => {
      if (char === " ") return " ";
      if (revealRatio >= 1 || index / Math.max(1, line.length - 1) < revealRatio) return char;
      return glyphs[(index * 17 + salt * 13) % glyphs.length];
    })
    .join("");
}

function createGlitchBlocks(seed: number) {
  const palette = [
    "rgba(255,57,57,.92)",
    "rgba(255,224,0,.95)",
    "rgba(0,245,255,.84)",
    "rgba(130,0,255,.8)",
    "rgba(255,255,255,.96)",
  ];

  return Array.from({ length: 20 }, (_, index) => ({
    id: `${seed}-${index}`,
    style: {
      left: `${(seed * 17 + index * 27) % 92}%`,
      top: `${(seed * 9 + index * 21) % 84}%`,
      width: `${8 + ((seed + index * 7) % 18)}%`,
      height: `${4 + ((seed * 3 + index * 5) % 12)}%`,
      background: palette[(seed + index) % palette.length],
      animationDelay: `${(index % 6) * 0.035}s`,
      animationDuration: `${0.26 + (index % 4) * 0.08}s`,
    },
  }));
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

function ArticleViewport({
  title,
  statusLine,
  html,
  revealing,
  displayLines,
  presentation,
  scrollRef,
}: {
  title: string;
  statusLine: string;
  html: string | null;
  revealing: boolean;
  displayLines: string[];
  presentation: Presentation;
  scrollRef: MutableRefObject<HTMLDivElement | null>;
}) {
  return (
    <div className={`relative ${presentation === "panel" ? "flex h-full flex-col" : ""}`}>
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/10 px-6 py-4">
        <div>
          <div className="text-[0.72rem] font-benderBold tracking-[0.36em] text-white/42">SEALED ARCHIVE</div>
          <div className="mt-2 text-[1.42rem] font-benderBold tracking-[0.08em] text-white">{title}</div>
        </div>

        <div className="rounded-full border border-cyan-200/18 bg-cyan-200/8 px-4 py-2 text-[0.72rem] font-n15eMedium tracking-[0.34em] text-cyan-100/90">
          {statusLine}
        </div>
      </div>

      <div
        ref={scrollRef}
        data-root-scroll-lock="true"
        className={`min-h-0 overscroll-contain ${presentation === "panel" ? "flex-1 overflow-y-auto px-6 py-6" : "px-6 py-6"}`}
      >
        <div className="relative">
          <article
            className={`sealed-article-body ${presentation === "panel" ? "sealed-article-body-panel" : ""} ${
              revealing ? "sealed-article-underlay" : "animate-[article-fade-in_.55s_ease]"
            }`}
            dangerouslySetInnerHTML={{ __html: html ?? "" }}
          />

          {revealing ? (
            <div className="pointer-events-none absolute inset-0 z-[2]">
              <div className={`sealed-article-body ${presentation === "panel" ? "sealed-article-body-panel" : ""} sealed-article-scramble-shell sealed-article-scramble`}>
                {displayLines.map((line, index) => (
                  <div key={`${index}-${line.slice(0, 10)}`} className="sealed-article-scramble-line" style={{ animationDelay: `${index * 18}ms` }}>
                    {line || "\u00A0"}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function ValidationViewport({
  hint,
  progress,
  statusLine,
  stage,
  loading,
  pw,
  onChange,
  onSubmit,
}: {
  hint?: string;
  progress: number;
  statusLine: string;
  stage: UnlockStage;
  loading: boolean;
  pw: string;
  onChange: (nextValue: string) => void;
  onSubmit: () => void;
}) {
  return (
    <div className="relative">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/10 px-6 py-4">
        <div>
          <div className="text-[0.72rem] font-benderBold tracking-[0.36em] text-white/42">SEALED ARCHIVE</div>
          <div className="mt-2 text-[1.42rem] font-benderBold tracking-[0.08em] text-white">{"\u6863\u6848\u9a8c\u8bc1"}</div>
        </div>

        <div className="rounded-full border border-cyan-200/18 bg-cyan-200/8 px-4 py-2 text-[0.72rem] font-n15eMedium tracking-[0.34em] text-cyan-100/90">
          {statusLine}
        </div>
      </div>

      <div className="px-6 pb-6 pt-6">
        <div className="rounded-[1.35rem] border border-white/10 bg-black/28 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-[0.72rem] font-benderBold tracking-[0.34em] text-white/45">UNSEAL PROGRESS</div>
            <div className="text-[0.72rem] font-benderBold tracking-[0.28em] text-white/55">{String(progress).padStart(2, "0")}%</div>
          </div>
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/8">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                stage === "bad" ? "bg-[#ffb800]" : "bg-gradient-to-r from-sky-300 via-cyan-300 to-slate-100"
              }`}
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="mt-4 text-[0.9rem] leading-7 text-white/66">{hint ?? "\u8f93\u5165\u5bc6\u7801\u540e\u5f00\u59cb\u9a8c\u8bc1\u3002"}</div>
        </div>

        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <input
            type="password"
            value={pw}
            onChange={(event) => onChange(event.target.value)}
            placeholder="\u8f93\u5165\u5bc6\u94a5"
            className="h-[3.5rem] flex-1 rounded-[1.1rem] border border-white/10 bg-black/40 px-4 text-white outline-none transition-colors duration-300 focus:border-cyan-300/35"
            onKeyDown={(event) => {
              if (event.key !== "Enter") return;
              event.preventDefault();
              onSubmit();
            }}
          />

          <button
            type="button"
            onClick={onSubmit}
            disabled={loading || !pw.trim()}
            className="h-[3.5rem] rounded-[1.1rem] border border-cyan-300/22 bg-cyan-300/12 px-5 text-[0.82rem] font-benderBold tracking-[0.28em] text-cyan-100 transition-colors duration-300 hover:bg-cyan-300/20 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "UNSEALING..." : "BEGIN UNSEAL"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function EncryptedArticle(props: {
  payload: EncryptedPayload;
  hint?: string;
  rememberKey?: string;
  autoDecrypt?: boolean;
  presentation?: Presentation;
  title?: string;
}) {
  const { payload, hint, presentation = "page", title } = props;

  const [pw, setPw] = useState("");
  const [html, setHtml] = useState<string | null>(null);
  const [stage, setStage] = useState<UnlockStage>("locked");
  const [statusLine, setStatusLine] = useState("WAITING");
  const [progress, setProgress] = useState(0);
  const [loading, setLoading] = useState(false);
  const [warningSeed, setWarningSeed] = useState(0);
  const [sourceLines, setSourceLines] = useState<string[]>([]);
  const [displayLines, setDisplayLines] = useState<string[]>([]);
  const articleScrollRef = useRef<HTMLDivElement | null>(null);

  const glitchBlocks = useMemo(() => createGlitchBlocks(warningSeed), [warningSeed]);
  const shellClass = presentation === "panel" ? "h-full" : "mx-auto max-w-[82rem] pb-12";
  const cardClass =
    presentation === "panel"
      ? "relative flex h-full flex-col overflow-hidden rounded-[1.8rem] border border-cyan-200/12 bg-[#04070b]/94 panel-grid panel-noise glow-frame backdrop-blur-md"
      : "relative overflow-hidden rounded-[1.8rem] border border-cyan-200/12 bg-[#04070b]/94 panel-grid panel-noise glow-frame backdrop-blur-md";
  const decodeWidth = presentation === "panel" ? 48 : 62;
  const headerTitle = title ?? "\u5c01\u5b58\u6863\u6848";
  const isArticleStage = stage === "revealing" || stage === "unlocked";

  useEffect(() => {
    if (stage !== "revealing" || sourceLines.length === 0) return undefined;

    let tick = 0;
    let startTimer: number | undefined;
    let settleTimer: number | undefined;
    let intervalTimer: number | undefined;
    const lineStagger = 2;
    const decodeDuration = 7;
    const totalTicks = sourceLines.length * lineStagger + decodeDuration + 12;

    articleScrollRef.current?.scrollTo({ top: 0, behavior: "auto" });

    startTimer = window.setTimeout(() => {
      intervalTimer = window.setInterval(() => {
        tick += 1;
        const decodeProgress = Math.min(1, tick / totalTicks);

        setDisplayLines(
          sourceLines.map((line, index) => {
            if (!line) return "";
            const revealRatio = Math.min(1, Math.max(0, (tick - index * lineStagger) / decodeDuration));
            return scrambleLine(line, revealRatio, tick + index * 9);
          }),
        );

        window.requestAnimationFrame(() => {
          const viewport = articleScrollRef.current;
          if (!viewport) return;
          const maxScroll = Math.max(0, viewport.scrollHeight - viewport.clientHeight);
          viewport.scrollTop = maxScroll * Math.min(0.34, decodeProgress * 0.34);
        });

        if (tick >= totalTicks) {
          if (intervalTimer) window.clearInterval(intervalTimer);
          settleTimer = window.setTimeout(() => {
            setStage("unlocked");
            setStatusLine("VERIFIED");
          }, 160);
        }
      }, 84);
    }, 520);

    return () => {
      if (startTimer) window.clearTimeout(startTimer);
      if (intervalTimer) window.clearInterval(intervalTimer);
      if (settleTimer) window.clearTimeout(settleTimer);
    };
  }, [sourceLines, stage]);

  function resetSignal(nextValue: string) {
    setPw(nextValue);
    setStage("locked");
    setStatusLine("WAITING");
    setProgress(0);
    setDisplayLines([]);
    articleScrollRef.current?.scrollTo({ top: 0, behavior: "auto" });
  }

  async function onDecrypt() {
    const password = pw.trim();
    if (!password) return;

    setLoading(true);
    setStage("verifying");
    setStatusLine("CHECKING");
    setProgress(16);

    try {
      await wait(160);
      setStatusLine("MATCHING");
      setProgress(44);

      const out = await decryptEncryptedPayload(payload, password);
      const previewLines = wrapPlainText(stripHtmlTags(out), decodeWidth);

      setStatusLine("DECODING");
      setProgress(82);
      await wait(220);

      setHtml(out);
      setSourceLines(previewLines);
      setDisplayLines(previewLines.map((line, index) => scrambleLine(line, 0, index * 7 + warningSeed)));
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

  return (
    <section className={shellClass}>
      <div className={cardClass}>
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_16%,rgba(255,255,255,.08),transparent_24%),radial-gradient(circle_at_76%_22%,rgba(56,189,248,.08),transparent_20%),linear-gradient(180deg,rgba(255,255,255,.02),rgba(2,6,23,.16)_30%,rgba(2,6,23,.52))]" />

        {stage === "revealing" && (
          <div className="pointer-events-none absolute inset-0 overflow-hidden">
            <div className="absolute inset-y-0 left-[-18%] w-[18%] bg-[linear-gradient(90deg,transparent,rgba(255,255,255,.34),transparent)]" style={{ animation: "decode-sweep 1.6s ease-out forwards" }} />
          </div>
        )}

        <div className={`relative ${presentation === "panel" ? "flex h-full flex-col" : ""}`}>
          {isArticleStage ? (
            <ArticleViewport
              title={headerTitle}
              statusLine={stage === "revealing" ? "DECODING" : statusLine}
              html={html}
              revealing={stage === "revealing"}
              displayLines={displayLines}
              presentation={presentation}
              scrollRef={articleScrollRef}
            />
          ) : (
            <ValidationViewport
              hint={hint}
              progress={progress}
              statusLine={statusLine}
              stage={stage}
              loading={loading}
              pw={pw}
              onChange={resetSignal}
              onSubmit={() => void onDecrypt()}
            />
          )}
        </div>

        {stage === "bad" && (
          <div className="pointer-events-none absolute inset-0 z-[4] overflow-hidden">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(255,255,255,.05),transparent_42%)] opacity-55" />
            {glitchBlocks.map((block) => (
              <span key={block.id} className="gpu-glitch-block absolute" style={block.style} />
            ))}

            <div key={warningSeed} className="absolute inset-x-0 top-1/2 -translate-y-1/2 px-0">
              <div className="warning-banner mx-auto flex min-h-[10.5rem] w-full items-center justify-center border-y border-[#ffe699]/80 bg-[#ffcf33]/96 px-6 py-5 text-center shadow-[0_0_48px_rgba(255,207,51,.28)]">
                <div className="space-y-1 font-n15eMedium text-[#a4001a]">
                  <div className="text-[1.15rem] tracking-[0.5em]">---⚠⚠⚠---</div>
                  <div className="text-[1.05rem] tracking-[0.42em]">---warning---</div>
                  <div className="text-[2rem] tracking-[0.18em] portrait:text-[1.45rem]">---{"\u6863\u6848\u65e0\u6743\u67e5\u770b"}---</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
