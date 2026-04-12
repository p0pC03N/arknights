import { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { readyToTouch, viewIndex } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";
import arknightsConfig from "../../../arknights.config";
import EncryptedArticle, { type EncryptedPayload } from "../../components/EncryptedArticle";

type MediaArticle = NonNullable<NonNullable<typeof arknightsConfig.rootPage.MEDIA>["articles"]>[number];

const payloadModules = import.meta.glob<{ default: EncryptedPayload }>("/src/content/secret/*.payload.json", { eager: true });
const payloadMap = Object.fromEntries(
  Object.entries(payloadModules).map(([path, mod]) => {
    const file = path.split("/").pop() ?? "";
    return [file.replace(/\.payload\.json$/i, ""), mod.default];
  }),
) as Record<string, EncryptedPayload>;

function getArticleId(article?: MediaArticle) {
  if (!article) return "secret";
  if (article.secretId) return String(article.secretId);
  const href = String(article.href ?? "");
  return href.split("?")[0].split("#")[0].split("/").filter(Boolean).pop() ?? "secret";
}

const VISUAL_ACCENTS = [
  {
    glow: "rgba(56,189,248,0.28)",
    gradient:
      "radial-gradient(circle at 30% 24%, rgba(56,189,248,.22), transparent 20%), radial-gradient(circle at 72% 64%, rgba(186,230,253,.12), transparent 22%), linear-gradient(140deg, rgba(2,6,23,.2), rgba(2,6,23,.74))",
  },
  {
    glow: "rgba(125,211,252,0.3)",
    gradient:
      "radial-gradient(circle at 38% 34%, rgba(34,211,238,.2), transparent 18%), radial-gradient(circle at 66% 58%, rgba(99,102,241,.12), transparent 22%), linear-gradient(140deg, rgba(2,6,23,.2), rgba(2,6,23,.74))",
  },
  {
    glow: "rgba(248,250,252,0.22)",
    gradient:
      "radial-gradient(circle at 35% 28%, rgba(248,250,252,.16), transparent 18%), radial-gradient(circle at 70% 56%, rgba(148,163,184,.12), transparent 20%), linear-gradient(140deg, rgba(2,6,23,.2), rgba(2,6,23,.74))",
  },
];

export default function Media() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const base = import.meta.env.BASE_URL;
  const media = useMemo(() => arknightsConfig?.rootPage?.MEDIA, []);
  const rightImage = useMemo(() => media?.rightImage ?? `${base}images/terra/right.jpg`, [base, media]);
  const articles = useMemo(() => media?.articles ?? [], [media]);

  useEffect(() => {
    const isActive = $viewIndex === 4 && $readyToTouch;
    if (isActive) directions.set({ top: false, right: true, bottom: true, left: false });
    setActive(isActive);
  }, [$readyToTouch, $viewIndex]);

  const selectedArticle =
    articles.find((article) => getArticleId(article as MediaArticle) === selectedId) ?? null;
  const selectedPayload = selectedArticle ? payloadMap[getArticleId(selectedArticle as MediaArticle)] : null;
  const accent = VISUAL_ACCENTS[(selectedArticle ? articles.indexOf(selectedArticle) : 0) % VISUAL_ACCENTS.length];

  return (
    <div
      id="media"
      className={`absolute left-auto right-0 top-0 h-full w-[100vw] max-w-[180rem] transition-all duration-1000 ${
        active ? "visible opacity-100" : "invisible opacity-0"
      }`}
    >
      <div className="relative h-full w-full overflow-hidden bg-[#03070b]">
        <div className="absolute inset-0 bg-[linear-gradient(120deg,rgba(2,6,23,.92),rgba(2,6,23,.82)_45%,rgba(2,6,23,.94))]" />
        <div className="absolute inset-0 panel-grid opacity-[0.16]" />

        <div className="absolute inset-x-[4.5rem] top-[8.75rem] bottom-[2.5rem] grid grid-cols-[minmax(17rem,26rem)_minmax(0,1fr)] gap-6 portrait:inset-x-[1.25rem] portrait:top-[8.75rem] portrait:grid-cols-1">
          <aside className="relative overflow-hidden rounded-[1.7rem] border border-white/10 bg-black/35 panel-grid panel-noise backdrop-blur-md glow-frame">
            <div className="border-b border-white/10 px-6 py-5">
              <div className="text-[0.72rem] font-benderBold tracking-[0.38em] text-white/45">SEALED CENTER</div>
              <div className="mt-2 text-[2rem] font-benderBold tracking-[0.08em] text-white">{"\u5c01\u5b58"}</div>
            </div>

            <nav className="h-[calc(100%-6.5rem)] overflow-y-auto px-4 py-4">
              <div className="space-y-3">
                {articles.map((article, index) => {
                  const articleId = getArticleId(article as MediaArticle);
                  const selected = articleId === selectedId;

                  return (
                    <button
                      key={`${article.href}-${index}`}
                      type="button"
                      onClick={() => setSelectedId(articleId)}
                      className={`group relative block w-full overflow-hidden rounded-[1.1rem] border bg-black/35 px-4 py-4 text-left text-inherit transition-all duration-300 panel-grid panel-noise ${
                        selected ? "border-cyan-200/28 bg-cyan-200/8 text-white glow-blue" : "border-white/10 text-white/72 hover:border-white/25 hover:text-white"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="text-[0.66rem] font-benderBold tracking-[0.3em] text-white/38">SECRET // {String(index + 1).padStart(2, "0")}</div>
                          <div className="mt-2 text-[1rem] font-benderBold tracking-[0.06em]">{article.title}</div>
                          {article.date && <div className="mt-2 text-[0.78rem] tracking-[0.18em] text-white/42">{article.date}</div>}
                        </div>
                        <div className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[0.62rem] font-benderBold tracking-[0.26em] text-white/55">
                          {article.locked ? "LOCKED" : "OPEN"}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </nav>
          </aside>

          <section className="relative overflow-hidden rounded-[1.9rem] border border-white/10 bg-black/35 panel-grid panel-noise backdrop-blur-md glow-frame">
            <div className="absolute inset-0 bg-cover bg-center opacity-24" style={{ backgroundImage: `url(${rightImage})` }} />
            <div className="absolute inset-0 transition-all duration-500" style={{ backgroundImage: accent.gradient }} />
            <div className="absolute inset-0 scanlines opacity-45" />
            <div className="absolute inset-[2.4rem] rounded-[1.8rem] border border-white/10 bg-black/14 portrait:inset-[1rem]" />
            <div className="absolute inset-[4.6rem] rounded-[1.5rem] border border-cyan-100/10 portrait:inset-[1.75rem]" />
            <div className="absolute left-1/2 top-1/2 h-[15rem] w-[15rem] -translate-x-1/2 -translate-y-1/2 rounded-full border border-cyan-100/10 portrait:h-[10rem] portrait:w-[10rem]" />
            <div
              className="absolute left-1/2 top-1/2 h-[11rem] w-[11rem] -translate-x-1/2 -translate-y-1/2 rounded-full border portrait:h-[7rem] portrait:w-[7rem]"
              style={{ borderColor: accent.glow, boxShadow: `0 0 42px ${accent.glow}` }}
            />
            <div className="absolute inset-x-[12%] top-1/2 h-px -translate-y-1/2 bg-white/14" />
            <div className="absolute inset-y-[14%] left-1/2 w-px -translate-x-1/2 bg-white/10" />
            <div className="absolute inset-[16%] border border-white/8 portrait:inset-[11%]" />
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_0%,transparent_42%,rgba(2,6,23,.58)_100%)]" />

            <div
              className={`absolute inset-0 z-[2] transition-all duration-500 ${
                selectedArticle ? "translate-x-0 opacity-100" : "translate-x-[10%] opacity-0 pointer-events-none"
              }`}
            >
              <div className="flex h-full flex-col bg-[linear-gradient(180deg,rgba(3,8,13,.74),rgba(3,8,13,.94))] backdrop-blur-md">
                <div className="flex items-center justify-between gap-4 border-b border-white/10 px-5 py-4 portrait:px-4">
                  <div>
                    <div className="text-[0.68rem] font-benderBold tracking-[0.32em] text-white/42">VERIFY ENTRY</div>
                    <div className="mt-2 text-[1.25rem] font-benderBold tracking-[0.08em] text-white">
                      {selectedArticle?.title ?? ""}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => setSelectedId(null)}
                    className="rounded-full border border-white/10 bg-black/25 px-3 py-2 text-[0.68rem] font-benderBold tracking-[0.28em] text-white/68 transition-colors duration-300 hover:border-white/20 hover:text-white"
                  >
                    CLOSE
                  </button>
                </div>

                <div className="min-h-0 flex-1 p-5 portrait:p-4">
                  {selectedArticle && selectedPayload ? (
                    <EncryptedArticle
                      key={getArticleId(selectedArticle as MediaArticle)}
                      presentation="panel"
                      payload={selectedPayload}
                      title={selectedArticle.title}
                      hint={selectedArticle.keyHint}
                    />
                  ) : (
                    <div className="flex h-full items-center justify-center rounded-[1.6rem] border border-white/10 bg-black/24 text-white/55">
                      NO PAYLOAD
                    </div>
                  )}
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
