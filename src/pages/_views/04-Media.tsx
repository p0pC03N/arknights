import { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { readyToTouch, viewIndex } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";
import arknightsConfig from "../../../arknights.config";

type MediaArticle = NonNullable<NonNullable<typeof arknightsConfig.rootPage.MEDIA>["articles"]>[number];

function getArticleId(article?: MediaArticle) {
  if (!article) return "secret";
  if (article.secretId) return String(article.secretId);
  const href = String(article.href ?? "");
  return href.split("?")[0].split("#")[0].split("/").filter(Boolean).pop() ?? "secret";
}

const VISUAL_ACCENTS = [
  {
    glow: "rgba(248,250,252,0.18)",
    gradient:
      "radial-gradient(circle at 34% 34%, rgba(248,250,252,.16), transparent 18%), radial-gradient(circle at 68% 62%, rgba(148,163,184,.14), transparent 20%), linear-gradient(140deg, rgba(2,6,23,.2), rgba(2,6,23,.72))",
  },
  {
    glow: "rgba(125,211,252,0.24)",
    gradient:
      "radial-gradient(circle at 34% 28%, rgba(56,189,248,.22), transparent 18%), radial-gradient(circle at 72% 56%, rgba(186,230,253,.12), transparent 22%), linear-gradient(140deg, rgba(2,6,23,.2), rgba(2,6,23,.72))",
  },
  {
    glow: "rgba(251,191,36,0.22)",
    gradient:
      "radial-gradient(circle at 38% 40%, rgba(250,204,21,.2), transparent 16%), radial-gradient(circle at 72% 54%, rgba(248,250,252,.1), transparent 20%), linear-gradient(140deg, rgba(2,6,23,.2), rgba(2,6,23,.72))",
  },
];

export default function Media() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);

  const base = import.meta.env.BASE_URL;
  const media = useMemo(() => arknightsConfig?.rootPage?.MEDIA, []);
  const rightImage = useMemo(() => media?.rightImage ?? `${base}images/terra/right.jpg`, [base, media]);
  const articles = useMemo(() => media?.articles ?? [], [media]);
  const [activeId, setActiveId] = useState<string>(() => getArticleId(articles[0] as MediaArticle | undefined));

  useEffect(() => {
    const isActive = $viewIndex === 4 && $readyToTouch;
    if (isActive) directions.set({ top: false, right: true, bottom: true, left: false });
    setActive(isActive);
  }, [$readyToTouch, $viewIndex]);

  const activeIndex = Math.max(
    0,
    articles.findIndex((article) => getArticleId(article as MediaArticle) === activeId),
  );
  const accent = VISUAL_ACCENTS[activeIndex % VISUAL_ACCENTS.length];

  return (
    <div
      id="media"
      className={`absolute left-auto right-0 top-0 h-full w-[100vw] max-w-[180rem] transition-all duration-1000 ${
        active ? "visible opacity-100" : "invisible opacity-0"
      }`}
    >
      <div className="relative h-full w-full overflow-hidden bg-[#03070b]">
        <div className="absolute inset-0 bg-[linear-gradient(120deg,rgba(2,6,23,.9),rgba(2,6,23,.8)_45%,rgba(2,6,23,.92))]" />
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
                  const selected = articleId === activeId;

                  return (
                    <a
                      key={`${article.href}-${index}`}
                      href={article.href}
                      target="_self"
                      onMouseEnter={() => setActiveId(articleId)}
                      onFocus={() => setActiveId(articleId)}
                      className={`group relative block overflow-hidden rounded-[1.1rem] border bg-black/35 px-4 py-4 text-inherit no-underline transition-all duration-300 panel-grid panel-noise ${
                        selected ? "border-slate-100/30 bg-slate-200/8 text-white glow-neutral" : "border-white/10 text-white/72 hover:border-white/25 hover:text-white"
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
                    </a>
                  );
                })}
              </div>
            </nav>
          </aside>

          <section className="relative overflow-hidden rounded-[1.9rem] border border-white/10 bg-black/35 panel-grid panel-noise backdrop-blur-md glow-frame portrait:hidden">
            <div className="absolute inset-0 bg-cover bg-center opacity-24" style={{ backgroundImage: `url(${rightImage})` }} />
            <div className="absolute inset-0 transition-all duration-500" style={{ backgroundImage: accent.gradient }} />
            <div className="absolute inset-0 scanlines opacity-45" />
            <div className="absolute inset-[2.75rem] rounded-[1.8rem] border border-white/10 bg-black/18" />
            <div className="absolute inset-[5.5rem] rounded-[1.6rem] border border-white/10" />
            <div className="absolute left-1/2 top-1/2 h-[16rem] w-[16rem] -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/12" />
            <div
              className="absolute left-1/2 top-1/2 h-[12rem] w-[12rem] -translate-x-1/2 -translate-y-1/2 rounded-full border"
              style={{ borderColor: accent.glow, boxShadow: `0 0 42px ${accent.glow}` }}
            />
            <div className="absolute inset-x-[12%] top-1/2 h-px -translate-y-1/2 bg-white/14" />
            <div className="absolute inset-y-[14%] left-1/2 w-px -translate-x-1/2 bg-white/10" />
            <div className="absolute inset-[17%] border border-white/8" />
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_0%,transparent_44%,rgba(2,6,23,.58)_100%)]" />
          </section>
        </div>
      </div>
    </div>
  );
}
