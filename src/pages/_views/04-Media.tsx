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

  const activeArticle =
    articles.find((article) => getArticleId(article as MediaArticle) === activeId) ?? (articles[0] as MediaArticle | undefined);

  return (
    <div
      id="media"
      className={`absolute left-auto right-0 top-0 h-full w-[100vw] max-w-[180rem] transition-all duration-1000 ${
        active ? "visible opacity-100" : "invisible opacity-0"
      }`}
    >
      <div className="relative h-full w-full overflow-hidden bg-[#03070b]">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat opacity-30"
          style={{ backgroundImage: `url(${rightImage})` }}
        />
        <div className="absolute inset-0 bg-[linear-gradient(120deg,rgba(2,6,23,.9),rgba(2,6,23,.78)_45%,rgba(2,6,23,.92))]" />
        <div className="absolute inset-0 panel-grid opacity-25" />

        <div className="absolute inset-x-[4.5rem] top-[8.75rem] bottom-[2.5rem] grid grid-cols-[minmax(17rem,26rem)_minmax(0,1fr)] gap-6 portrait:inset-x-[1.25rem] portrait:top-[8.75rem] portrait:grid-cols-1">
          <aside className="relative overflow-hidden rounded-[1.7rem] border border-white/10 bg-black/35 panel-grid panel-noise backdrop-blur-md glow-frame">
            <div className="border-b border-white/10 px-6 py-5">
              <div className="text-[0.72rem] font-benderBold tracking-[0.38em] text-white/45">SEALED CENTER</div>
              <div className="mt-2 text-[2rem] font-benderBold tracking-[0.08em] text-white">封存</div>
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

          <section className="relative overflow-hidden rounded-[1.9rem] border border-white/10 bg-black/35 panel-grid panel-noise backdrop-blur-md glow-frame">
            <div
              className="absolute inset-0 bg-cover bg-center opacity-20"
              style={{ backgroundImage: `url(${rightImage})` }}
            />
            <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(2,6,23,.12),rgba(2,6,23,.72))]" />
            <div className="absolute inset-0 scanlines opacity-40" />

            <div className="relative flex h-full flex-col justify-between px-8 py-8 portrait:px-5">
              <div>
                <div className="text-[0.72rem] font-benderBold tracking-[0.38em] text-white/45">CURRENT ENTRY</div>
                <div className="mt-4 text-[3rem] font-benderBold tracking-[0.08em] text-white portrait:text-[2rem]">
                  {activeArticle?.title ?? "No Entry"}
                </div>
                <div className="mt-3 text-[0.95rem] text-white/68">{activeArticle?.subTitle ?? "点击左侧条目进入验证页。"}</div>
              </div>

              <div className="grid gap-4 md:grid-cols-3">
                <div className="rounded-[1.2rem] border border-white/10 bg-black/30 px-4 py-4">
                  <div className="text-[0.66rem] font-benderBold tracking-[0.3em] text-white/35">MODE</div>
                  <div className="mt-3 text-[1.15rem] font-benderBold tracking-[0.06em] text-white">封存入口</div>
                </div>
                <div className="rounded-[1.2rem] border border-white/10 bg-black/30 px-4 py-4">
                  <div className="text-[0.66rem] font-benderBold tracking-[0.3em] text-white/35">STATUS</div>
                  <div className="mt-3 text-[1.15rem] font-benderBold tracking-[0.06em] text-white">
                    {activeArticle?.locked ? "等待验证" : "公开内容"}
                  </div>
                </div>
                <div className="rounded-[1.2rem] border border-white/10 bg-black/30 px-4 py-4">
                  <div className="text-[0.66rem] font-benderBold tracking-[0.3em] text-white/35">PATH</div>
                  <div className="mt-3 text-[1.15rem] font-benderBold tracking-[0.06em] text-white">{getArticleId((activeArticle ?? articles[0]) as MediaArticle)}</div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 border-t border-white/10 pt-6">
                <div className="text-[0.88rem] text-white/55">先到这里选条目，再进入单独的验证页。</div>
                {activeArticle && (
                  <a
                    href={activeArticle.href}
                    target="_self"
                    className="rounded-[1rem] border border-slate-100/20 bg-slate-100/10 px-5 py-3 text-[0.78rem] font-benderBold tracking-[0.28em] text-white no-underline transition-colors duration-300 hover:bg-slate-100/18"
                  >
                    进入验证页
                  </a>
                )}
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
