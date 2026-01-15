import React, { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore.ts";
import { directions } from "../../components/store/lineDecoratorStore";
import arknightsConfig from "../../../arknights.config"; // 如果解析不到，改成 "../../../arknights.config.tsx"

export default function Media() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);

  useEffect(() => {
    const isActive = $viewIndex === 4 && $readyToTouch;
    if (isActive) directions.set({ top: false, right: true, bottom: true, left: false });
    setActive(isActive);
  }, [$viewIndex, $readyToTouch]);

  const media = arknightsConfig?.rootPage?.MEDIA;

  const rightImage = media?.rightImage ?? "/images/terra/right.jpg";
  const articles = useMemo(() => media?.articles ?? [], [media]);

  return (
    <section
      id="media"
      className={`w-full h-full transition-opacity duration-1000 ${active ? "opacity-100" : "opacity-0"}`}
    >
      {/* 你想要“像友链”，通常背景不要纯色块。这里不给固定颜色，你可以自己按主题再加。 */}
      <div className="w-full h-full px-6 py-6">
        <div
          className="grid gap-6 h-full"
          style={{
            gridTemplateColumns: "30% 70%",
          }}
        >
          {/* 左侧：30% 文章列表 */}
          <aside
            className="h-full overflow-hidden rounded-2xl border border-white/10 bg-black/20"
            style={{ backdropFilter: "blur(6px)" }}
          >
            <div className="p-4 border-b border-white/10">
              <div className="text-xl font-benderBold tracking-wide">泰拉万象</div>
              <div className="text-sm opacity-70 mt-1">MEDIA</div>
            </div>

            <nav className="h-[calc(100%-72px)] overflow-auto p-3 space-y-3">
              {articles.length === 0 ? (
                <div className="p-3 text-sm opacity-70">
                  还没有内容。你可以在 <code className="opacity-90">arknights.config.tsx</code> 里添加
                  <code className="opacity-90">rootPage.MEDIA.articles</code>。
                </div>
              ) : (
                articles.map((a, idx) => (
                  <a
                    key={`${a.href}-${idx}`}
                    href={a.href}
                    className="block rounded-2xl border border-white/10 bg-white/5 hover:bg-white/10 transition-colors"
                  >
                    <div className="p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="font-semibold truncate">
                            {a.title}
                            {a.subTitle ? <span className="opacity-70"> · {a.subTitle}</span> : null}
                          </div>
                          {a.date ? <div className="text-xs opacity-60 mt-1">{a.date}</div> : null}
                        </div>

                        <div className="shrink-0 text-lg" title={a.locked ? "加密文档" : "公开内容"}>
                          {a.locked ? "🔒" : "📰"}
                        </div>
                      </div>
                    </div>
                  </a>
                ))
              )}
            </nav>
          </aside>

          {/* 右侧：70% 固定图片（一直一张） */}
          <div
            className="h-full overflow-hidden rounded-2xl border border-white/10 bg-black/20"
            style={{ backdropFilter: "blur(6px)" }}
          >
            <img
              src={rightImage}
              alt="Terra Omnia"
              className="w-full h-full object-cover select-none pointer-events-none"
              loading="lazy"
            />
          </div>
        </div>
      </div>
    </section>
  );
}
