import React, { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";

import arknightsConfig from "../../../arknights.config";

export default function Media() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);

  // ✅ 兼容 GitHub Pages 子路径
  const base = import.meta.env.BASE_URL;

  // ✅ 从 config 里拿 MEDIA 数据
  const media = useMemo(() => arknightsConfig?.rootPage?.MEDIA, []);

  // ✅ 右侧“固定大图”（像友链那样一直显示）
  const rightImage = useMemo(() => {
    // 允许你在 config 里写 base + "images/..."，也允许写 "/images/..."
    return media?.rightImage ?? base + "images/terra/right.jpg";
  }, [media, base]);

  // ✅ 左侧文章列表
  const articles = useMemo(() => media?.articles ?? [], [media]);

  useEffect(() => {
    const isActive = $viewIndex === 4 && $readyToTouch;
    if (isActive) directions.set({ top: false, right: true, bottom: true, left: false });
    setActive(isActive);
  }, [$viewIndex, $readyToTouch]);

  return (
    <div
      id="media"
      className={`w-[100vw] max-w-[180rem] h-full absolute top-0 right-0 bottom-0 left-auto transition-all duration-1000 ${
        active ? "opacity-100 visible" : "opacity-0 invisible"
      }`}
    >
      {/* 整页容器 */}
      <div className="w-full h-full relative overflow-hidden">
        {/* ✅ 背景图层：这里用“右侧固定图”作为整个页面背景（风格跟 Operator 一致） */}
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `url(${rightImage})`,
            backgroundSize: "cover",
            backgroundPosition: "center",
            backgroundRepeat: "no-repeat",
          }}
        />

        {/* ✅ 暗色遮罩，让字更清晰 */}
        <div className="absolute inset-0 bg-black/45" />

        {/* 标题 */}
        <h1 className="text-6xl absolute top-10 left-10 text-white drop-shadow">
          MEDIA
        </h1>

        {/* ✅ 内容区：左 30% 列表；右侧是“固定图片展示框”，但图片不随选择变化 */}
        <div className="absolute left-10 right-10 top-28 bottom-10">
          <div
            className="grid gap-6 h-full"
            style={{ gridTemplateColumns: "30% 70%" }}
          >
            {/* 左侧列表 */}
            <aside className="h-full overflow-hidden rounded-2xl border border-white/10 bg-black/60 backdrop-blur-md">
              <div className="p-4 border-b border-white/10">
                <div className="text-xl text-white font-benderBold tracking-wide">
                  泰拉万象
                </div>
                <div className="text-sm text-white/70 mt-1">TERRA OMNIA</div>
              </div>

              <nav className="h-[calc(100%-72px)] overflow-auto p-3 space-y-3">
                {articles.length === 0 ? (
                  <div className="p-3 text-sm text-white/70">
                    还没有内容。请在 <code className="text-white/90">arknights.config.tsx</code> 里添加
                    <code className="text-white/90"> rootPage.MEDIA.articles</code>。
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
                            <div className="font-semibold text-white truncate">
                              {a.title}
                              {a.subTitle ? <span className="text-white/70"> · {a.subTitle}</span> : null}
                            </div>
                            {a.date ? <div className="text-xs text-white/60 mt-1">{a.date}</div> : null}
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

            {/* 右侧固定图片框（一直一张图，不联动） */}
            <section className="h-full overflow-hidden rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md">
              <img
                src={rightImage}
                alt="Terra Omnia"
                className="w-full h-full object-cover select-none pointer-events-none"
                loading="lazy"
              />
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}
