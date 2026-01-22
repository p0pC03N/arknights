import React, { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";

import arknightsConfig from "../../../arknights.config";
import { decryptEncryptedPayload, type EncryptedPayload } from "../../components/EncryptedArticle";

type AuthState = "idle" | "loading" | "ok" | "bad";

export default function Media() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);

  const [pwMap, setPwMap] = useState<Record<string, string>>({});
  const [authMap, setAuthMap] = useState<Record<string, AuthState>>({});
  const [htmlMap, setHtmlMap] = useState<Record<string, string>>({});
  const [activeId, setActiveId] = useState<string | null>(null);

  // ✅ 兼容 GitHub Pages 子路径
  const base = import.meta.env.BASE_URL;

  // ✅ 从 config 里拿 MEDIA 数据
  const media = useMemo(() => arknightsConfig?.rootPage?.MEDIA, []);

  // ✅ 右侧“固定大图”
  const rightImage = useMemo(() => {
    return media?.rightImage ?? base + "images/terra/right.jpg";
  }, [media, base]);

  // ✅ 左侧文章列表
  const articles = useMemo(() => media?.articles ?? [], [media]);

  // ✅ 关键：把加密 payload（json）打包进前端，这样点击“打开”就能立即解密验证
  // 路径一定要以 /src 开头（Vite 约定），并且文件必须真的存在于 src/content/secret 下
  const payloadModules = useMemo(() => {
    return import.meta.glob<{ default: EncryptedPayload }>(
      "/src/content/secret/*.payload.json",
      { eager: true }
    );
  }, []);

  function getArticleId(a: any) {
    if (a?.secretId) return String(a.secretId);
    const href = String(a?.href ?? "");
    const seg = href.split("?")[0].split("#")[0].split("/").filter(Boolean).pop();
    return seg || "unknown";
  }

  function getPayloadById(id: string): EncryptedPayload | null {
    // 可能的 key 形如：/src/content/secret/f03_u.payload.json
    const key = `/src/content/secret/${id}.payload.json`;
    const mod = (payloadModules as any)[key];
    return mod?.default ?? null;
  }

  useEffect(() => {
    const isActive = $viewIndex === 4 && $readyToTouch;
    if (isActive) directions.set({ top: false, right: true, bottom: true, left: false });
    setActive(isActive);
  }, [$viewIndex, $readyToTouch]);

  async function onOpen(a: any) {
    const id = getArticleId(a);
    const locked = !!a.locked;
    if (!locked) return;

    const pw = (pwMap[id] ?? "").trim();
    if (!pw) {
      // 没输入密码：给一个“未授权”反馈也可以，这里用 idle 不闪红
      setAuthMap((m) => ({ ...m, [id]: "idle" }));
      return;
    }

    // 已经解密过就直接展开
    if (htmlMap[id]) {
      setAuthMap((m) => ({ ...m, [id]: "ok" }));
      setActiveId(id);
      return;
    }

    setAuthMap((m) => ({ ...m, [id]: "loading" }));

    try {
      const payload = getPayloadById(id);
      if (!payload) {
        // payload 文件不存在/路径不匹配
        setAuthMap((m) => ({ ...m, [id]: "bad" }));
        return;
      }

      const html = await decryptEncryptedPayload(payload, pw);

      setHtmlMap((m) => ({ ...m, [id]: html }));
      setAuthMap((m) => ({ ...m, [id]: "ok" }));
      setActiveId(id);
    } catch {
      setAuthMap((m) => ({ ...m, [id]: "bad" }));
      // 解密失败不展开
      if (activeId === id) setActiveId(null);
    }
  }

  function onClosePanel() {
    setActiveId(null);
  }

  return (
    <div
      id="media"
      className={`w-[100vw] max-w-[180rem] h-full absolute top-0 right-0 bottom-0 left-auto transition-all duration-1000 ${
        active ? "opacity-100 visible" : "opacity-0 invisible"
      }`}
    >
      <div className="w-full h-full relative overflow-hidden">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `url(${rightImage})`,
            backgroundSize: "cover",
            backgroundPosition: "center",
            backgroundRepeat: "no-repeat",
          }}
        />
        <div className="absolute inset-0 bg-black/45" />

        <h1 className="text-6xl absolute top-10 left-10 text-white drop-shadow">MEDIA</h1>

        <div className="absolute left-10 right-10 top-28 bottom-10">
          <div className="grid gap-6 h-full" style={{ gridTemplateColumns: "30% 70%" }}>
            {/* 左侧列表 + 抽屉内容 */}
            <aside className="relative h-full overflow-hidden rounded-2xl border border-white/10 bg-black/60 backdrop-blur-md">
              <div className="p-4 border-b border-white/10">
                <div className="text-xl text-white font-benderBold tracking-wide">泰拉万象</div>
                <div className="text-sm text-white/70 mt-1">TERRA OMNIA</div>
              </div>

              <nav className="h-[calc(100%-72px)] overflow-auto p-3 space-y-3">
                {articles.length === 0 ? (
                  <div className="p-3 text-sm text-white/70">
                    还没有内容。请在 <code className="text-white/90">arknights.config.tsx</code> 里添加
                    <code className="text-white/90"> rootPage.MEDIA.articles</code>。
                  </div>
                ) : (
                  articles.map((a, idx) => {
                    const id = getArticleId(a);
                    const locked = !!a.locked;
                    const hint = a.keyHint || "请输入密钥";
                    const pw = pwMap[id] ?? "";
                    const st: AuthState = authMap[id] ?? "idle";

                    // 非加密：仍然是普通跳转
                    if (!locked) {
                      return (
                        <a
                          key={`${a.href}-${idx}`}
                          href={a.href}
                          className="block rounded-xl border border-white/10 hover:border-white/30 bg-black/30 p-4 transition"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="font-semibold text-white truncate">
                                {a.title}
                                {a.subTitle ? <span className="text-white/70"> · {a.subTitle}</span> : null}
                              </div>
                              {a.date ? <div className="text-xs text-white/60 mt-1">{a.date}</div> : null}
                            </div>
                            <div className="shrink-0 text-lg" title="公开内容">📰</div>
                          </div>
                        </a>
                      );
                    }

                    // 加密：不跳转，只有点“打开”才验证
                    return (
                      <div
                        key={`${a.href}-${idx}`}
                        className="group rounded-xl border border-white/10 hover:border-white/30 bg-black/30 p-4 transition"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="font-semibold text-white truncate">
                              {a.title}
                              {a.subTitle ? <span className="text-white/70"> · {a.subTitle}</span> : null}
                            </div>
                            {a.date ? <div className="text-xs text-white/60 mt-1">{a.date}</div> : null}
                          </div>
                          <div className="shrink-0 text-lg" title="加密文档">🔒</div>
                        </div>

                        {/* hover 往下伸展：输入密钥 */}
                        <div className="overflow-hidden max-h-0 group-hover:max-h-36 transition-[max-height] duration-300">
                          <div className="pt-3">
                            <div className="text-xs text-white/70 mb-2">{hint}</div>

                            <div className="flex gap-2 items-center">
                              <input
                                type="password"
                                value={pw}
                                onChange={(ev) => setPwMap((m) => ({ ...m, [id]: ev.target.value }))}
                                placeholder={hint}
                                className="flex-1 px-3 py-2 rounded-lg bg-black/40 border border-white/10 text-white outline-none focus:border-white/30"
                                onKeyDown={(ev) => {
                                  if (ev.key !== "Enter") return;
                                  ev.preventDefault();
                                  ev.stopPropagation();
                                  onOpen(a);
                                }}
                              />
                              <button
                                type="button"
                                className="px-3 py-2 rounded-lg border border-white/10 hover:border-white/30 bg-white/5 text-white text-sm"
                                onClick={(ev) => {
                                  ev.preventDefault();
                                  ev.stopPropagation();
                                  onOpen(a);
                                }}
                                disabled={st === "loading"}
                              >
                                {st === "loading" ? "验证中…" : "打开"}
                              </button>
                            </div>

                            {/* 状态提示 */}
                            {st === "ok" ? (
                              <div className="mt-2 text-sm text-white/80">请查阅</div>
                            ) : st === "bad" ? (
                              <div className="mt-2 text-sm text-white/80">未授权</div>
                            ) : null}
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </nav>

              {/* ✅ 左侧抽屉：解密成功后从左侧列表“伸展”出来（覆盖到右侧区域） */}
              <div
                className={[
                  "absolute top-0 right-0 bottom-0 w-[70vw] max-w-[980px]",
                  "bg-black/70 backdrop-blur-md border-l border-white/10",
                  "transition-transform duration-300",
                  activeId ? "translate-x-0" : "translate-x-full",
                ].join(" ")}
              >
                <div className="h-full flex flex-col">
                  <div className="p-4 border-b border-white/10 flex items-center justify-between">
                    <div className="text-white font-semibold truncate">
                      {activeId ? activeId : ""}
                    </div>
                    <button
                      type="button"
                      className="px-3 py-2 rounded-lg border border-white/10 hover:border-white/30 bg-white/5 text-white text-sm"
                      onClick={onClosePanel}
                    >
                      关闭
                    </button>
                  </div>

                  <div className="flex-1 overflow-auto p-4">
                    {activeId && htmlMap[activeId] ? (
                      <article dangerouslySetInnerHTML={{ __html: htmlMap[activeId] }} />
                    ) : (
                      <div className="text-white/70 text-sm">没有内容</div>
                    )}
                  </div>
                </div>
              </div>
            </aside>

            {/* 右侧固定图片框 */}
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
