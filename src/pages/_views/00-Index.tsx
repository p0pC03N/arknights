import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useStore } from "@nanostores/react";
import { directions } from "../../components/store/lineDecoratorStore";
import { readyToTouch, viewIndex } from "../../components/store/rootLayoutStore.ts";
import PixelCat from "../../components/cat/PixelCat";
import {
  CAT_PROFILE_EVENT,
  feedCat,
  loadCatProfile,
  petCat,
} from "../../components/cat/catProfile";
import type { CatProfile } from "../../components/cat/catProfile";

const base = import.meta.env.BASE_URL;

const giscusConfig = {
  repo: "p0pC03N/arknights",
  repoId: "R_kgDOQxpzQQ",
  category: "General",
  categoryId: "DIC_kwDOQxpzQc4C9pZc",
};

type FeedItem = {
  title: string;
  date: string;
  summary: string;
  href: string;
};

type HomeFeed = {
  docs: FeedItem[];
  blog: FeedItem[];
};

type CupSide = "yang" | "yin";

type CupCast = {
  id: string;
  left: CupSide;
  right: CupSide;
  name: string;
  verdict: string;
  basis: string;
};

function readCupResult(left: CupSide, right: CupSide) {
  if (left !== right) {
    return {
      name: "圣杯",
      verdict: "可行",
      basis: "一阳一阴，表示允准，所问之事可推进。",
    };
  }

  if (left === "yang") {
    return {
      name: "笑杯",
      verdict: "未定",
      basis: "两阳相对，表示神意未明，宜静候再问。",
    };
  }

  return {
    name: "阴杯",
    verdict: "暂缓",
    basis: "两阴相对，表示不允，所问之事暂不宜行。",
  };
}

function PixelPanel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={
        "relative border-2 border-black bg-[#f8f1d1] text-black shadow-[8px_8px_0_#000] " +
        "before:pointer-events-none before:absolute before:inset-0 before:border before:border-[#ffffff80] " +
        className
      }
    >
      {children}
    </section>
  );
}

function PanelHeader({
  title,
  label,
  accent = "bg-[#22d3ee]",
}: {
  title: string;
  label: string;
  accent?: string;
}) {
  return (
    <div className="flex items-center border-b-2 border-black bg-black text-white">
      <div className={`h-7 w-7 border-r-2 border-black ${accent}`} />
      <div className="px-3 py-1 font-benderBold text-[1rem] leading-none">{title}</div>
      <div className="ml-auto border-l-2 border-black px-3 py-1 font-benderRegular text-[0.7rem] text-[#9ffcff]">
        {label}
      </div>
    </div>
  );
}

function CupIcon({ side, rolling }: { side: CupSide; rolling: boolean }) {
  return (
    <div
      className={
        "relative flex h-20 w-24 items-center justify-center border-2 border-[#d6c28e] bg-[#15110b] shadow-[4px_4px_0_#000] transition-transform " +
        (rolling ? "animate-[showHide_.45s_infinite]" : "")
      }
    >
      <div
        className={
          "h-12 w-16 border-2 border-black " +
          (side === "yang"
            ? "rounded-t-[2rem] rounded-b-md bg-[#f5d06a] shadow-[inset_0_-8px_0_#a76221]"
            : "rounded-b-[2rem] rounded-t-md bg-[#221b14] shadow-[inset_0_8px_0_#5b3b1b]")
        }
      />
      <span className="absolute bottom-1 right-2 font-benderBold text-[0.65rem] text-[#f7e7a4]">
        {side === "yang" ? "YANG" : "YIN"}
      </span>
    </div>
  );
}

function FortunePanel() {
  const [question, setQuestion] = useState("今日代码运势");
  const [casts, setCasts] = useState<CupCast[]>([]);
  const [rolling, setRolling] = useState(false);
  const current = casts[0];

  const castCups = () => {
    if (rolling) return;
    setRolling(true);

    window.setTimeout(() => {
      const left: CupSide = Math.random() > 0.5 ? "yang" : "yin";
      const right: CupSide = Math.random() > 0.5 ? "yang" : "yin";
      const result = readCupResult(left, right);

      setCasts((items) => [
        {
          id: `${Date.now()}`,
          left,
          right,
          ...result,
        },
        ...items,
      ].slice(0, 5));
      setRolling(false);
    }, 620);
  };

  return (
    <PixelPanel className="min-h-0 overflow-hidden bg-[#091014] text-[#e8fff7]">
      <PanelHeader title="掷圣杯" label="DIVINATION RITE" accent="bg-[#f43f5e]" />
      <div className="relative overflow-hidden p-4">
        <div className="absolute inset-0 opacity-20 [background-image:linear-gradient(#d6b25e_1px,transparent_1px),linear-gradient(90deg,#d6b25e_1px,transparent_1px)] [background-size:20px_20px]" />
        <div className="relative space-y-4">
          <div className="border-2 border-[#d6c28e] bg-[#060707] p-3 shadow-[4px_4px_0_#000]">
            <label className="block font-benderBold text-[0.7rem] text-[#f7e7a4]">所问之事</label>
            <input
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              maxLength={18}
              className="mt-2 w-full border-2 border-[#d6c28e] bg-[#111814] px-3 py-2 text-sm font-bold text-white outline-none"
            />
          </div>

          <div className="grid grid-cols-[1fr_8rem] gap-3 portrait:grid-cols-1">
            <div className="flex items-center justify-center gap-3 border-2 border-[#d6c28e] bg-[#0d0b08] p-3">
              <CupIcon side={rolling ? "yang" : current?.left ?? "yang"} rolling={rolling} />
              <CupIcon side={rolling ? "yin" : current?.right ?? "yin"} rolling={rolling} />
            </div>
            <button
              type="button"
              onClick={castCups}
              disabled={rolling}
              className="border-2 border-black bg-[#f7d35f] px-3 py-3 font-benderBold text-sm text-black shadow-[5px_5px_0_#000] transition-transform hover:-translate-y-1 disabled:cursor-wait disabled:opacity-70"
            >
              {rolling ? "落杯中" : "掷圣杯"}
            </button>
          </div>

          <div className="border-2 border-[#d6c28e] bg-[#050606] p-3">
            <div className="flex items-center gap-2">
              <span className="border-2 border-[#f7d35f] bg-[#f7d35f] px-3 py-1 font-benderBold text-xl text-black">
                {current?.name ?? "未掷"}
              </span>
              <span className="ml-auto font-benderBold text-[#88fff8]">{current?.verdict ?? "待问"}</span>
            </div>
            <p className="mt-3 min-h-[3rem] text-sm font-bold leading-6 text-white">
              {current ? current.basis : "输入所问之事，点击掷圣杯。杯象按一阳一阴、两阳、两阴判读。"}
            </p>
            <div className="mt-2 text-xs text-[#d6c28e]">QUESTION: {question || "未填写"}</div>
          </div>

          <div className="grid grid-cols-3 gap-2 text-xs">
            {casts.length === 0 ? (
              <div className="col-span-3 border border-[#d6c28e] bg-[#d6c28e1a] p-2 text-[#d6c28e]">
                暂无掷杯记录
              </div>
            ) : casts.slice(0, 3).map((item, index) => (
              <div key={item.id} className="border border-[#d6c28e] bg-[#d6c28e1a] p-2">
                <span className="block text-[#d6c28e]">第 {casts.length - index} 掷</span>
                {item.name} / {item.verdict}
              </div>
            ))}
          </div>

          <div className="grid grid-cols-3 gap-2 text-[0.68rem] leading-4 text-[#cbbf9a]">
            <div>圣杯：一阳一阴，可行。</div>
            <div>笑杯：两阳，未定。</div>
            <div>阴杯：两阴，暂缓。</div>
          </div>
        </div>
      </div>
    </PixelPanel>
  );
}

function MessageBoard({ active }: { active: boolean }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [readyToLoad, setReadyToLoad] = useState(false);
  const isConfigured = Boolean(giscusConfig.categoryId);

  useEffect(() => {
    if (!active || readyToLoad) return;
    const timer = window.setTimeout(() => setReadyToLoad(true), 1200);
    return () => window.clearTimeout(timer);
  }, [active, readyToLoad]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container || !isConfigured || !readyToLoad) return;

    container.innerHTML = "";

    const script = document.createElement("script");
    script.src = "https://giscus.app/client.js";
    script.async = true;
    script.crossOrigin = "anonymous";
    script.setAttribute("data-repo", giscusConfig.repo);
    script.setAttribute("data-repo-id", giscusConfig.repoId);
    script.setAttribute("data-category", giscusConfig.category);
    script.setAttribute("data-category-id", giscusConfig.categoryId);
    script.setAttribute("data-mapping", "pathname");
    script.setAttribute("data-strict", "0");
    script.setAttribute("data-reactions-enabled", "1");
    script.setAttribute("data-emit-metadata", "0");
    script.setAttribute("data-input-position", "bottom");
    script.setAttribute("data-theme", "preferred_color_scheme");
    script.setAttribute("data-lang", "zh-CN");
    script.setAttribute("data-loading", "lazy");

    container.appendChild(script);

    return () => {
      container.innerHTML = "";
    };
  }, [isConfigured, readyToLoad]);

  return (
    <PixelPanel className="flex min-h-0 flex-1 flex-col overflow-hidden bg-[#071014] text-white">
      <PanelHeader title="MESSAGE BOARD" label="GISCUS" accent="bg-[#84cc16]" />
      <div className="min-h-[22rem] flex-1 overflow-y-auto p-3">
        {isConfigured ? (
          <div ref={containerRef} className="giscus-shell min-h-[18rem]" />
        ) : (
          <div className="border-2 border-[#84cc16] bg-[#84cc161f] p-4 font-bold leading-6 text-[#eaffd4] shadow-[4px_4px_0_#000]">
            <div className="font-benderBold text-xl text-[#ffee22]">留言板已上线</div>
            <p className="mt-3 text-sm">
              GitHub Discussions 尚未启用。启用 Discussions、安装 giscus，并填入 categoryId 后，这里会显示真实留言。
            </p>
          </div>
        )}
      </div>
    </PixelPanel>
  );
}

function HeroCover() {
  const [catOpen, setCatOpen] = useState(false);
  const [profile, setProfile] = useState<CatProfile>(() => loadCatProfile());
  const [hint, setHint] = useState("米线从封面里跳出来了。");

  useEffect(() => {
    const handleProfile = (event: Event) => {
      setProfile((event as CustomEvent<CatProfile>).detail ?? loadCatProfile());
    };

    window.addEventListener(CAT_PROFILE_EVENT, handleProfile);
    return () => window.removeEventListener(CAT_PROFILE_EVENT, handleProfile);
  }, []);

  const openCatHome = () => {
    location.hash = "more";
    viewIndex.set(5);
  };

  const popCat = () => {
    setCatOpen(true);
    setHint(`${profile.name} 从封面里跳出来了。`);
  };

  const handlePet = () => {
    const result = petCat();
    setProfile(result.profile);
    setHint(result.petted ? `${result.profile.name} 被摸到眯起眼睛。` : `${Math.ceil(result.cooldownMs / 1000)} 秒后再摸。`);
  };

  const handleFeed = () => {
    const result = feedCat();
    setProfile(result.profile);
    setHint(result.fed ? `${result.profile.name} 吃掉一个罐头。` : "没有罐头了，去读文章带一个回来。");
  };

  return (
    <PixelPanel className="aspect-[1672/941] overflow-hidden bg-black">
      <button type="button" onClick={popCat} className="absolute inset-0 z-[2] cursor-pointer" aria-label="唤出小猫" />
      <img
        src={`${base}images/home/cat-crayon-pixel-cover.webp`}
        alt="像素涂鸦猫咪封面"
        className="h-full w-full object-cover [image-rendering:pixelated]"
      />
      <div className="absolute inset-0 border-[10px] border-black/35" />
      <div className="pointer-events-none absolute bottom-4 left-4 z-[3] border-2 border-black bg-[#ffee22] px-4 py-2 font-benderBold text-xl text-black shadow-[5px_5px_0_#000]">
        WAKE CAT
      </div>
      {catOpen && (
        <div className="cat-cover-pop absolute bottom-5 left-5 z-[5] w-[min(25rem,calc(100%-2.5rem))] border-2 border-black bg-[#fff7df] p-3 text-black shadow-[8px_8px_0_#000]">
          <button
            type="button"
            onClick={() => setCatOpen(false)}
            className="absolute right-2 top-2 z-[2] border-2 border-black bg-white px-2 py-1 font-benderBold text-xs shadow-[2px_2px_0_#000]"
          >
            关
          </button>
          <div className="grid grid-cols-[9rem_1fr] items-center gap-3 portrait:grid-cols-1">
            <PixelCat coat={profile.coat} outfit={profile.outfit} mood="happy" onClick={handlePet} className="min-h-[9rem] min-w-[9rem] scale-[0.62] origin-center" />
            <div>
              <div className="inline-block border-2 border-black bg-[#ffee22] px-2 py-1 font-benderBold text-xs">POP!</div>
              <p className="mt-2 min-h-[3rem] text-sm font-black leading-5">{hint}</p>
              <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                <button type="button" onClick={handlePet} className="border-2 border-black bg-white px-2 py-2 font-bold shadow-[3px_3px_0_#000]">
                  摸摸
                </button>
                <button type="button" onClick={handleFeed} className="border-2 border-black bg-[#f97316] px-2 py-2 font-bold text-white shadow-[3px_3px_0_#000]">
                  投喂
                </button>
                <button type="button" onClick={openCatHome} className="border-2 border-black bg-[#22d3ee] px-2 py-2 font-bold shadow-[3px_3px_0_#000]">
                  主页
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      <div className="pointer-events-none absolute right-[5.8%] top-[15%] z-[3] w-[22%] min-w-[8rem] rotate-[1deg] border-4 border-black bg-white p-2 shadow-[6px_6px_0_#000] portrait:right-4 portrait:top-4 portrait:w-[9rem]">
        <img
          src={`${base}images/home/alipay-qr.jpg`}
          alt="支付宝收款码"
          className="aspect-square w-full object-contain object-center"
        />
      </div>
    </PixelPanel>
  );
}

function FeedColumn({
  title,
  label,
  href,
  items,
  accent,
}: {
  title: string;
  label: string;
  href: string;
  items: FeedItem[];
  accent: string;
}) {
  return (
    <PixelPanel className="min-h-[24rem] overflow-hidden bg-[#f8f1d1]">
      <PanelHeader title={title} label={label} accent={accent} />
      <div className="max-h-[26rem] overflow-y-auto p-3">
        {items.map((item) => (
          <a
            key={item.href}
            href={item.href}
            className="group mb-3 block border-2 border-black bg-white p-3 text-black no-underline shadow-[4px_4px_0_#000] transition-transform hover:-translate-y-1"
          >
            <div className="flex items-center gap-3 font-benderBold text-xs">
              <span className="bg-black px-2 py-1 text-white">{item.date}</span>
              <span className="ml-auto text-[#0e7490] group-hover:text-[#f43f5e]">OPEN</span>
            </div>
            <h3 className="mt-3 break-words text-xl font-black leading-6">{item.title}</h3>
            {item.summary && <p className="mt-2 line-clamp-2 text-sm font-bold leading-5 text-[#3f3f3f]">{item.summary}</p>}
          </a>
        ))}
      </div>
      <a
        href={href}
        className="flex items-center justify-between border-t-2 border-black bg-black px-4 py-3 font-benderBold text-sm text-[#ffee22] no-underline hover:bg-[#ffee22] hover:text-black"
      >
        VIEW ALL
        <span>»</span>
      </a>
    </PixelPanel>
  );
}

function FeedColumns() {
  const [feed, setFeed] = useState<HomeFeed>({ docs: [], blog: [] });

  useEffect(() => {
    fetch(`${base}home-feed.json`)
      .then((response) => response.json())
      .then((data: HomeFeed) => setFeed(data))
      .catch(() => setFeed({ docs: [], blog: [] }));
  }, []);

  return (
    <div className="grid grid-cols-2 gap-5 portrait:grid-cols-1">
      <FeedColumn title="DOCS" label="NEWEST FIRST" href={`${base}docs/`} items={feed.docs} accent="bg-[#22d3ee]" />
      <FeedColumn title="BLOG" label="NEWEST FIRST" href={`${base}blog/`} items={feed.blog} accent="bg-[#ffee22]" />
    </div>
  );
}

export default function Index() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState($viewIndex === 0);

  useEffect(() => {
    const isActive = $viewIndex === 0 && $readyToTouch;
    if (isActive) {
      directions.set({ top: false, right: true, bottom: true, left: false });
    }
    setActive(isActive);
  }, [$readyToTouch, $viewIndex]);

  return (
    <div className="absolute inset-0 z-[2] h-full w-[100vw] max-w-[180rem] overflow-y-auto overflow-x-hidden bg-[#08090d] text-white transition-opacity duration-100" data-root-scroll-lock="true">
      <div className="absolute inset-0 bg-[linear-gradient(180deg,#081016,#101011_48%,#040406)]" />
      <div className="absolute inset-0 opacity-[0.18] [background-image:linear-gradient(#28f7ff_1px,transparent_1px),linear-gradient(90deg,#28f7ff_1px,transparent_1px)] [background-size:28px_28px]" />
      <div className="absolute inset-0 pointer-events-none bg-[repeating-linear-gradient(0deg,rgba(255,255,255,.06)_0,rgba(255,255,255,.06)_1px,transparent_1px,transparent_4px)] opacity-30" />

      <div className={`relative z-[2] mx-auto min-h-full max-w-[102rem] px-5 pb-16 pt-[7.5rem] transition-all duration-500 portrait:px-3 portrait:pt-[8.5rem] ${active ? "translate-y-0 opacity-100" : "translate-y-8 opacity-0"}`}>
        <div className="mb-5 flex items-end justify-between gap-4 portrait:block">
          <div>
            <div className="inline-block border-2 border-black bg-[#48fff4] px-3 py-1 font-benderBold text-xs text-black shadow-[4px_4px_0_#000]">
              PIXEL HOME / DOODLE BUILD
            </div>
            <h1 className="mt-3 font-benderBold text-5xl leading-none text-[#ffee22] [text-shadow:4px_4px_0_#000] portrait:text-4xl">
              CORN KINGDOM
            </h1>
          </div>
          <p className="max-w-[27rem] border-2 border-black bg-white px-4 py-3 text-sm font-bold leading-6 text-black shadow-[5px_5px_0_#000] portrait:mt-4">
            喵喵喵&gt;w&lt;
          </p>
        </div>

        <div className="grid items-start gap-5 portrait:grid-cols-1 landscape:grid-cols-[minmax(0,1fr)_minmax(20rem,28rem)]">
          <div className="min-w-0 space-y-7">
            <HeroCover />
            <FeedColumns />
          </div>

          <aside className="flex min-h-full flex-col gap-5">
            <FortunePanel />
            <MessageBoard active={active} />
          </aside>
        </div>
      </div>
    </div>
  );
}
