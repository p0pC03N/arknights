import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "@nanostores/react";
import { directions } from "../../components/store/lineDecoratorStore";
import { readyToTouch, viewIndex } from "../../components/store/rootLayoutStore.ts";
import arknightsConfig from "../../../arknights.config.tsx";

const base = import.meta.env.BASE_URL;
const VIDEO_PATH = `${base}videos/home.mp4`;
const VIDEO_LOOP_START = 0.35;
const VIDEO_LOOP_END = 7.6;

type RouteMood = {
  id: "blog" | "docs" | "archive";
  label: string;
  title: string;
  subTitle: string;
  status: string;
  signal: string;
  summary: string;
  href: string;
  actionLabel: string;
  badge: string;
  accent: string;
  frameClass: string;
  chipClass: string;
  auraClass: string;
  gridClass: string;
};

const routeMoods: RouteMood[] = [
  {
    id: "blog",
    label: "01 // BLOG",
    title: "FIELD JOURNAL",
    subTitle: "暖黄日志舱",
    status: "AMBER TRACE",
    signal: "PERSONAL REPORTS / REVERSE NOTES / ANNUAL LOGS",
    summary: "承载逆向札记、年报、杂记和阶段性记录，像一个可追溯的行动日志舱。",
    href: `${base}blog/`,
    actionLabel: "进入博客航线",
    badge: "JOURNAL",
    accent: "#facc15",
    frameClass: "border-yellow-300/30 hover:border-yellow-200/70",
    chipClass: "border-yellow-300/40 bg-yellow-300/12 text-yellow-100",
    auraClass: "from-yellow-300/22 via-amber-400/10 to-transparent",
    gridClass: "from-yellow-200/10 to-transparent",
  },
  {
    id: "docs",
    label: "02 // DOCS",
    title: "BLUEPRINT DECK",
    subTitle: "冷蓝蓝图台",
    status: "CYAN GRID",
    signal: "TECHNICAL NOTES / WRITEUPS / TOOLCHAIN DOCS",
    summary: "承载专题整理、题解和站点说明，把零散经验压成可复用的技术蓝图。",
    href: `${base}docs/`,
    actionLabel: "进入文档航线",
    badge: "BLUEPRINT",
    accent: "#38bdf8",
    frameClass: "border-sky-300/30 hover:border-sky-200/70",
    chipClass: "border-sky-300/40 bg-sky-300/12 text-sky-100",
    auraClass: "from-sky-300/25 via-cyan-400/12 to-transparent",
    gridClass: "from-sky-200/10 to-transparent",
  },
  {
    id: "archive",
    label: "03 // ARCHIVE",
    title: "SEALED ENTRY",
    subTitle: "灰黑取证室",
    status: "NULL VEIL",
    signal: "SEALED PAYLOADS / PRIVATE KEYS / CONTROLLED ACCESS",
    summary: "通往封存档案的入口，保留仪式感和取证气氛，但不假装成真正的安全系统。",
    href: `${base}terra-omnia/secret-02`,
    actionLabel: "进入封存航线",
    badge: "SEALED",
    accent: "#d4d4d8",
    frameClass: "border-slate-200/20 hover:border-slate-100/50",
    chipClass: "border-slate-200/30 bg-slate-200/10 text-slate-100",
    auraClass: "from-slate-200/18 via-slate-400/8 to-transparent",
    gridClass: "from-slate-200/8 to-transparent",
  },
];

function StatusChip({ label, className }: { label: string; className: string }) {
  return (
    <div className={`rounded-full border px-4 py-2 text-[0.7rem] font-benderBold tracking-[0.32em] ${className}`}>
      {label}
    </div>
  );
}

function RouteCard({
  mood,
  active,
  onActivate,
}: {
  mood: RouteMood;
  active: boolean;
  onActivate: (id: RouteMood["id"]) => void;
}) {
  return (
    <a
      href={mood.href}
      target="_self"
      onMouseEnter={() => onActivate(mood.id)}
      onFocus={() => onActivate(mood.id)}
      className={[
        "group relative overflow-hidden rounded-[1.75rem] border bg-black/35 px-6 py-6 text-inherit no-underline transition-all duration-300",
        "panel-grid panel-noise scanlines backdrop-blur-md",
        mood.frameClass,
        active ? "translate-x-0 scale-100 glow-frame" : "translate-x-0 opacity-90",
      ].join(" ")}
    >
      <div className={`absolute inset-0 bg-gradient-to-br ${mood.auraClass} opacity-80 transition-opacity duration-300`} />
      <div
        className="absolute right-4 top-4 h-2.5 w-2.5 rounded-full shadow-[0_0_18px_currentColor]"
        style={{ color: mood.accent }}
      />
      <div className="relative">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-[0.72rem] font-benderBold tracking-[0.35em] text-white/55">{mood.label}</div>
            <div className="mt-3 text-[1.9rem] font-benderBold tracking-[0.08em] text-white">{mood.title}</div>
            <div className="mt-2 text-[0.95rem] font-benderBold tracking-[0.25em] text-white/55">{mood.subTitle}</div>
          </div>
          <StatusChip label={mood.badge} className={mood.chipClass} />
        </div>

        <p className="mt-6 max-w-[28rem] text-[0.98rem] leading-7 text-white/72">{mood.summary}</p>

        <div className="mt-6 flex items-center justify-between border-t border-white/10 pt-4">
          <div className="text-[0.78rem] font-benderBold tracking-[0.25em] text-white/45">{mood.status}</div>
          <div className="text-[0.85rem] font-benderBold tracking-[0.25em] text-white transition-transform duration-300 group-hover:translate-x-1">
            {mood.actionLabel}
          </div>
        </div>
      </div>
    </a>
  );
}

export default function Index() {
  const { title, subtitle, url, copyright } = arknightsConfig.rootPage.INDEX;
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);

  const [active, setActive] = useState($viewIndex === 0);
  const [videoLoaded, setVideoLoaded] = useState(false);
  const [activeRouteId, setActiveRouteId] = useState<RouteMood["id"]>("docs");
  const videoRef = useRef<HTMLVideoElement>(null);

  const activeRoute = useMemo(
    () => routeMoods.find((item) => item.id === activeRouteId) ?? routeMoods[1],
    [activeRouteId],
  );

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return undefined;

    const handleLoadedData = () => {
      setVideoLoaded(true);
      if ($viewIndex === 0 && $readyToTouch) {
        video.play().catch(() => undefined);
      }
    };

    const handleTimeUpdate = () => {
      if (video.currentTime >= VIDEO_LOOP_END) {
        video.currentTime = VIDEO_LOOP_START;
      }
    };

    video.src = VIDEO_PATH;
    video.preload = "metadata";
    video.load();
    video.addEventListener("loadeddata", handleLoadedData);
    video.addEventListener("timeupdate", handleTimeUpdate);

    return () => {
      video.removeEventListener("loadeddata", handleLoadedData);
      video.removeEventListener("timeupdate", handleTimeUpdate);
    };
  }, [$readyToTouch, $viewIndex]);

  useEffect(() => {
    const isActive = $viewIndex === 0 && $readyToTouch;
    if (isActive) {
      directions.set({ top: false, right: true, bottom: true, left: false });
      videoRef.current?.play().catch(() => undefined);
    } else {
      videoRef.current?.pause();
    }
    setActive(isActive);
  }, [$readyToTouch, $viewIndex]);

  return (
    <div className="absolute inset-0 z-[2] h-full w-[100vw] max-w-[180rem] overflow-hidden transition-opacity duration-100">
      <div className="absolute inset-0 bg-index bg-cover bg-center bg-no-repeat" />
      <video
        ref={videoRef}
        className={`absolute inset-0 h-full w-full object-cover transition-opacity duration-1000 ${videoLoaded ? "opacity-70" : "opacity-0"}`}
        loop
        muted
        playsInline
        poster={`${base}images/index-bg.jpg`}
      />

      <div className="absolute inset-0 bg-[linear-gradient(115deg,rgba(2,6,23,.92),rgba(2,6,23,.55)_48%,rgba(2,6,23,.88))]" />
      <div className={`absolute inset-0 bg-gradient-to-br ${activeRoute.auraClass} transition-all duration-500`} />
      <div className="absolute inset-0 panel-grid opacity-35" />
      <div className="absolute inset-0 panel-noise opacity-60 mix-blend-screen" />
      <div className={`absolute inset-y-0 right-0 w-[42rem] bg-gradient-to-l ${activeRoute.gridClass} transition-all duration-500`} />

      <div className="absolute left-[4.5rem] right-[4.5rem] top-[8.35rem] z-[2] flex items-start justify-between gap-6 portrait:left-[1.75rem] portrait:right-[1.75rem] portrait:top-[8.75rem] portrait:flex-col">
        <div className="flex flex-wrap gap-3 portrait:gap-2">
          <StatusChip label="COMMAND NEXUS" className="border-white/15 bg-black/35 text-white/75" />
          <StatusChip label={activeRoute.status} className={activeRoute.chipClass} />
          <StatusChip label="VIDEO LOOP // 00:07" className="border-white/15 bg-black/35 text-white/55" />
        </div>
        <div className="max-w-[32rem] text-right portrait:text-left">
          <div className="text-[0.75rem] font-benderBold tracking-[0.42em] text-white/45">ACTIVE SIGNAL</div>
          <div className="mt-2 text-[0.95rem] font-benderBold tracking-[0.26em] text-white/80">{activeRoute.signal}</div>
        </div>
      </div>

      <div className="absolute inset-x-0 bottom-[3.2rem] top-[12.8rem] z-[2] grid grid-cols-[minmax(0,1.2fr)_minmax(25rem,38rem)] gap-10 px-[4.5rem] portrait:top-[12.75rem] portrait:bottom-[2rem] portrait:grid-cols-1 portrait:gap-6 portrait:px-[1.75rem]">
        <section className={`relative overflow-hidden rounded-[2.3rem] border border-white/10 bg-black/30 p-9 backdrop-blur-md transition-all duration-500 ${active ? "opacity-100" : "opacity-0"}`}>
          <div className="absolute inset-0 panel-grid opacity-40" />
          <div className="absolute inset-0 panel-noise opacity-55" />
          <div className={`absolute inset-0 bg-gradient-to-br ${activeRoute.auraClass} opacity-95 transition-all duration-500`} />

          <div className="relative flex h-full flex-col justify-between">
            <div>
              <div className="text-[0.82rem] font-benderBold tracking-[0.45em] text-white/45">CORN KINGDOM // COMMAND PANEL</div>
              <div className="mt-5 flex items-end gap-5 portrait:flex-col portrait:items-start portrait:gap-3">
                <div className="text-[5.2rem] font-n15eUltraBold leading-[0.8] text-white portrait:text-[2.8rem]">{title}</div>
                <div className="pb-2">
                  <div className="text-[1.05rem] font-benderBold tracking-[0.28em] text-white/80">{subtitle}</div>
                  <div className="mt-2 text-[0.82rem] font-benderBold tracking-[0.3em] text-white/45">{url}</div>
                </div>
              </div>

              <div className="mt-10 max-w-[44rem] rounded-[1.6rem] border border-white/10 bg-black/30 px-6 py-5">
                <div className="text-[0.72rem] font-benderBold tracking-[0.32em] text-white/45">ROUTE BRIEFING</div>
                <div className="mt-3 text-[2rem] font-benderBold tracking-[0.08em] text-white portrait:text-[1.55rem]">{activeRoute.title}</div>
                <p className="mt-4 max-w-[38rem] text-[1rem] leading-8 text-white/72">{activeRoute.summary}</p>
              </div>
            </div>

            <div className="flex items-end justify-between gap-6 portrait:flex-col portrait:items-start">
              <div className="grid gap-3 sm:grid-cols-3">
                {routeMoods.map((mood) => (
                  <button
                    key={mood.id}
                    type="button"
                    onMouseEnter={() => setActiveRouteId(mood.id)}
                    onFocus={() => setActiveRouteId(mood.id)}
                    onClick={() => setActiveRouteId(mood.id)}
                    className={[
                      "rounded-[1.15rem] border px-4 py-4 text-left transition-all duration-300",
                      activeRoute.id === mood.id ? mood.chipClass : "border-white/12 bg-black/25 text-white/55 hover:text-white",
                    ].join(" ")}
                  >
                    <div className="text-[0.72rem] font-benderBold tracking-[0.32em]">{mood.label}</div>
                    <div className="mt-3 text-[1rem] font-benderBold tracking-[0.12em]">{mood.subTitle}</div>
                  </button>
                ))}
              </div>

              <div className="w-[8.5rem] portrait:w-[7.25rem]">{copyright}</div>
            </div>
          </div>
        </section>

        <aside className="grid content-start gap-5">
          {routeMoods.map((mood) => (
            <RouteCard
              key={mood.id}
              mood={mood}
              active={activeRoute.id === mood.id}
              onActivate={setActiveRouteId}
            />
          ))}

          <a
            href="https://github.com/p0pC03N"
            target="_blank"
            className="group relative overflow-hidden rounded-[1.5rem] border border-white/10 bg-black/30 px-6 py-5 text-inherit no-underline panel-grid panel-noise backdrop-blur-md transition-colors duration-300 hover:border-white/30"
          >
            <div className="relative flex items-center justify-between gap-6">
              <div>
                <div className="text-[0.72rem] font-benderBold tracking-[0.32em] text-white/45">REPOSITORY LINK</div>
                <div className="mt-3 text-[1.4rem] font-benderBold tracking-[0.1em] text-white">OPEN GITHUB</div>
              </div>
              <div className="text-[0.82rem] font-benderBold tracking-[0.26em] text-white transition-transform duration-300 group-hover:translate-x-1">
                SOURCE ONLINE
              </div>
            </div>
          </a>
        </aside>
      </div>
    </div>
  );
}
