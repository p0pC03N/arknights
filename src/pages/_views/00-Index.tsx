import { useEffect, useRef, useState } from "react";
import { useStore } from "@nanostores/react";
import { directions } from "../../components/store/lineDecoratorStore";
import { readyToTouch, viewIndex } from "../../components/store/rootLayoutStore.ts";
import SandtableMap, { type SandtableCamp } from "../../components/SandtableMap";

const base = import.meta.env.BASE_URL;
const VIDEO_PATH = `${base}videos/home.mp4`;
const VIDEO_LOOP_START = 0.2;
const VIDEO_LOOP_END = 7.4;

const camps: SandtableCamp[] = [
  {
    id: "blog",
    title: "BLOG",
    hint: "日常生活喵",
    href: `${base}blog/`,
    accent: "#facc15",
    textClass: "text-yellow-100",
    glowClass: "glow-amber",
    position: { x: 24, y: 67 },
  },
  {
    id: "docs",
    title: "DOCS",
    hint: "小小知识笔记",
    href: `${base}docs/`,
    accent: "#38bdf8",
    textClass: "text-sky-100",
    glowClass: "glow-blue",
    position: { x: 54, y: 34 },
  },
  {
    id: "secret",
    title: "SECRET",
    hint: ">w<",
    href: `${base}#media`,
    accent: "#e2e8f0",
    textClass: "text-slate-100",
    glowClass: "glow-neutral",
    position: { x: 76, y: 58 },
  },
];

export default function Index() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);

  const [active, setActive] = useState($viewIndex === 0);
  const [videoLoaded, setVideoLoaded] = useState(false);
  const [activeCampId, setActiveCampId] = useState<SandtableCamp["id"]>("docs");
  const videoRef = useRef<HTMLVideoElement>(null);

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
        className={`absolute inset-0 h-full w-full object-cover transition-opacity duration-1000 ${videoLoaded ? "opacity-30" : "opacity-0"}`}
        muted
        playsInline
        poster={`${base}images/index-bg.jpg`}
      />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(255,255,255,.08),transparent_22%),linear-gradient(180deg,rgba(2,6,23,.78),rgba(2,6,23,.92))]" />
      <div className="absolute inset-0 panel-grid opacity-20" />
      <div className="absolute inset-x-[3rem] top-[7.8rem] bottom-[2rem] z-[2] portrait:inset-x-[1rem] portrait:top-[8.5rem]">
        <div className={`h-full transition-all duration-500 ${active ? "opacity-100 translate-y-0" : "opacity-0 translate-y-10"}`}>
          <SandtableMap camps={camps} activeId={activeCampId} onActivate={setActiveCampId} />
        </div>
      </div>
    </div>
  );
}
