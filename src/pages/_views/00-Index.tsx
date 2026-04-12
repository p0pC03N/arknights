import { useEffect, useState } from "react";
import { useStore } from "@nanostores/react";
import { directions } from "../../components/store/lineDecoratorStore";
import { readyToTouch, viewIndex } from "../../components/store/rootLayoutStore.ts";
import SandtableMap, { type SandtableCamp } from "../../components/SandtableMap";

const base = import.meta.env.BASE_URL;

const camps: SandtableCamp[] = [
  {
    id: "blog",
    title: "BLOG",
    hint: "\u65e5\u5e38\u751f\u6d3b\u55b5",
    href: `${base}blog/`,
    accent: "#facc15",
    textClass: "text-yellow-100",
    glowClass: "glow-amber",
    position: { x: 18, y: 76 },
  },
  {
    id: "docs",
    title: "DOCS",
    hint: "\u5c0f\u5c0f\u77e5\u8bc6\u7b14\u8bb0",
    href: `${base}docs/`,
    accent: "#38bdf8",
    textClass: "text-sky-100",
    glowClass: "glow-blue",
    position: { x: 44, y: 28 },
  },
  {
    id: "secret",
    title: "SECRET",
    hint: ">w<",
    href: `${base}#media`,
    accent: "#e2e8f0",
    textClass: "text-slate-100",
    glowClass: "glow-neutral",
    position: { x: 74, y: 46 },
  },
];

export default function Index() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);

  const [active, setActive] = useState($viewIndex === 0);
  const [activeCampId, setActiveCampId] = useState<SandtableCamp["id"]>("docs");

  useEffect(() => {
    const isActive = $viewIndex === 0 && $readyToTouch;
    if (isActive) {
      directions.set({ top: false, right: true, bottom: true, left: false });
    }
    setActive(isActive);
  }, [$readyToTouch, $viewIndex]);

  return (
    <div className="absolute inset-0 z-[2] h-full w-[100vw] max-w-[180rem] overflow-hidden transition-opacity duration-100">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_12%,rgba(250,204,21,.08),transparent_20%),radial-gradient(circle_at_78%_18%,rgba(56,189,248,.08),transparent_18%),linear-gradient(180deg,#03060a,#02060b_52%,#010306)]" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(255,255,255,.03),transparent_48%)]" />
      <div className="absolute inset-0 panel-grid opacity-[0.12]" />
      <div className="absolute inset-x-0 bottom-0 h-[18rem] bg-[linear-gradient(180deg,transparent,rgba(1,3,6,.94))]" />

      <div className="absolute inset-x-[3rem] top-[7.8rem] bottom-[2rem] z-[2] portrait:inset-x-[1rem] portrait:top-[8.5rem]">
        <div className={`h-full transition-all duration-500 ${active ? "translate-y-0 opacity-100" : "translate-y-10 opacity-0"}`}>
          <SandtableMap camps={camps} activeId={activeCampId} onActivate={setActiveCampId} />
        </div>
      </div>
    </div>
  );
}
