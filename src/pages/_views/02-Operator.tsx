import { useEffect } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";

const prototypeSrc = `${import.meta.env.BASE_URL}friend-links-magic-phase1.html`;

export default function Operator() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const isActive = $viewIndex === 2 && $readyToTouch;

  useEffect(() => {
    if (!isActive) {
      return;
    }

    directions.set({ top: true, right: true, bottom: true, left: false });
  }, [isActive]);

  return (
    <div
      className={`w-[100vw] max-w-[180rem] h-full absolute top-0 right-0 bottom-0 left-auto transition-all duration-1000 ${
        isActive
          ? "opacity-100 visible pointer-events-auto"
          : "opacity-0 invisible pointer-events-none"
      }`}
    >
      <section className="w-full h-full relative overflow-hidden bg-black">
        <iframe
          src={prototypeSrc}
          title="Tarot Friend Links"
          data-native-cursor="true"
          className="w-full h-full border-0 block"
          allow="fullscreen"
        />

        <div className="absolute right-8 bottom-7 z-10 pointer-events-none select-none">
          <div className="px-4 py-2 border border-white/10 bg-black/45 backdrop-blur-md text-right">
            <div className="text-[0.72rem] tracking-[0.35em] text-[#f0d18c] font-bold">
              TAROT
            </div>
            <div className="mt-1 text-[0.75rem] text-white/72 tracking-[0.16em]">
              Friend Links Arcana
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
