import { useEffect, useRef, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";

const sceneSrc = `${import.meta.env.BASE_URL}friend-links/`;

export default function Operator() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const isActive = $viewIndex === 2 && $readyToTouch;

  const [hasVisited, setHasVisited] = useState(false);
  const iframe = useRef<HTMLIFrameElement>(null);

  const syncActivity = () => {
    iframe.current?.contentWindow?.postMessage(
      { type: "arcana:activity", active: isActive },
      window.location.origin,
    );
  };

  useEffect(() => {
    // Load behind the site's intro, instead of adding another wait after it.
    if ($viewIndex === 2) setHasVisited(true);
    if (isActive) {
      directions.set({ top: true, right: true, bottom: true, left: false });
    }
    syncActivity();
    // Also synchronize when modules initialize after iframe.onload.
    const handleReady = (event: MessageEvent) => {
      if (
        event.origin === window.location.origin &&
        event.source === iframe.current?.contentWindow &&
        event.data?.type === "arcana:ready"
      ) syncActivity();
    };
    window.addEventListener("message", handleReady);
    return () => window.removeEventListener("message", handleReady);
  }, [$viewIndex, isActive]);

  return (
    <div
      className={`w-[100vw] max-w-[180rem] h-full absolute top-0 right-0 bottom-0 left-auto transition-all duration-1000 ${
        isActive
          ? "opacity-100 visible pointer-events-auto"
          : "opacity-0 invisible pointer-events-none"
      }`}
    >
      <section className="w-full h-full relative overflow-hidden bg-black">
        {hasVisited && (
          <iframe
            ref={iframe}
            src={sceneSrc}
            title="塔罗友链"
            data-shared-cursor="true"
            className="w-full h-full border-0 block"
            onLoad={syncActivity}
            tabIndex={isActive ? 0 : -1}
          />
        )}
      </section>
    </div>
  );
}
