import React, { useEffect, useRef, useState } from "react";

type Props = {
  defaultEnabled?: boolean;
};

export default function ArkCursor({ defaultEnabled = true }: Props) {
  const [enabled, setEnabled] = useState(defaultEnabled);
  const [isTouch, setIsTouch] = useState(false);
  const [isHover, setIsHover] = useState(false);
  const [isDown, setIsDown] = useState(false);

  const dotRef = useRef<HTMLDivElement | null>(null);
  const ringRef = useRef<HTMLDivElement | null>(null);

  const pos = useRef({ x: 0, y: 0 });
  const ring = useRef({ x: 0, y: 0 });
  const raf = useRef<number | null>(null);

  useEffect(() => {
    const touch =
      "ontouchstart" in window ||
      (navigator as any).maxTouchPoints > 0 ||
      window.matchMedia?.("(pointer: coarse)").matches;

    setIsTouch(!!touch);
    if (touch) setEnabled(false);
  }, []);

  useEffect(() => {
    if (!enabled || isTouch) {
      if (dotRef.current) dotRef.current.style.opacity = "0";
      if (ringRef.current) ringRef.current.style.opacity = "0";
      if (raf.current) {
        cancelAnimationFrame(raf.current);
        raf.current = null;
      }
      return;
    }

    const dot = dotRef.current!;
    const ringEl = ringRef.current!;

    const move = (e: MouseEvent) => {
      pos.current.x = e.clientX;
      pos.current.y = e.clientY;

      // ✅ 第一次移动时把拖尾位置也初始化到当前位置
      if (ring.current.x === 0 && ring.current.y === 0) {
        ring.current.x = e.clientX;
        ring.current.y = e.clientY;
      }

      dot.style.opacity = "1";
      ringEl.style.opacity = "1";
    };

    const down = () => setIsDown(true);
    const up = () => setIsDown(false);

    const onOver = (e: MouseEvent) => {
      const t = e.target as HTMLElement | null;
      if (!t) return;
      if (t.closest("a,button,[role='button'],input,textarea,select,label")) {
        setIsHover(true);
      }
    };
    const onOut = () => setIsHover(false);

    window.addEventListener("mousemove", move, { passive: true });
    window.addEventListener("mousedown", down);
    window.addEventListener("mouseup", up);
    window.addEventListener("mouseover", onOver);
    window.addEventListener("mouseout", onOut);

    const tick = () => {
      const dx = pos.current.x - ring.current.x;
      const dy = pos.current.y - ring.current.y;
      ring.current.x += dx * 0.12;
      ring.current.y += dy * 0.12;

      dot.style.transform = `translate3d(${pos.current.x}px, ${pos.current.y}px, 0)`;
      ringEl.style.transform = `translate3d(${ring.current.x}px, ${ring.current.y}px, 0)`;

      raf.current = requestAnimationFrame(tick);
    };

    raf.current = requestAnimationFrame(tick);

    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mousedown", down);
      window.removeEventListener("mouseup", up);
      window.removeEventListener("mouseover", onOver);
      window.removeEventListener("mouseout", onOut);
      if (raf.current) cancelAnimationFrame(raf.current);
      raf.current = null;
    };
  }, [enabled, isTouch]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && (e.key === "m" || e.key === "M")) setEnabled((v) => !v);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (isTouch) return null;

  return (
    <>
      <div
        ref={ringRef}
        className={[
          "fixed left-0 top-0 z-[9999] pointer-events-none",
          "w-10 h-10 -translate-x-1/2 -translate-y-1/2 rounded-full",
          "border border-white/60",
          "opacity-0 transition-[width,height,opacity,border-color,transform] duration-200",
          isHover ? "w-14 h-14 border-white" : "",
          isDown ? "w-20 h-20 border-white/80" : "",
        ].join(" ")}
        style={{
          mixBlendMode: "screen",
          backdropFilter: "blur(2px)",
        }}
      />

      <div
        ref={dotRef}
        className={[
          "fixed left-0 top-0 z-[9999] pointer-events-none",
          "w-2.5 h-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full",
          "bg-white",
          "opacity-0 transition-[opacity,transform] duration-100",
          isHover ? "scale-150" : "",
          isDown ? "scale-75" : "",
        ].join(" ")}
        style={{ mixBlendMode: "screen" }}
      />
    </>
  );
}

