import { useEffect, useRef, useState } from "react";

type Dust = {
  x: number; y: number; vx: number; vy: number;
  nx: number; ny: number; seed: number; radius: number;
  color: string; alpha: number; part: "eye" | "ear" | "head" | "body" | "tail";
};

const guardianSrc = `${import.meta.env.BASE_URL}images/archive/xiaohei.svg`;

export default function ArchiveGuardian({ active, resting, signal }: {
  active: boolean; resting: boolean; signal: number;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const controller = useRef<(() => void) | null>(null);
  const activity = useRef({ active, resting, signal });
  const [ready, setReady] = useState(false);

  useEffect(() => {
    activity.current = { active, resting, signal };
    controller.current?.();
  }, [active, resting, signal]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const holder = canvas?.parentElement;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !holder || !ctx) return;
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const compact = matchMedia("(pointer: coarse)").matches;
    let width = 0, height = 0, frame = 0, last = 0, elapsed = 0;
    let loaded = false, disposed = false;
    let points: Dust[] = [];
    let signalAt = -10000, previousSignal = activity.current.signal;
    const pointer = { x: -1000, y: -1000 };
    const brush = { x: 0, y: 0, active: false, speed: 0 };
    let gaze = 0;
    let nextBlink = 3600 + Math.random() * 1800;
    const motes = Array.from({ length: compact ? 28 : 52 }, () => ({
      x: Math.random(), y: Math.random(), size: Math.random() * 1.1 + .3,
      speed: Math.random() * .000012 + .000007, phase: Math.random() * 6.28,
    }));
    const ease = (t: number) => 1 - (1 - Math.max(0, Math.min(1, t))) ** 3;

    function draw(now: number) {
      frame = 0;
      if (disposed || !activity.current.active || document.hidden || !loaded || !width || !height) return;
      // Allow normal 60 Hz frames through, including slightly short vsync intervals.
      const interval = activity.current.resting || compact ? 30 : 15;
      if (last && now - last < interval && !reduced) { frame = requestAnimationFrame(draw); return; }
      const dt = last ? Math.min(now - last, 34) : 16;
      elapsed += dt;
      last = now;
      if (previousSignal !== activity.current.signal) {
        previousSignal = activity.current.signal;
        signalAt = elapsed;
      }
      ctx!.clearRect(0, 0, width, height);
      const progress = reduced ? 1 : Math.min(1, elapsed / 2100);
      const s = Math.min(width / 460, height / 510);
      const cx = width * .48, cy = height * .53;
      const interacting = !reduced && !compact && !activity.current.resting && pointer.x >= 0;
      const fromX = brush.active ? brush.x : pointer.x;
      const fromY = brush.active ? brush.y : pointer.y;
      brush.active = interacting;
      brush.x = pointer.x;
      brush.y = pointer.y;
      const sweepX = brush.x - fromX, sweepY = brush.y - fromY;
      const sweepLength = sweepX * sweepX + sweepY * sweepY;
      brush.speed += ((interacting ? Math.min(1, Math.sqrt(sweepLength) / 40) : 0) - brush.speed) * .3;
      const targetGaze = interacting ? Math.max(-1, Math.min(1, (pointer.x - cx) / 180)) : 0;
      gaze += (targetGaze - gaze) * (1 - Math.exp(-dt / 145));
      const breath = reduced ? 0 : Math.sin(elapsed * .0012) * 2;
      const blinkTime = elapsed - nextBlink;
      let blink = 0;
      if (!reduced && blinkTime >= 0) {
        if (blinkTime < 85) blink = ease(blinkTime / 85);
        else if (blinkTime < 120) blink = 1;
        else if (blinkTime < 285) blink = 1 - ease((blinkTime - 120) / 165);
        else nextBlink = elapsed + 3400 + Math.random() * 4300;
      }
      for (const mote of motes) {
        const y = reduced ? mote.y : (mote.y - elapsed * mote.speed % 1 + 1) % 1;
        ctx!.fillStyle = `rgba(198,216,209,${.1 + .16 * Math.sin(mote.phase + elapsed * .0005) ** 2})`;
        ctx!.beginPath(); ctx!.arc(mote.x * width, y * height, mote.size, 0, Math.PI * 2); ctx!.fill();
      }
      for (const point of points) {
        const isHead = point.part === "head" || point.part === "eye" || point.part === "ear";
        const delay = point.part === "eye" ? .35 : isHead ? .13 : 0;
        const entry = ease((progress - delay) / (1 - delay));
        let tx = cx + (point.nx - 210) * s;
        let ty = cy + (point.ny - 245) * s + breath;
        if (!reduced && point.part === "tail") tx += Math.sin(elapsed * .0016 + point.ny * .012) * 5 * s;
        if (isHead) {
          const tilt = gaze * .055;
          tx -= (ty - (cy + 25 * s)) * tilt;
          ty += (tx - cx) * tilt;
        }
        if (entry < 1) {
          tx += Math.sin(point.seed) * (1 - entry) * width * .55;
          ty += (1 - entry) * (height * .55 + Math.cos(point.seed) * 70);
        }
        const step = dt / 16.67;
        if (interacting) {
          // Sweep along the pointer path so quick passes still catch nearby dust.
          const along = sweepLength > 0 && sweepLength < 180 ** 2
            ? Math.max(0, Math.min(1, ((point.x - fromX) * sweepX + (point.y - fromY) * sweepY) / sweepLength))
            : 1;
          const dx = point.x - (fromX + along * sweepX), dy = point.y - (fromY + along * sweepY);
          const dist = Math.hypot(dx, dy);
          const radius = Math.max(75, Math.min(115, 92 * s));
          if (dist < radius && dist > .1) {
            const proximity = 1 - dist / radius;
            const force = proximity ** 1.4 * (2.8 + brush.speed * 3.4) * (point.part === "eye" ? .45 : 1);
            point.vx += dx / dist * force * step;
            point.vy += dy / dist * force * step;
          }
        }
        point.vx += (tx - point.x) * .025 * step;
        point.vy += (ty - point.y) * .025 * step;
        point.vx *= Math.pow(.86, step); point.vy *= Math.pow(.86, step);
        point.x = reduced ? tx : point.x + point.vx * step;
        point.y = reduced ? ty : point.y + point.vy * step;
        let visibility = .84 + Math.sin(elapsed * .001 + point.seed) * .16;
        if (point.part === "eye") {
          // Occlude the eye from the top without moving or compressing its particles.
          const eyeCenterX = point.nx < 186 ? 117 : 254;
          const lid = 114 + blink * 171 + 9 * (1 - ((point.nx - eyeCenterX) / 65) ** 2);
          visibility = blink === 0 ? 1 : Math.max(0, Math.min(1, (point.ny - lid) / 7));
        }
        ctx!.globalAlpha = point.alpha * entry * visibility;
        ctx!.fillStyle = point.color;
        ctx!.beginPath(); ctx!.arc(point.x, point.y, point.radius * Math.max(.6, s), 0, Math.PI * 2); ctx!.fill();
      }
      // A brief thread of dust travels toward the selected archive.
      const transfer = (elapsed - signalAt) / 1000;
      if (!reduced && transfer > 0 && transfer < 1) {
        for (let i = 0; i < 16; i++) {
          const t = Math.max(0, transfer - i * .012);
          ctx!.globalAlpha = Math.sin(transfer * Math.PI) * (1 - i / 18) * .8;
          ctx!.fillStyle = "#c5dfb7";
          ctx!.beginPath(); ctx!.arc(cx - t * width * .5, cy + Math.sin(t * Math.PI) * 45, 1.3, 0, Math.PI * 2); ctx!.fill();
        }
      }
      ctx!.globalAlpha = 1;
      if (!reduced) frame = requestAnimationFrame(draw);
    }

    function sync() {
      cancelAnimationFrame(frame);
      last = 0;
      if (activity.current.active && !document.hidden && loaded) frame = requestAnimationFrame(draw);
    }
    controller.current = sync;
    const observer = new ResizeObserver(([entry]) => {
      width = entry.contentRect.width; height = entry.contentRect.height;
      const dpr = Math.min(devicePixelRatio || 1, compact ? 1.25 : 1.5);
      canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      sync();
    });
    observer.observe(holder);
    const move = (event: PointerEvent) => {
      if (event.pointerType === "touch") return;
      const rect = canvas.getBoundingClientRect(); pointer.x = event.clientX - rect.left; pointer.y = event.clientY - rect.top;
    };
    const leave = () => { pointer.x = -1000; pointer.y = -1000; };
    holder.addEventListener("pointermove", move, { passive: true });
    holder.addEventListener("pointerleave", leave);
    document.addEventListener("visibilitychange", sync);
    const image = new Image();
    image.onload = () => {
      if (disposed) return;
      const sample = document.createElement("canvas"); sample.width = 420; sample.height = 480;
      const sampleCtx = sample.getContext("2d");
      if (!sampleCtx) return;
      sampleCtx.drawImage(image, 0, 0, 420, 480);
      const pixels = sampleCtx.getImageData(0, 0, 420, 480).data;
      const candidates: Dust[] = [];
      for (let y = 0; y < 480; y += 3) for (let x = 0; x < 420; x += 3) {
        const index = (y * 420 + x) * 4;
        const r = pixels[index], g = pixels[index + 1], b = pixels[index + 2], a = pixels[index + 3];
        const brightness = Math.max(r, g, b);
        if (a < 120 || brightness < 38) continue;
        const bright = brightness > 100;
        if (Math.random() > (bright ? .9 : .13)) continue;
        const eye = r > 185 && g > 185 && b > 165;
        const ear = y < 225 && g > r * 1.1;
        const part: Dust["part"] = eye ? "eye" : ear ? "ear" : x > 250 && y > 320 ? "tail" : y < 318 ? "head" : "body";
        const seed = Math.random() * Math.PI * 2;
        candidates.push({ nx: x + (Math.random() - .5) * 1.7, ny: y + (Math.random() - .5) * 1.7, x: width * .48 + Math.sin(seed) * width * .4, y: height * .9, vx: 0, vy: 0,
          seed, radius: eye ? .95 : Math.random() * .7 + .65, color: bright ? `rgb(${r},${g},${b})` : "#879c98",
          alpha: bright ? .7 + Math.random() * .3 : .12 + Math.random() * .16, part });
      }
      // Keep bright defining features when limiting the particle budget.
      points = candidates.sort((a, b) => b.alpha - a.alpha).slice(0, compact ? 1600 : 2600);
      loaded = true; setReady(true); sync();
    };
    image.src = guardianSrc;
    return () => {
      disposed = true; cancelAnimationFrame(frame); observer.disconnect(); controller.current = null;
      holder.removeEventListener("pointermove", move); holder.removeEventListener("pointerleave", leave);
      document.removeEventListener("visibilitychange", sync);
    };
  }, []);

  return <>
    <img className={`archive-guardian-fallback ${ready ? "is-ready" : ""}`} src={guardianSrc} alt="" aria-hidden="true" />
    <canvas ref={canvasRef} className="archive-guardian-canvas" role="img" aria-label="罗小黑形态的粒子守档人，鼠标靠近时尘埃会散开并重新聚合" />
  </>;
}
