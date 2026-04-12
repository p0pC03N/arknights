import { useMemo, useState } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";

export type SandtableCamp = {
  id: "blog" | "docs" | "secret";
  title: string;
  hint: string;
  href: string;
  accent: string;
  textClass: string;
  glowClass: string;
  position: { x: number; y: number };
};

function TerrainPlane({ tiltX, tiltY }: { tiltX: number; tiltY: number }) {
  const transform = `translate(-50%, -50%) rotateX(${66 + tiltY * 2}deg) rotateZ(${-20 + tiltX * 1.8}deg)`;

  return (
    <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
      <div className="relative h-[80%] w-[86%] [perspective:1800px] portrait:h-[72%] portrait:w-[120%]">
        <div
          className="absolute left-1/2 top-1/2 h-[85%] w-full overflow-hidden rounded-[2.6rem] border border-white/10 bg-[#060b10] shadow-[0_40px_120px_rgba(0,0,0,.55)]"
          style={{ transform, transformStyle: "preserve-3d" }}
        >
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_25%_28%,rgba(255,255,255,0.12),transparent_18%),radial-gradient(circle_at_48%_36%,rgba(56,189,248,0.09),transparent_22%),radial-gradient(circle_at_78%_58%,rgba(255,255,255,0.08),transparent_16%),linear-gradient(180deg,#17222b,#0a1218_54%,#060a0d)]" />
          <div className="absolute inset-0 panel-grid opacity-45" />
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_26%_34%,rgba(250,204,21,0.12),transparent_14%),radial-gradient(circle_at_58%_24%,rgba(56,189,248,0.12),transparent_18%),radial-gradient(circle_at_70%_65%,rgba(248,250,252,0.1),transparent_14%),radial-gradient(circle_at_38%_60%,rgba(255,255,255,0.06),transparent_24%)]" />

          <svg className="absolute inset-0 h-full w-full opacity-80" viewBox="0 0 1000 700" fill="none" preserveAspectRatio="none">
            <path d="M0 482C126 422 213 454 302 401C382 354 433 260 532 232C637 202 705 257 811 229C884 210 939 175 1000 146" stroke="rgba(148,163,184,.28)" strokeWidth="2" />
            <path d="M0 522C126 462 213 494 302 441C382 394 433 300 532 272C637 242 705 297 811 269C884 250 939 215 1000 186" stroke="rgba(148,163,184,.22)" strokeWidth="2" />
            <path d="M0 562C126 502 213 534 302 481C382 434 433 340 532 312C637 282 705 337 811 309C884 290 939 255 1000 226" stroke="rgba(148,163,184,.18)" strokeWidth="2" />
            <path d="M80 188C180 148 242 124 334 140C432 158 482 204 560 214C644 224 714 186 776 170C848 152 910 156 962 184" stroke="rgba(248,250,252,.14)" strokeWidth="2" />
            <path d="M138 232C206 208 270 194 338 204C414 216 472 252 548 264C644 278 708 250 774 228C840 206 900 206 958 228" stroke="rgba(248,250,252,.12)" strokeWidth="2" />
            <path d="M150 310C206 290 272 278 344 288C412 300 458 330 530 350C620 374 698 354 770 334C846 312 912 308 968 324" stroke="rgba(248,250,252,.1)" strokeWidth="2" />
            <path d="M88 645C188 584 310 526 394 468C472 414 514 358 588 322C662 286 724 292 790 250C850 212 900 148 964 114" stroke="rgba(56,189,248,.72)" strokeWidth="5" strokeLinecap="round" />
            <path d="M118 620C204 568 316 514 394 456C468 402 514 352 582 320C650 288 720 292 784 256C840 224 888 178 946 140" stroke="rgba(255,255,255,.24)" strokeWidth="12" strokeLinecap="round" />
          </svg>

          <div className="absolute left-[18%] top-[20%] h-[20%] w-[24%] rounded-full bg-white/10 blur-[60px]" />
          <div className="absolute left-[46%] top-[24%] h-[18%] w-[22%] rounded-full bg-sky-300/12 blur-[58px]" />
          <div className="absolute left-[62%] top-[46%] h-[16%] w-[18%] rounded-full bg-white/8 blur-[52px]" />
          <div className="absolute inset-x-[10%] bottom-[10%] h-[22%] bg-[linear-gradient(180deg,transparent,rgba(2,6,23,.82))]" />
        </div>
      </div>
    </div>
  );
}

export default function SandtableMap({
  camps,
  activeId,
  onActivate,
}: {
  camps: SandtableCamp[];
  activeId: SandtableCamp["id"];
  onActivate: (id: SandtableCamp["id"]) => void;
}) {
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const activeCamp = useMemo(
    () => camps.find((camp) => camp.id === activeId) ?? camps[0],
    [activeId, camps],
  );

  function handlePointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    const rect = event.currentTarget.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width - 0.5;
    const y = (event.clientY - rect.top) / rect.height - 0.5;
    setTilt({ x: x * 10, y: y * 8 });
  }

  function handlePointerLeave() {
    setTilt({ x: 0, y: 0 });
  }

  return (
    <div
      className="relative aspect-[16/10] w-full overflow-hidden rounded-[2.6rem] border border-white/10 bg-[#02060a]/72 glow-frame"
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_18%,rgba(250,204,21,0.12),transparent_20%),radial-gradient(circle_at_78%_18%,rgba(56,189,248,0.12),transparent_20%),radial-gradient(circle_at_78%_70%,rgba(248,250,252,0.08),transparent_18%),linear-gradient(180deg,rgba(2,6,23,.2),rgba(2,6,23,.82))]" />
      <TerrainPlane tiltX={tilt.x} tiltY={tilt.y} />

      <div className="absolute inset-x-0 top-0 z-[2] flex items-start justify-between px-6 pt-5 portrait:flex-col portrait:gap-3 portrait:px-4">
        <div>
          <div className="text-[0.72rem] font-benderBold tracking-[0.42em] text-white/45">TACTICAL TABLE</div>
          <div className="mt-2 text-[2.6rem] font-benderBold tracking-[0.08em] text-white portrait:text-[1.9rem]">玉米王国</div>
        </div>

        <div className="rounded-[1rem] border border-white/10 bg-black/40 px-4 py-3 backdrop-blur-md">
          <div className="text-[0.65rem] font-benderBold tracking-[0.35em] text-white/40">ACTIVE MARKER</div>
          <div className={`mt-2 text-[1.35rem] font-benderBold tracking-[0.08em] ${activeCamp.textClass}`}>{activeCamp.title}</div>
          <div className="mt-1 text-[0.92rem] text-white/72">{activeCamp.hint}</div>
        </div>
      </div>

      <div className="absolute inset-0 z-[3]">
        {camps.map((camp, index) => (
          <a
            key={camp.id}
            href={camp.href}
            target="_self"
            onMouseEnter={() => onActivate(camp.id)}
            onFocus={() => onActivate(camp.id)}
            className="group absolute -translate-x-1/2 -translate-y-1/2 text-inherit no-underline"
            style={{ left: `${camp.position.x}%`, top: `${camp.position.y}%` }}
          >
            <div
              className="absolute left-1/2 top-[1.2rem] h-[3.4rem] w-px -translate-x-1/2 bg-white/35"
              style={{ boxShadow: `0 0 18px ${camp.accent}` }}
            />
            <div
              className={`relative z-[2] flex h-[2.8rem] min-w-[7rem] items-center rounded-[0.9rem] border border-white/12 bg-black/55 px-3 backdrop-blur-md ${camp.glowClass}`}
              style={{ animation: `camp-float ${4.2 + index * 0.45}s ease-in-out infinite`, animationDelay: `${index * 0.15}s` }}
            >
              <div className="mr-3 h-2.5 w-2.5 rounded-full" style={{ backgroundColor: camp.accent, boxShadow: `0 0 18px ${camp.accent}` }} />
              <div>
                <div className={`text-[0.78rem] font-benderBold tracking-[0.28em] ${camp.textClass}`}>{camp.id.toUpperCase()}</div>
                <div className="mt-0.5 text-[0.72rem] text-white/55">ENTER</div>
              </div>
            </div>

            <div
              className={`absolute left-1/2 top-[-2.8rem] min-w-[8rem] -translate-x-1/2 rounded-full border border-white/12 bg-black/70 px-3 py-1.5 text-center text-[0.82rem] text-white/82 opacity-0 transition-all duration-300 group-hover:top-[-3.2rem] group-hover:opacity-100 ${
                activeCamp.id === camp.id ? "opacity-100 top-[-3.2rem]" : ""
              }`}
              style={{ animation: "flag-flicker 3.4s ease-in-out infinite" }}
            >
              {camp.hint}
            </div>
          </a>
        ))}
      </div>

      <div className="absolute inset-x-0 bottom-0 z-[2] flex items-center justify-between border-t border-white/10 bg-[linear-gradient(180deg,transparent,rgba(2,6,23,.85))] px-6 py-4 portrait:flex-col portrait:items-start portrait:gap-3 portrait:px-4">
        <div className="text-[0.78rem] font-benderBold tracking-[0.3em] text-white/40">MOVE POINTER TO TILT THE TABLE</div>
        <div className="flex flex-wrap gap-2">
          {camps.map((camp) => (
            <button
              key={camp.id}
              type="button"
              onMouseEnter={() => onActivate(camp.id)}
              onFocus={() => onActivate(camp.id)}
              onClick={() => (window.location.href = camp.href)}
              className={`rounded-full border px-3 py-1.5 text-[0.68rem] font-benderBold tracking-[0.28em] transition-colors duration-300 ${
                activeCamp.id === camp.id
                  ? "border-white/15 bg-white/10 text-white"
                  : "border-white/10 bg-black/35 text-white/55 hover:text-white"
              }`}
            >
              {camp.id}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
