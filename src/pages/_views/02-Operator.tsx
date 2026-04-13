import type { CSSProperties } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";
import type { FriendLink } from "../../_types/ArknightsConfig";
import "../../_styles/friend-links-rift.css";

import arknightsConfig from "../../../arknights.config";
import FriendLinksRift from "../../components/FriendLinksRift";

type Stage = "idle" | "omen" | "crack" | "tear" | "depth" | "panels" | "steady";

const stageRanks: Record<Stage, number> = {
  idle: 0,
  omen: 1,
  crack: 2,
  tear: 3,
  depth: 4,
  panels: 5,
  steady: 6,
};

const depthParticleCount = 12;
const debrisCount = 10;
const mainCrackPath =
  "M160 28 C182 86 126 140 168 204 C204 256 136 324 180 398 C212 454 150 528 194 602 C220 654 164 730 206 806 C232 858 190 918 214 962";
const branchCrackPaths = [
  "M170 204 C138 226 126 252 134 286",
  "M180 398 C210 426 220 456 216 488",
  "M194 602 C164 620 150 652 156 684",
];
const surfaceLeftNotes = [
  "relay archive / public coordinates",
  "surface lattice / integrity nominal",
  "sealed layer / external nodes below",
];
const surfaceRightStats = [
  { label: "shell", value: "01" },
  { label: "stress", value: "latent" },
  { label: "relay", value: "locked" },
];
const depthMarkers = [
  { label: "A1", left: "22%", top: "28%" },
  { label: "C4", left: "73%", top: "24%" },
  { label: "D7", left: "66%", top: "69%" },
  { label: "H3", left: "31%", top: "66%" },
];
const leftStressTraces = [
  { top: "16%", width: "38%", right: "8%" },
  { top: "29%", width: "51%", right: "12%" },
  { top: "64%", width: "44%", right: "6%" },
  { top: "78%", width: "30%", right: "16%" },
];
const rightStressTraces = [
  { top: "14%", width: "33%", left: "10%" },
  { top: "34%", width: "45%", left: "8%" },
  { top: "58%", width: "40%", left: "14%" },
  { top: "76%", width: "28%", left: "20%" },
];

export default function Operator() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [stage, setStage] = useState<Stage>("idle");
  const [hasEntered, setHasEntered] = useState(false);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  const sectionRef = useRef<HTMLDivElement | null>(null);
  const hasPlayedRef = useRef(false);

  const isActive = $viewIndex === 2 && $readyToTouch;

  const links = useMemo<FriendLink[]>(() => {
    return arknightsConfig.rootPage.OPERATOR?.friendLinks ?? [];
  }, []);

  const depthParticles = useMemo(
    () =>
      Array.from({ length: depthParticleCount }, (_, index) => ({
        id: index,
        left: `${10 + ((index * 19) % 78)}%`,
        top: `${12 + ((index * 17) % 68)}%`,
        size: `${2 + (index % 3)}px`,
        duration: `${10 + (index % 4) * 1.4}s`,
        delay: `${-(index % 5) * 0.55}s`,
      })),
    [],
  );

  const debris = useMemo(
    () =>
      Array.from({ length: debrisCount }, (_, index) => ({
        id: index,
        left: `${45 + ((index * 7) % 20)}%`,
        top: `${12 + ((index * 11) % 72)}%`,
        width: `${4 + (index % 4) * 2}px`,
        height: `${2 + (index % 2)}px`,
        rotate: `${-24 + (index % 7) * 8}deg`,
        driftX: `${index % 2 === 0 ? -12 - index : 14 + index}px`,
        driftY: `${-8 - (index % 4) * 4}px`,
        delay: `${index * 42}ms`,
      })),
    [],
  );

  useEffect(() => {
    if (isActive) {
      directions.set({ top: true, right: true, bottom: true, left: false });
    }
  }, [isActive]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    const updateMotionPreference = () => setPrefersReducedMotion(mediaQuery.matches);

    updateMotionPreference();
    mediaQuery.addEventListener?.("change", updateMotionPreference);

    return () => {
      mediaQuery.removeEventListener?.("change", updateMotionPreference);
    };
  }, []);

  useEffect(() => {
    if (!isActive || hasPlayedRef.current) {
      return;
    }

    const target = sectionRef.current;
    if (!target) {
      return;
    }

    if (typeof IntersectionObserver === "undefined") {
      hasPlayedRef.current = true;
      setHasEntered(true);
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        if (!entry?.isIntersecting || entry.intersectionRatio < 0.45) {
          return;
        }

        hasPlayedRef.current = true;
        setHasEntered(true);
        observer.disconnect();
      },
      {
        threshold: [0.25, 0.45, 0.65],
      },
    );

    observer.observe(target);

    return () => {
      observer.disconnect();
    };
  }, [isActive]);

  useEffect(() => {
    if (!hasEntered) {
      if (!hasPlayedRef.current) {
        setStage("idle");
      }
      return;
    }

    if (prefersReducedMotion) {
      setStage("steady");
      return;
    }

    setStage("omen");

    const timers: Array<ReturnType<typeof window.setTimeout>> = [
      window.setTimeout(() => setStage("crack"), 190),
      window.setTimeout(() => setStage("tear"), 380),
      window.setTimeout(() => setStage("depth"), 790),
      window.setTimeout(() => setStage("panels"), 1180),
      window.setTimeout(() => setStage("steady"), 1760),
    ];

    return () => {
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [hasEntered, prefersReducedMotion]);

  const stageLevel = stageRanks[stage];
  const isCracked = stageLevel >= stageRanks.crack;
  const isOpening = stageLevel >= stageRanks.tear;
  const isDepthVisible = stageLevel >= stageRanks.depth;
  const isPanelsVisible = stageLevel >= stageRanks.panels || prefersReducedMotion;
  const isSettled = stageLevel >= stageRanks.steady;

  return (
    <div
      ref={sectionRef}
      className={`w-[100vw] max-w-[180rem] h-full absolute top-0 right-0 bottom-0 left-auto transition-all duration-1000 ${
        isActive
          ? "opacity-100 visible pointer-events-auto"
          : "opacity-0 invisible pointer-events-none"
      }`}
    >
      <section
        className="rift-links-shell"
        data-stage={stage}
        data-reduced-motion={prefersReducedMotion ? "true" : "false"}
        aria-labelledby="rift-links-heading"
      >
        <h2 id="rift-links-heading" className="sr-only">
          Friend links revealed behind a ruptured profile surface
        </h2>

        <div className="rift-surface-base" aria-hidden="true">
          <div className={`rift-surface-omen ${stageLevel >= stageRanks.omen ? "is-live" : ""}`} />
          <div className="rift-surface-grid" />

          <div
            className={`rift-surface-split rift-surface-split--left ${
              isCracked ? "is-cracked" : ""
            } ${isOpening ? "is-opening" : ""} ${isSettled ? "is-settled" : ""}`}
          >
            <span className="rift-surface-band rift-surface-band--mid" />
            <span className="rift-surface-band rift-surface-band--near" />

            <div className="rift-surface-copy rift-surface-copy--left">
              <div className="rift-surface-kicker">PROFILE</div>
              <div className="rift-surface-title">External Relay Index</div>
              <div className="rift-surface-copytext">
                Surface layer still reads as a normal page until stress reaches the
                sealed coordinates beneath it.
              </div>
              <div className="rift-surface-note-list">
                {surfaceLeftNotes.map((item) => (
                  <span key={item} className="rift-surface-note">
                    {item}
                  </span>
                ))}
              </div>
            </div>

            <div className="rift-surface-traces">
              {leftStressTraces.map((trace) => (
                <span
                  key={`${trace.top}-${trace.width}`}
                  className="rift-surface-trace"
                  style={
                    {
                      top: trace.top,
                      width: trace.width,
                      right: trace.right,
                    } as CSSProperties
                  }
                />
              ))}
            </div>
          </div>

          <div
            className={`rift-surface-split rift-surface-split--right ${
              isCracked ? "is-cracked" : ""
            } ${isOpening ? "is-opening" : ""} ${isSettled ? "is-settled" : ""}`}
          >
            <span className="rift-surface-band rift-surface-band--mid" />
            <span className="rift-surface-band rift-surface-band--near" />

            <div className="rift-surface-copy rift-surface-copy--right">
              <div className="rift-surface-stat-grid">
                {surfaceRightStats.map((item) => (
                  <div key={item.label} className="rift-surface-stat">
                    <span className="rift-surface-stat-label">{item.label}</span>
                    <span className="rift-surface-stat-value">{item.value}</span>
                  </div>
                ))}
              </div>
              <div className="rift-surface-fineprint">
                Any offset beyond this plane indicates the profile shell has begun to
                fail.
              </div>
            </div>

            <div className="rift-surface-traces">
              {rightStressTraces.map((trace) => (
                <span
                  key={`${trace.top}-${trace.width}`}
                  className="rift-surface-trace"
                  style={
                    {
                      top: trace.top,
                      width: trace.width,
                      left: trace.left,
                    } as CSSProperties
                  }
                />
              ))}
            </div>
          </div>
        </div>

        <div
          className={`rift-depth-chamber ${isOpening ? "is-breached" : ""} ${
            isDepthVisible ? "is-exposed" : ""
          } ${isSettled ? "is-settled" : ""}`}
          aria-hidden="true"
        >
          <div className="rift-depth-wall rift-depth-wall--left" />
          <div className="rift-depth-wall rift-depth-wall--right" />
          <div className="rift-depth-wall rift-depth-wall--far" />
          <div className="rift-depth-grid-overlay" />
          <div className="rift-depth-fog" />
          <div className="rift-depth-scan" />

          <div className="rift-depth-markers">
            {depthMarkers.map((marker) => (
              <span
                key={marker.label}
                className="rift-depth-marker"
                style={
                  {
                    left: marker.left,
                    top: marker.top,
                  } as CSSProperties
                }
              >
                <span className="rift-depth-marker-cross" />
                <span className="rift-depth-marker-label">{marker.label}</span>
              </span>
            ))}
          </div>

          {depthParticles.map((particle) => (
            <span
              key={particle.id}
              className="rift-depth-particle"
              style={
                {
                  left: particle.left,
                  top: particle.top,
                  width: particle.size,
                  height: particle.size,
                  "--particle-duration": particle.duration,
                  "--particle-delay": particle.delay,
                } as CSSProperties
              }
            />
          ))}
        </div>

        <div
          className={`rift-fracture-edge ${isCracked ? "is-visible" : ""} ${
            isSettled ? "is-settled" : ""
          }`}
          aria-hidden="true"
        >
          <span className="rift-fracture-face rift-fracture-face--left" />
          <span className="rift-fracture-face rift-fracture-face--right" />
          <span className="rift-fracture-noise" />
          <span className="rift-fracture-glow" />

          <svg
            className="rift-fracture-seam"
            viewBox="0 0 320 1000"
            preserveAspectRatio="none"
          >
            <path
              className="rift-fracture-seam-path rift-fracture-seam-path--outer"
              d={mainCrackPath}
            />
            <path
              className="rift-fracture-seam-path rift-fracture-seam-path--inner"
              d={mainCrackPath}
            />
            {branchCrackPaths.map((path, index) => (
              <path
                key={path}
                className={`rift-fracture-seam-path rift-fracture-seam-path--branch rift-fracture-seam-path--branch-${index}`}
                d={path}
              />
            ))}
          </svg>
        </div>

        <div
          className={`rift-debris-layer ${isOpening ? "is-active" : ""}`}
          aria-hidden="true"
        >
          {debris.map((item) => (
            <span
              key={item.id}
              className="rift-debris-piece"
              style={
                {
                  left: item.left,
                  top: item.top,
                  width: item.width,
                  height: item.height,
                  "--piece-rotate": item.rotate,
                  "--piece-drift-x": item.driftX,
                  "--piece-drift-y": item.driftY,
                  "--debris-delay": item.delay,
                } as CSSProperties
              }
            />
          ))}
        </div>

        <div className={`rift-relay-panels ${isDepthVisible ? "is-visible" : ""}`}>
          <div className="rift-relay-caption">
            <span className="rift-relay-caption-tag">sealed relays</span>
            <span className="rift-relay-caption-rule" />
            <span className="rift-relay-caption-tag">unseal sequence</span>
          </div>

          <FriendLinksRift
            links={links}
            active={isPanelsVisible}
            reducedMotion={prefersReducedMotion}
          />
        </div>
      </section>
    </div>
  );
}
