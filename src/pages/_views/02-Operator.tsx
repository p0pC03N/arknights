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

const depthParticleCount = 18;
const debrisCount = 12;
const mainCrackPath =
  "M164 24 C182 74 130 122 170 176 C206 225 132 286 182 352 C214 406 150 474 196 538 C228 590 168 666 210 734 C236 792 192 862 220 928";
const branchCrackPaths = [
  "M170 176 C138 204 126 228 134 262",
  "M181 352 C212 376 224 404 218 438",
  "M196 538 C162 560 150 592 156 622",
];
const surfaceLeftNotes = [
  "external relay index",
  "public contact records",
  "verified outbound signals",
];
const surfaceRightStats = [
  { label: "channels", value: "01" },
  { label: "layer", value: "surface" },
  { label: "state", value: "stable" },
];
const depthMarkers = [
  { label: "A1", left: "21%", top: "28%" },
  { label: "C4", left: "74%", top: "26%" },
  { label: "D7", left: "67%", top: "72%" },
  { label: "H3", left: "32%", top: "66%" },
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
        left: `${8 + ((index * 17) % 84)}%`,
        top: `${9 + ((index * 13) % 72)}%`,
        size: `${2 + (index % 4)}px`,
        duration: `${8 + (index % 5) * 1.25}s`,
        delay: `${-(index % 6) * 0.35}s`,
      })),
    [],
  );

  const debris = useMemo(
    () =>
      Array.from({ length: debrisCount }, (_, index) => ({
        id: index,
        left: `${52 + ((index * 7) % 18)}%`,
        top: `${12 + ((index * 9) % 70)}%`,
        width: `${6 + (index % 4) * 3}px`,
        height: `${2 + (index % 3)}px`,
        rotate: `${-32 + (index % 8) * 10}deg`,
        delay: `${index * 40}ms`,
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

    // Trigger the breach only once after the PROFILE section is truly visible.
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

    // Stage timing is intentionally serialized so the section reads like a
    // cinematic reveal instead of multiple effects firing at once.
    setStage("omen");

    const timers: Array<ReturnType<typeof window.setTimeout>> = [
      window.setTimeout(() => setStage("crack"), 180),
      window.setTimeout(() => setStage("tear"), 420),
      window.setTimeout(() => setStage("depth"), 760),
      window.setTimeout(() => setStage("panels"), 1120),
      window.setTimeout(() => setStage("steady"), 1760),
    ];

    return () => {
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [hasEntered, prefersReducedMotion]);

  const stageLevel = stageRanks[stage];

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
          Friend links hidden behind a breached page surface
        </h2>

        <div className="rift-links-surface-layer" aria-hidden="true">
          <div className={`rift-links-omen ${stageLevel >= stageRanks.omen ? "is-live" : ""}`} />
          <div
            className={`rift-links-surface-half rift-links-surface-half--left ${
              stageLevel >= stageRanks.crack ? "is-scored" : ""
            } ${stageLevel >= stageRanks.tear ? "is-open" : ""}`}
          >
            <div className="rift-links-surface-panel rift-links-surface-panel--left">
              <div className="rift-links-surface-kicker">PROFILE</div>
              <div className="rift-links-surface-title">External Contacts</div>
              <div className="rift-links-surface-copy">
                Normal page surface. Verified external contact routes are listed
                here until the structure gives way.
              </div>
              <div className="rift-links-surface-lines">
                {surfaceLeftNotes.map((item) => (
                  <span key={item} className="rift-links-surface-line">
                    {item}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div
            className={`rift-links-surface-half rift-links-surface-half--right ${
              stageLevel >= stageRanks.crack ? "is-scored" : ""
            } ${stageLevel >= stageRanks.tear ? "is-open" : ""}`}
          >
            <div className="rift-links-surface-panel rift-links-surface-panel--right">
              <div className="rift-links-surface-grid">
                {surfaceRightStats.map((item) => (
                  <div key={item.label} className="rift-links-surface-stat">
                    <span className="rift-links-surface-stat-label">{item.label}</span>
                    <span className="rift-links-surface-stat-value">{item.value}</span>
                  </div>
                ))}
              </div>
              <div className="rift-links-surface-fineprint">
                Any anomaly below this plane indicates a sealed depth chamber.
              </div>
            </div>
          </div>
        </div>

        <div
          className={`rift-links-depth-layer ${
            stageLevel >= stageRanks.depth ? "is-exposed" : ""
          }`}
          aria-hidden="true"
        >
          <div className="rift-links-depth-grid" />
          <div className="rift-links-depth-fog" />
          <div className="rift-links-depth-halo" />
          <div className="rift-links-depth-scan" />
          <div className="rift-links-depth-markers">
            {depthMarkers.map((marker) => (
              <span
                key={marker.label}
                className="rift-links-depth-marker"
                style={
                  {
                    left: marker.left,
                    top: marker.top,
                  } as CSSProperties
                }
              >
                <span className="rift-links-depth-marker-cross" />
                <span className="rift-links-depth-marker-label">{marker.label}</span>
              </span>
            ))}
          </div>

          {depthParticles.map((particle) => (
            <span
              key={particle.id}
              className="rift-links-depth-particle"
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
          className={`rift-links-tear-layer ${
            stageLevel >= stageRanks.crack ? "is-visible" : ""
          } ${stageLevel >= stageRanks.steady ? "is-settled" : ""}`}
          aria-hidden="true"
        >
          <span className="rift-links-tear-shadow" />
          <span className="rift-links-tear-rim rift-links-tear-rim--outer" />
          <span className="rift-links-tear-rim rift-links-tear-rim--inner" />
          <span className="rift-links-tear-core" />
          <svg
            className="rift-links-seam-svg"
            viewBox="0 0 320 960"
            preserveAspectRatio="none"
          >
            <path
              className="rift-links-seam-path rift-links-seam-path--outer"
              d={mainCrackPath}
            />
            <path
              className="rift-links-seam-path rift-links-seam-path--noise"
              d={mainCrackPath}
            />
            <path
              className="rift-links-seam-path rift-links-seam-path--inner"
              d={mainCrackPath}
            />

            {branchCrackPaths.map((path, index) => (
              <path
                key={path}
                className={`rift-links-seam-path rift-links-seam-path--branch rift-links-seam-path--branch-${index}`}
                d={path}
              />
            ))}
          </svg>
        </div>

        <div
          className={`rift-links-debris-layer ${
            stageLevel >= stageRanks.tear ? "is-active" : ""
          }`}
          aria-hidden="true"
        >
          {debris.map((item) => (
            <span
              key={item.id}
              className="rift-links-debris-piece"
              style={
                {
                  left: item.left,
                  top: item.top,
                  width: item.width,
                  height: item.height,
                  transform: `rotate(${item.rotate})`,
                  "--piece-rotate": item.rotate,
                  "--debris-delay": item.delay,
                } as CSSProperties
              }
            />
          ))}
        </div>

        <div
          className={`rift-links-panels-layer ${
            stageLevel >= stageRanks.depth ? "is-visible" : ""
          }`}
        >
          <div className="rift-links-depth-caption">
            <span className="rift-links-depth-caption-tag">subspace archive</span>
            <span className="rift-links-depth-caption-rule" />
            <span className="rift-links-depth-caption-tag">external relays</span>
          </div>

          <div className="rift-links-depth-axes" aria-hidden="true">
            <span className="rift-links-depth-axis rift-links-depth-axis--top">
              breach aperture / sealed layer below
            </span>
            <span className="rift-links-depth-axis rift-links-depth-axis--bottom">
              relay nodes unlocking in sequence
            </span>
          </div>

          <FriendLinksRift
            links={links}
            active={stageLevel >= stageRanks.panels || prefersReducedMotion}
            reducedMotion={prefersReducedMotion}
          />
        </div>
      </section>
    </div>
  );
}
