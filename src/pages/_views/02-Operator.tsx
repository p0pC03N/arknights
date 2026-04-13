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

const seamPath =
  "M160 22 C176 90 136 156 170 232 C198 294 144 370 182 446 C208 508 156 590 192 664 C216 726 170 808 202 884 C220 930 192 968 206 992";
const branchPaths = [
  "M170 232 C148 252 140 276 146 306",
  "M182 446 C204 470 212 500 208 528",
];
const seamNoiseCount = 8;
const chamberParticleCount = 6;

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

  const seamNoise = useMemo(
    () =>
      Array.from({ length: seamNoiseCount }, (_, index) => ({
        id: index,
        left: `${47 + ((index * 4) % 14)}%`,
        top: `${11 + ((index * 13) % 74)}%`,
        width: `${2 + (index % 3)}px`,
        height: `${2 + (index % 2)}px`,
        driftX: `${index % 2 === 0 ? -8 - index : 8 + index}px`,
        driftY: `${-4 - (index % 4) * 3}px`,
        delay: `${index * 36}ms`,
      })),
    [],
  );

  const chamberParticles = useMemo(
    () =>
      Array.from({ length: chamberParticleCount }, (_, index) => ({
        id: index,
        left: `${18 + ((index * 15) % 64)}%`,
        top: `${18 + ((index * 19) % 56)}%`,
        size: `${2 + (index % 2)}px`,
        duration: `${9 + index * 1.1}s`,
        delay: `${-(index % 4) * 0.7}s`,
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
      window.setTimeout(() => setStage("crack"), 180),
      window.setTimeout(() => setStage("tear"), 380),
      window.setTimeout(() => setStage("depth"), 760),
      window.setTimeout(() => setStage("panels"), 1120),
      window.setTimeout(() => setStage("steady"), 1660),
    ];

    return () => {
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [hasEntered, prefersReducedMotion]);

  const stageLevel = stageRanks[stage];
  const isCracked = stageLevel >= stageRanks.crack;
  const isOpening = stageLevel >= stageRanks.tear;
  const isDepthVisible = stageLevel >= stageRanks.depth;
  const isNodesVisible = stageLevel >= stageRanks.panels || prefersReducedMotion;
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
          Graybox verification of a page surface tearing open to reveal hidden links
        </h2>

        <div
          className={`rift-depth-chamber ${isOpening ? "is-open" : ""} ${
            isDepthVisible ? "is-exposed" : ""
          } ${isSettled ? "is-settled" : ""}`}
          aria-hidden="true"
        >
          <div className="rift-depth-wall rift-depth-wall--near-left" />
          <div className="rift-depth-wall rift-depth-wall--near-right" />
          <div className="rift-depth-wall rift-depth-wall--mid-left" />
          <div className="rift-depth-wall rift-depth-wall--mid-right" />
          <div className="rift-depth-deep-zone" />
          <div className="rift-depth-grid" />
          <div className="rift-depth-scan" />

          {chamberParticles.map((particle) => (
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

        <div className="rift-surface-stage" aria-hidden="true">
          <div className={`rift-omen-overlay ${stageLevel >= stageRanks.omen ? "is-live" : ""}`} />

          <div
            className={`rift-surface-segment rift-surface-skin rift-surface-skin--left ${
              isOpening ? "is-open" : ""
            }`}
          />
          <div
            className={`rift-surface-segment rift-surface-skin rift-surface-skin--right ${
              isOpening ? "is-open" : ""
            }`}
          />

          <div
            className={`rift-surface-segment rift-surface-flap rift-surface-flap--left ${
              isOpening ? "is-open" : ""
            }`}
          />
          <div
            className={`rift-surface-segment rift-surface-flap rift-surface-flap--right ${
              isOpening ? "is-open" : ""
            }`}
          />

          <div
            className={`rift-fractured-surface-edge rift-fractured-surface-edge--left ${
              isOpening ? "is-open" : ""
            }`}
          />
          <div
            className={`rift-fractured-surface-edge rift-fractured-surface-edge--right ${
              isOpening ? "is-open" : ""
            }`}
          />

          <div
            className={`rift-inner-energy-rim rift-inner-energy-rim--left ${
              isOpening ? "is-open" : ""
            } ${isSettled ? "is-settled" : ""}`}
          />
          <div
            className={`rift-inner-energy-rim rift-inner-energy-rim--right ${
              isOpening ? "is-open" : ""
            } ${isSettled ? "is-settled" : ""}`}
          />

          <div
            className={`rift-seam-line ${isCracked ? "is-visible" : ""} ${
              isSettled ? "is-settled" : ""
            }`}
          >
            <svg viewBox="0 0 320 1000" preserveAspectRatio="none">
              <path className="rift-seam-path rift-seam-path--main" d={seamPath} />
              {branchPaths.map((path) => (
                <path key={path} className="rift-seam-path rift-seam-path--branch" d={path} />
              ))}
            </svg>
          </div>

          <div
            className={`rift-seam-noise ${isOpening ? "is-active" : ""}`}
            aria-hidden="true"
          >
            {seamNoise.map((item) => (
              <span
                key={item.id}
                className="rift-seam-noise-bit"
                style={
                  {
                    left: item.left,
                    top: item.top,
                    width: item.width,
                    height: item.height,
                    "--noise-drift-x": item.driftX,
                    "--noise-drift-y": item.driftY,
                    "--noise-delay": item.delay,
                  } as CSSProperties
                }
              />
            ))}
          </div>
        </div>

        <FriendLinksRift
          links={links}
          active={isNodesVisible}
          reducedMotion={prefersReducedMotion}
        />
      </section>
    </div>
  );
}
