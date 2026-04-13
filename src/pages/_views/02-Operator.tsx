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
        <div className="rift-links-surface-layer" aria-hidden="true">
          <div className={`rift-links-omen ${stageLevel >= stageRanks.omen ? "is-live" : ""}`} />
          <div
            className={`rift-links-surface-half rift-links-surface-half--left ${
              stageLevel >= stageRanks.crack ? "is-scored" : ""
            } ${stageLevel >= stageRanks.tear ? "is-open" : ""}`}
          />
          <div
            className={`rift-links-surface-half rift-links-surface-half--right ${
              stageLevel >= stageRanks.crack ? "is-scored" : ""
            } ${stageLevel >= stageRanks.tear ? "is-open" : ""}`}
          />
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
          <div className="rift-links-heading">
            <div>
              <p className="rift-links-heading-kicker">PROFILE</p>
              <h2 id="rift-links-heading" className="rift-links-heading-title">
                External Relays
              </h2>
            </div>
            <p className="rift-links-heading-meta">Surface breach / hidden channels</p>
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
