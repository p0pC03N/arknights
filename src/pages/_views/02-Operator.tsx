import type { CSSProperties } from "react";
import { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";

import arknightsConfig from "../../../arknights.config";
import FriendLinks from "../../components/FriendLinks";

type Stage = "idle" | "glitch" | "crack" | "open" | "cards" | "stable";

const stageRanks: Record<Stage, number> = {
  idle: 0,
  glitch: 1,
  crack: 2,
  open: 3,
  cards: 4,
  stable: 5,
};

export default function Operator() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [stage, setStage] = useState<Stage>("idle");
  const [sceneToken, setSceneToken] = useState(0);

  const isActive = $viewIndex === 2 && $readyToTouch;

  const links = useMemo(() => {
    const anyConfig = arknightsConfig as Record<string, any>;
    return (
      anyConfig?.rootPage?.OPERATOR?.friendLinks ??
      anyConfig?.operator?.friendLinks ??
      []
    );
  }, []);

  const particles = useMemo(
    () =>
      Array.from({ length: 18 }, (_, index) => ({
        id: index,
        left: `${8 + ((index * 19) % 82)}%`,
        top: `${10 + ((index * 23) % 68)}%`,
        size: `${2 + (index % 4)}px`,
        duration: `${7 + (index % 5) * 1.35}s`,
        delay: `${-(index % 6) * 0.45}s`,
      })),
    [],
  );

  useEffect(() => {
    if (isActive) {
      directions.set({ top: true, right: true, bottom: true, left: false });
    }
  }, [isActive]);

  useEffect(() => {
    if (!isActive) {
      setStage("idle");
      return;
    }

    setSceneToken((current) => current + 1);
    setStage("glitch");

    const timers: Array<ReturnType<typeof window.setTimeout>> = [
      window.setTimeout(() => setStage("crack"), 180),
      window.setTimeout(() => setStage("open"), 380),
      window.setTimeout(() => setStage("cards"), 560),
      window.setTimeout(() => setStage("stable"), 1500),
    ];

    return () => {
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [isActive]);

  const stageLevel = stageRanks[stage];

  return (
    <div
      className={`w-[100vw] max-w-[180rem] h-full absolute top-0 right-0 bottom-0 left-auto transition-all duration-1000 ${
        isActive
          ? "opacity-100 visible pointer-events-auto"
          : "opacity-0 invisible pointer-events-none"
      }`}
    >
      <div
        className="operator-rift-shell"
        data-stage={stage}
        data-open={stageLevel >= stageRanks.open ? "true" : "false"}
      >
        <div className={`operator-rift-signal ${stage !== "idle" ? "is-live" : ""}`} />

        <div className={`operator-rift-chamber ${stageLevel >= stageRanks.open ? "is-open" : ""}`}>
          <div className="operator-rift-chamber-grid" />
          <div className="operator-rift-chamber-fog" />
          <div className="operator-rift-chamber-glow" />

          {particles.map((particle) => (
            <span
              key={particle.id}
              className="operator-rift-particle"
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
          className={`operator-rift-surface operator-rift-surface-left ${
            stageLevel >= stageRanks.crack ? "is-torn" : ""
          } ${stageLevel >= stageRanks.open ? "is-open" : ""}`}
        />
        <div
          className={`operator-rift-surface operator-rift-surface-right ${
            stageLevel >= stageRanks.crack ? "is-torn" : ""
          } ${stageLevel >= stageRanks.open ? "is-open" : ""}`}
        />

        <div
          className={`operator-rift-crack ${
            stageLevel >= stageRanks.crack ? "is-cracked" : ""
          } ${stageLevel >= stageRanks.stable ? "is-stable" : ""}`}
        >
          <span className="operator-rift-crack-core" />
          <span className="operator-rift-crack-shards" />
        </div>

        <div className={`operator-rift-content ${stageLevel >= stageRanks.open ? "is-visible" : ""}`}>
          <div className="operator-rift-frame">
            <div className="operator-rift-frame-header">
              <div>
                <div className="operator-rift-kicker">PROFILE</div>
                <div className="operator-rift-title">Friend Links</div>
              </div>
              <div className="operator-rift-tags">
                <span className="operator-rift-tag">SIGNAL BREACH</span>
                <span className="operator-rift-tag">UNSEALED CHANNELS</span>
              </div>
            </div>

            <FriendLinks
              key={sceneToken}
              links={links}
              active={stageLevel >= stageRanks.cards}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
