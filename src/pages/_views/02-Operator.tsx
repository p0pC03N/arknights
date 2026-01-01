import React, { useEffect, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";

import arknightsConfig from "../../../arknights.config";
import FriendLinks from "../../components/FriendLinks";

export default function Operator() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);

  useEffect(() => {
    const isActive = $viewIndex === 2 && $readyToTouch;
    if (isActive) {
      directions.set({ top: true, right: true, bottom: true, left: false });
    }
    setActive(isActive);
  }, [$viewIndex, $readyToTouch]);

  return (
    <div
      className={`w-[100vw] max-w-[180rem] h-full absolute top-0 right-0 bottom-0 left-auto transition-all duration-1000 ${
        active ? "opacity-100 visible" : "opacity-0 invisible"
      }`}
    >
      <div className="w-full h-full relative" style={{ backgroundColor: "darkgrey" }}>
        <h1 className="text-6xl absolute top-10 left-10">OPERATOR</h1>

        {/* ✅ 友链区域：固定在底部 */}
        <div className="absolute left-0 right-0 bottom-0 bg-black/60 backdrop-blur-md">
          <FriendLinks links={arknightsConfig.rootPage?.OPERATOR?.friendLinks ?? []} />
        </div>
      </div>
    </div>
  );
}
