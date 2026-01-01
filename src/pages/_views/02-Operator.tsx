import React, { useEffect, useMemo, useState } from "react";
import { useStore } from "@nanostores/react";
import { viewIndex, readyToTouch } from "../../components/store/rootLayoutStore";
import { directions } from "../../components/store/lineDecoratorStore";

import arknightsConfig from "../../../arknights.config";
import FriendLinks from "../../components/FriendLinks";

export default function Operator() {
  const $viewIndex = useStore(viewIndex);
  const $readyToTouch = useStore(readyToTouch);
  const [active, setActive] = useState(false);

  // ✅ 兼容 GitHub Pages 子路径
  const base = import.meta.env.BASE_URL;

  // ✅ 这里放你的 OPERATOR 页背景图（放到 public/images/operator/bg.jpg）
  const operatorBg = useMemo(() => base + "images/operator/bg.jpg", [base]);

  // ✅ 从 config 里拿友链（建议你把数据放到 arknightsConfig.operator.friendLinks）
  const links = useMemo(() => {
    // 兼容：如果你还没改配置，也给你兜底一下（两种路径都尝试）
    const anyCfg = arknightsConfig as any;
    return (
      anyCfg?.operator?.friendLinks ??
      anyCfg?.rootPage?.OPERATOR?.friendLinks ??
      []
    );
  }, []);

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
      {/* 整页容器 */}
      <div className="w-full h-full relative overflow-hidden">
        {/* ✅ 背景图层（替换掉灰色） */}
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `url(${operatorBg})`,
            backgroundSize: "cover",
            backgroundPosition: "center",
            backgroundRepeat: "no-repeat",
          }}
        />

        {/* ✅ 加一个暗色遮罩，让字更清晰（可删） */}
        <div className="absolute inset-0 bg-black/35" />

        {/* 标题 */}
        <h1 className="text-6xl absolute top-10 left-10 text-white drop-shadow">
          OPERATOR
        </h1>

        {/* ✅ 友链区域：固定在底部 */}
        <div className="absolute left-0 right-0 bottom-0 bg-black/60 backdrop-blur-md">
          <FriendLinks links={links} />
        </div>
      </div>
    </div>
  );
}

