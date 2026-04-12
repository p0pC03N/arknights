import { IconArrow } from "./SvgIcons.tsx";
import { useEffect, useMemo, useState } from "react";

export default function DocsLeftAsideSwitch() {
  const [isOpen, setIsOpen] = useState(false);
  const iconClassName = useMemo(() => (isOpen ? "rotate-180 " : "") + "h-4 inline-block select-none", [isOpen]);

  useEffect(() => {
    const shell = document.getElementById("docs-map-shell");
    if (!shell) return;

    if (isOpen) shell.classList.add("docs-map-expanded");
    else shell.classList.remove("docs-map-expanded");
  }, [isOpen]);

  return (
    <button
      type="button"
      className="absolute bottom-0 left-0 right-0 h-10 border-t border-white/10 bg-[#071019]/96 text-white/70 transition hover:bg-white hover:text-black"
      title={isOpen ? "收起知识地图" : "展开知识地图"}
      aria-label={isOpen ? "收起知识地图" : "展开知识地图"}
      onClick={() => setIsOpen(!isOpen)}
    >
      <div className="flex items-center justify-center gap-2">
        <div className="text-[0.62rem] font-benderBold tracking-[0.28em]">{isOpen ? "HIDE" : "MAP"}</div>
        <IconArrow className={iconClassName} />
      </div>
    </button>
  );
}
