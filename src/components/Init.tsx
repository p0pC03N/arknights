import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { IconDblArrow } from "../components/SvgIcons";
import { useStore } from "@nanostores/react";
import { isInitialized, readyToTouch } from "../components/store/rootLayoutStore";

type CellType = "empty" | "core" | "kernel";

function CornCrossSection({ progress }: { progress: number }) {
    const size = 17;
    const center = Math.floor(size / 2);
    const cellSize = "clamp(10px, 1.15vw, 18px)";

    const cellMap = useMemo(() => {
        const map = new Map<string, { type: CellType; dist: number; angle: number }>();

        for (let row = 0; row < size; row++) {
            for (let col = 0; col < size; col++) {
                const dx = col - center;
                const dy = row - center;
                const dist = Math.sqrt(dx * dx + dy * dy);

                let type: CellType = "empty";

                // 中心玉米棒芯
                if (dist <= 2.35) {
                    type = "core";
                }
                // 周围玉米粒区域
                else if (dist >= 3.4 && dist <= 7.2) {
                    type = "kernel";
                }

                if (type !== "empty") {
                    let angle = Math.atan2(dy, dx);
                    if (angle < 0) angle += Math.PI * 2;

                    map.set(`${row}-${col}`, {
                        type,
                        dist,
                        angle,
                    });
                }
            }
        }

        return map;
    }, [center]);

    const kernels = useMemo(() => {
        return Array.from(cellMap.entries())
            .filter(([, cell]) => cell.type === "kernel")
            .map(([key, cell]) => ({ key, ...cell }))
            .sort((a, b) => {
                // 外圈优先，再顺时针填充
                if (Math.abs(a.dist - b.dist) > 0.2) return b.dist - a.dist;
                return a.angle - b.angle;
            });
    }, [cellMap]);

    const filledKernelCount = Math.floor((progress / 100) * kernels.length);

    const filledMap = useMemo(() => {
        const set = new Set<string>();
        kernels.slice(0, filledKernelCount).forEach((cell) => {
            set.add(cell.key);
        });
        return set;
    }, [kernels, filledKernelCount]);

    const getCellStyle = (
        type: CellType,
        filled: boolean,
        dist: number
    ): React.CSSProperties => {
        if (type === "empty") {
            return {
                width: cellSize,
                height: cellSize,
                backgroundColor: "transparent",
            };
        }

        if (type === "core") {
            return {
                width: cellSize,
                height: cellSize,
                borderRadius: "3px",
                backgroundColor: "#a36f3c",
                boxShadow:
                    "inset 0 0 0 1px rgba(72,42,14,.28), 0 0 6px rgba(120,80,30,.10)",
            };
        }

        const glow = filled ? Math.max(0.12, 0.28 - (dist - 3.4) * 0.02) : 0;

        return {
            width: cellSize,
            height: cellSize,
            borderRadius: "4px",
            backgroundColor: filled ? "#ffd84a" : "#5b4b1d",
            boxShadow: filled
                ? `inset 0 0 0 1px rgba(120,88,0,.24), 0 0 10px rgba(255,216,74,${glow})`
                : "inset 0 0 0 1px rgba(24,16,4,.35)",
            transform: filled ? "scale(1.03)" : "scale(1)",
            transition:
                "background-color 180ms ease, box-shadow 180ms ease, transform 180ms ease",
        };
    };

    return (
        <div className="relative flex flex-col items-center select-none">
            <div
                className="grid gap-[2px] p-[12px] bg-[#1f1f1f] border border-[#5a5a5a] rounded-[8px]"
                style={{ gridTemplateColumns: `repeat(${size}, ${cellSize})` }}
            >
                {Array.from({ length: size * size }).map((_, index) => {
                    const row = Math.floor(index / size);
                    const col = index % size;
                    const key = `${row}-${col}`;
                    const cell = cellMap.get(key);

                    if (!cell) {
                        return (
                            <div
                                key={key}
                                style={getCellStyle("empty", false, 0)}
                            />
                        );
                    }

                    const filled =
                        cell.type === "kernel" && filledMap.has(key);

                    return (
                        <div
                            key={key}
                            style={getCellStyle(cell.type, filled, cell.dist)}
                        />
                    );
                })}
            </div>

            <div className="mt-[1.1vw] portrait:mt-[3vw] text-[#cfcfcf] text-[0.95vw] portrait:text-[2.4vw] tracking-[0.28em]">
                CORN CROSS SECTION FILL SYSTEM
            </div>
        </div>
    );
}

export function Init() {
    const $isInitialized = useStore(isInitialized);
    const [progress, setProgress] = useState(0);
    const [isHidden, setIsHidden] = useState(false);
    const [isFadingOut, setIsFadingOut] = useState(false);
    const [isComplete, setIsComplete] = useState(false);
    const observerRef = useRef<PerformanceObserver | null>(null);
    const [loadedResources, setLoadedResources] = useState<Set<string>>(new Set());
    const [isObserving, setIsObserving] = useState(true);

    const frameColor = "#686767";
    const commonColor = "rgb(164,164,164)";
    const accentColor = "#ffd84a";
    const accentSoft = "#fff0a5";

    const incrementProgress = useCallback(() => {
        setProgress((prev) => Math.min(prev + 0.6, 82));
    }, []);

    const stopObserving = useCallback(() => {
        if (observerRef.current) {
            observerRef.current.disconnect();
            observerRef.current = null;
        }
        setIsObserving(false);
    }, []);

    useEffect(() => {
        if (!isObserving) return;

        const observer = new PerformanceObserver((list) => {
            list.getEntries().forEach((entry) => {
                if (entry.entryType !== "resource") return;

                const resourceName = (entry as PerformanceResourceTiming).name;
                if (loadedResources.has(resourceName)) return;

                setLoadedResources((prev) => {
                    const next = new Set(prev);
                    next.add(resourceName);
                    return next;
                });
                incrementProgress();

                if (resourceName.endsWith("/images/index-bg.jpg")) {
                    isInitialized.set(true);
                    stopObserving();
                }
            });
        });

        observerRef.current = observer;
        observer.observe({ entryTypes: ["resource"] });

        const existingResources = performance.getEntriesByType("resource");
        existingResources.forEach((entry) => {
            if (loadedResources.has(entry.name)) return;

            setLoadedResources((prev) => {
                const next = new Set(prev);
                next.add(entry.name);
                return next;
            });
            incrementProgress();

            if (entry.name.endsWith("/images/index-bg.jpg")) {
                isInitialized.set(true);
                stopObserving();
            }
        });

        return () => {
            observer.disconnect();
        };
    }, [incrementProgress, isObserving, loadedResources, stopObserving]);

    useEffect(() => {
        let interval: number | undefined;

        if ($isInitialized && progress < 100) {
            interval = window.setInterval(() => {
                setProgress((prev) => {
                    const next = prev + 100;
                    if (next >= 100) {
                        window.clearInterval(interval);
                        return 100;
                    }
                    return next;
                });
            }, 50);
        }

        return () => {
            if (interval) window.clearInterval(interval);
        };
    }, [$isInitialized, progress]);

    useEffect(() => {
        if (progress >= 100 && !isComplete) {
            setIsComplete(true);
            setTimeout(() => {
                readyToTouch.set(true);
                setIsFadingOut(true);
                setTimeout(() => {
                    setIsHidden(true);
                }, 800);
            }, 500);
        }
    }, [isComplete, progress]);

    if (isHidden) return null;

    return (
        <div
            className={`fixed inset-0 z-50 flex flex-col items-center justify-center bg-[#272727] font-benderBold transition-opacity duration-1000 ${
                isFadingOut ? "opacity-0" : "opacity-100"
            }`}
        >
            <div
                className={`absolute left-0 right-0 h-[0.05vw] transition-all duration-1000 ease-in-out ${
                    isFadingOut ? "top-[-5vw]" : "top-[5vw]"
                }`}
                style={{ backgroundColor: frameColor }}
            />
            <div
                className={`absolute top-0 bottom-0 w-[0.05vw] transition-all duration-1000 ease-in-out ${
                    isFadingOut ? "right-[-5vw]" : "right-[5vw]"
                }`}
                style={{ backgroundColor: frameColor }}
            />

            <div className="flex h-full w-full flex-col items-center justify-center">
                <div className="flex-grow" />

                <div className="mb-[2.4vw] portrait:mb-[6vw] flex flex-col items-center justify-center">
                    <div className="text-[rgb(196,196,196)] font-oswaldMedium text-[4.6vw] portrait:text-[10.5vw] tracking-[0.22em] leading-none">
                        玉米
                    </div>
                    <div className="mt-[0.8vw] portrait:mt-[2vw] text-[#9e9e9e] text-[0.9vw] portrait:text-[2.5vw] tracking-[0.45em] leading-none">
                        CORN KINGDOM
                    </div>
                </div>

                <CornCrossSection progress={progress} />

                <div className="mt-[1.6vw] portrait:mt-[4vw] text-[0.9vw] portrait:text-[2.5vw] tracking-[0.28em] text-[#8c8c8c]">
                    {progress < 30 && "正在塑造玉米横切面..."}
                    {progress >= 30 && progress < 70 && "外圈玉米粒正在逐步填充..."}
                    {progress >= 70 && progress < 100 && "横切面即将装填完成..."}
                    {progress >= 100 && "装填完成，准备进入玉米王国"}
                </div>

                <div className="flex-grow" />

                <div className="absolute w-full max-w-[90vw] px-[2vw]" style={{ top: "75%" }}>
                    <div className="flex items-start">
                        <div
                            className="mr-[15vw] whitespace-nowrap text-[1.2vw] portrait:fixed portrait:bottom-[1%] portrait:left-[1%] portrait:text-[10px]"
                            style={{ color: commonColor }}
                        >
                            <span>© p0pC03N</span>
                        </div>

                        <div className="flex-grow pl-[5vw] pr-[5.5vw]">
                            <div className="relative flex h-[0.3vw] items-center" style={{ backgroundColor: "transparent" }}>
                                <div className="absolute left-0 h-[0.3vw] w-[0.3vw]" style={{ backgroundColor: commonColor }} />
                                <div className="absolute right-0 h-[0.3vw] w-[0.3vw]" style={{ backgroundColor: commonColor }} />
                                <div className="absolute left-0 right-0 top-[0.1vw] h-[0.1vw]" style={{ backgroundColor: commonColor }} />
                                <div
                                    className="absolute left-0 top-0 h-[0.3vw] transition-all duration-300 ease-linear"
                                    style={{ width: `${progress}%`, backgroundColor: accentColor }}
                                />
                            </div>

                            <div className="mt-[0.8vw] flex items-center justify-between">
                                <div className="flex items-center text-[0.8vw] portrait:text-[2.2vw]" style={{ color: accentSoft }}>
                                    <IconDblArrow className="mr-[0.4vw] h-[0.8vw] w-[0.8vw] portrait:h-[2vw] portrait:w-[2vw]" />
                                    <span>{`HARVESTING CORN - ${Math.round(progress)}%`}</span>
                                </div>

                                <div className="flex items-center text-[0.8vw] portrait:hidden" style={{ color: commonColor }}>
                                    <span>CORN KINGDOM</span>
                                    <span className="mx-[0.8vw]">//</span>
                                    <span>CROSS SECTION LOADER</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="flex-grow" />
            </div>
        </div>
    );
}
