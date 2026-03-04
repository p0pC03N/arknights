import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { IconDblArrow } from "../components/SvgIcons";
import { useStore } from "@nanostores/react";
import { isInitialized, readyToTouch } from "../components/store/rootLayoutStore";

type PixelType = "empty" | "husk" | "kernel" | "stem";

const CORN_PATTERN = [
    "......HH......",
    ".....HKKH.....",
    "....HKKKKH....",
    "...HKKKKKKH...",
    "..HKKKKKKKKH..",
    "..HKKKKKKKKH..",
    "..HKKKKKKKKH..",
    "..HKKKKKKKKH..",
    "..HKKKKKKKKH..",
    "...HKKKKKKH...",
    "....HKKKKH....",
    ".....HKKH.....",
    ".....HSSH.....",
    "....HH..HH....",
];

function PixelCorn({ progress }: { progress: number }) {
    const cellSize = "clamp(10px, 1.2vw, 18px)";

    const kernelPositions = useMemo(() => {
        const result: { row: number; col: number }[] = [];
        for (let row = CORN_PATTERN.length - 1; row >= 0; row--) {
            for (let col = 0; col < CORN_PATTERN[row].length; col++) {
                if (CORN_PATTERN[row][col] === "K") {
                    result.push({ row, col });
                }
            }
        }
        return result;
    }, []);

    const filledKernelCount = Math.floor((progress / 100) * kernelPositions.length);
    const filledMap = useMemo(() => {
        const map = new Set<string>();
        kernelPositions.slice(0, filledKernelCount).forEach(({ row, col }) => {
            map.add(`${row}-${col}`);
        });
        return map;
    }, [kernelPositions, filledKernelCount]);

    const getPixelStyle = (type: PixelType, filled = false): React.CSSProperties => {
        if (type === "empty") {
            return {
                width: cellSize,
                height: cellSize,
                backgroundColor: "transparent",
            };
        }

        if (type === "husk") {
            return {
                width: cellSize,
                height: cellSize,
                backgroundColor: "#4f8f3d",
                boxShadow: "inset 0 0 0 1px rgba(18,32,14,.28)",
            };
        }

        if (type === "stem") {
            return {
                width: cellSize,
                height: cellSize,
                backgroundColor: "#8f6e39",
                boxShadow: "inset 0 0 0 1px rgba(45,32,14,.24)",
            };
        }

        return {
            width: cellSize,
            height: cellSize,
            backgroundColor: filled ? "#ffd84a" : "#5a4c1f",
            boxShadow: filled
                ? "inset 0 0 0 1px rgba(98,72,0,.30), 0 0 8px rgba(255,216,74,.18)"
                : "inset 0 0 0 1px rgba(20,14,2,.38)",
            transition: "background-color 180ms ease, box-shadow 180ms ease, transform 180ms ease",
            transform: filled ? "translateY(-1px)" : "none",
        };
    };

    return (
        <div className="relative flex flex-col items-center select-none">
            <div
                className="grid gap-[2px] p-[10px] bg-[#1f1f1f] border border-[#5a5a5a]"
                style={{ gridTemplateColumns: `repeat(${CORN_PATTERN[0].length}, ${cellSize})` }}
            >
                {CORN_PATTERN.map((row, rowIndex) =>
                    row.split("").map((char, colIndex) => {
                        const key = `${rowIndex}-${colIndex}`;
                        let type: PixelType = "empty";

                        if (char === "H") type = "husk";
                        else if (char === "K") type = "kernel";
                        else if (char === "S") type = "stem";

                        const filled = type === "kernel" && filledMap.has(key);

                        return (
                            <div
                                key={key}
                                style={getPixelStyle(type, filled)}
                                className={filled ? "rounded-[2px]" : ""}
                            />
                        );
                    })
                )}
            </div>

            <div className="mt-[1.1vw] portrait:mt-[3vw] text-[#cfcfcf] text-[0.95vw] portrait:text-[2.4vw] tracking-[0.28em]">
                CORN KERNEL FILL SYSTEM
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
                className={`absolute left-0 right-0 h-[0.05vw] bg-[${frameColor}] transition-all duration-1000 ease-in-out ${
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

                <PixelCorn progress={progress} />

                <div className="mt-[1.6vw] portrait:mt-[4vw] text-[0.9vw] portrait:text-[2.5vw] tracking-[0.28em] text-[#8c8c8c]">
                    {progress < 30 && "正在整理玉米粒仓库..."}
                    {progress >= 30 && progress < 70 && "正在向玉米棒填充像素颗粒..."}
                    {progress >= 70 && progress < 100 && "即将完成收割装填..."}
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
                                    <span>PIXEL KERNEL LOADER</span>
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
