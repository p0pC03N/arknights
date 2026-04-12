import { useMemo, useState } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";

export type SandtableCamp = {
  id: "blog" | "docs" | "secret";
  title: string;
  hint: string;
  href: string;
  accent: string;
  textClass: string;
  glowClass: string;
  position: { x: number; y: number };
};

type Point3 = { x: number; y: number; z: number };
type Point2 = { x: number; y: number; depth: number };

const VIEWBOX_WIDTH = 1400;
const VIEWBOX_HEIGHT = 940;
const TERRAIN_WIDTH = 1040;
const TERRAIN_DEPTH = 720;
const TERRAIN_HEIGHT = 240;

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function ridge(
  x: number,
  z: number,
  centerX: number,
  centerZ: number,
  angle: number,
  longAxis: number,
  shortAxis: number,
  intensity: number,
) {
  const dx = x - centerX;
  const dz = z - centerZ;
  const cos = Math.cos(angle);
  const sin = Math.sin(angle);
  const rx = dx * cos + dz * sin;
  const rz = -dx * sin + dz * cos;

  return intensity * Math.exp(-((rx * rx) / (longAxis * longAxis) + (rz * rz) / (shortAxis * shortAxis)));
}

function riverLineForX(x: number) {
  return 0.24 * Math.sin((x + 0.18) * 2.55) - 0.14;
}

function terrainHeight(u: number, v: number) {
  const x = u * 2 - 1;
  const z = v * 2 - 1;
  const riverLine = riverLineForX(x);
  const riverCut = Math.exp(-Math.pow(z - riverLine, 2) / 0.028);

  let value = 0.12;
  value += ridge(x, z, -0.56, -0.02, -0.76, 0.52, 0.11, 0.9);
  value += ridge(x, z, -0.14, 0.1, -0.72, 0.56, 0.12, 0.78);
  value += ridge(x, z, 0.36, -0.18, -0.42, 0.52, 0.15, 0.86);
  value += ridge(x, z, 0.62, 0.26, 0.28, 0.34, 0.18, 0.44);
  value += 0.18 * Math.exp(-(((x + 0.72) * (x + 0.72)) + ((z - 0.55) * (z - 0.55))) / 0.12);
  value += 0.08 * Math.cos((x - 0.2) * 4.1) * Math.sin((z + 0.12) * 3.6);
  value -= riverCut * 0.42;
  value -= 0.12 * Math.exp(-(((x - 0.46) * (x - 0.46)) + ((z + 0.52) * (z + 0.52))) / 0.09);

  return clamp(value, 0.02, 1.08);
}

function createWorldPoint(u: number, v: number) {
  return {
    x: (u - 0.5) * TERRAIN_WIDTH,
    y: terrainHeight(u, v) * TERRAIN_HEIGHT,
    z: (v - 0.5) * TERRAIN_DEPTH,
  };
}

function rotatePoint(point: Point3, yaw: number, pitch: number): Point3 {
  const x1 = point.x * Math.cos(yaw) + point.z * Math.sin(yaw);
  const z1 = -point.x * Math.sin(yaw) + point.z * Math.cos(yaw);
  const y2 = point.y * Math.cos(pitch) - z1 * Math.sin(pitch);
  const z2 = point.y * Math.sin(pitch) + z1 * Math.cos(pitch);

  return { x: x1, y: y2, z: z2 };
}

function projectPoint(point: Point3, yaw: number, pitch: number): Point2 {
  const rotated = rotatePoint(point, yaw, pitch);
  const perspective = 1 + rotated.z / 2600;

  return {
    x: VIEWBOX_WIDTH / 2 + rotated.x * perspective,
    y: VIEWBOX_HEIGHT * 0.56 - rotated.y * 1.04 + rotated.z * 0.28,
    depth: rotated.z,
  };
}

function buildPath(points: Point2[]) {
  return points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(" ") + " Z";
}

function buildLine(points: Point2[]) {
  return points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(" ");
}

function cellFill(avgHeight: number, slope: number, light: number) {
  const hue = Math.round(194 - avgHeight * 18 + slope * 4);
  const saturation = Math.round(18 + avgHeight * 20);
  const luminance = clamp(10 + avgHeight * 24 + light * 14 - slope * 8, 8, 44);
  return `hsl(${hue} ${saturation}% ${luminance}%)`;
}

function buildTerrain(camps: SandtableCamp[], tiltX: number, tiltY: number) {
  const cols = 24;
  const rows = 18;
  const yaw = -0.86 + tiltX * 0.014;
  const pitch = 1.02 + tiltY * 0.011;
  const baseY = -44;
  const grid: Point2[][] = [];
  const heights: number[][] = [];
  const cells: { d: string; fill: string; stroke: string; depth: number }[] = [];
  const rowLines: string[] = [];
  const colLines: string[] = [];

  for (let row = 0; row <= rows; row += 1) {
    const rowPoints: Point2[] = [];
    const rowHeights: number[] = [];

    for (let col = 0; col <= cols; col += 1) {
      const u = col / cols;
      const v = row / rows;
      rowHeights.push(terrainHeight(u, v));
      rowPoints.push(projectPoint(createWorldPoint(u, v), yaw, pitch));
    }

    grid.push(rowPoints);
    heights.push(rowHeights);
  }

  for (let row = 0; row < rows; row += 1) {
    for (let col = 0; col < cols; col += 1) {
      const a = grid[row][col];
      const b = grid[row][col + 1];
      const c = grid[row + 1][col + 1];
      const d = grid[row + 1][col];
      const avgHeight = (heights[row][col] + heights[row][col + 1] + heights[row + 1][col + 1] + heights[row + 1][col]) / 4;
      const slope =
        Math.abs(heights[row][col] - heights[row][col + 1]) +
        Math.abs(heights[row][col] - heights[row + 1][col]) +
        Math.abs(heights[row + 1][col + 1] - heights[row][col + 1]);
      const light =
        (heights[row + 1][col] - heights[row][col]) * 0.42 -
        (heights[row][col + 1] - heights[row][col]) * 0.28 +
        avgHeight * 0.3;

      cells.push({
        d: buildPath([a, b, c, d]),
        fill: cellFill(avgHeight, slope, light),
        stroke: `rgba(255,255,255,${clamp(0.03 + avgHeight * 0.05 + slope * 0.02, 0.03, 0.16)})`,
        depth: (a.depth + b.depth + c.depth + d.depth) / 4,
      });
    }
  }

  for (let row = 0; row <= rows; row += 2) {
    rowLines.push(buildLine(grid[row]));
  }

  for (let col = 0; col <= cols; col += 3) {
    const points: Point2[] = [];
    for (let row = 0; row <= rows; row += 1) {
      points.push(grid[row][col]);
    }
    colLines.push(buildLine(points));
  }

  const frontTop = grid[rows];
  const frontBottom = frontTop.map((_, index) =>
    projectPoint(
      {
        x: (index / cols - 0.5) * TERRAIN_WIDTH,
        y: baseY,
        z: TERRAIN_DEPTH / 2,
      },
      yaw,
      pitch,
    ),
  );
  const rightTop = grid.map((row) => row[cols]);
  const rightBottom = rightTop.map((_, index) =>
    projectPoint(
      {
        x: TERRAIN_WIDTH / 2,
        y: baseY,
        z: (index / rows - 0.5) * TERRAIN_DEPTH,
      },
      yaw,
      pitch,
    ),
  );

  const riverPoints: Point2[] = [];
  for (let step = 0; step <= 36; step += 1) {
    const u = step / 36;
    const x = u * 2 - 1;
    const v = clamp((riverLineForX(x) + 1) / 2, 0.04, 0.96);
    const base = createWorldPoint(u, v);
    riverPoints.push(projectPoint({ ...base, y: base.y - 6 }, yaw, pitch));
  }

  const campPoints = camps.map((camp) => {
    const u = clamp(camp.position.x / 100, 0.04, 0.96);
    const v = clamp(camp.position.y / 100, 0.04, 0.96);
    const point = projectPoint(createWorldPoint(u, v), yaw, pitch);
    return {
      camp,
      point,
      left: (point.x / VIEWBOX_WIDTH) * 100,
      top: (point.y / VIEWBOX_HEIGHT) * 100,
    };
  });

  return {
    cells: cells.sort((left, right) => left.depth - right.depth),
    rowLines,
    colLines,
    river: buildLine(riverPoints),
    frontFace: buildPath([...frontTop, ...frontBottom.reverse()]),
    rightFace: buildPath([...rightTop, ...rightBottom.reverse()]),
    rim: buildPath([grid[0][0], grid[0][cols], grid[rows][cols], grid[rows][0]]),
    campPoints,
  };
}

export default function SandtableMap({
  camps,
  activeId,
  onActivate,
}: {
  camps: SandtableCamp[];
  activeId: SandtableCamp["id"];
  onActivate: (id: SandtableCamp["id"]) => void;
}) {
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const terrain = useMemo(() => buildTerrain(camps, tilt.x, tilt.y), [camps, tilt.x, tilt.y]);

  function handlePointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    const rect = event.currentTarget.getBoundingClientRect();
    const pointerX = (event.clientX - rect.left) / rect.width - 0.5;
    const pointerY = (event.clientY - rect.top) / rect.height - 0.5;
    setTilt({ x: pointerX * 10, y: pointerY * 9 });
  }

  function handlePointerLeave() {
    setTilt({ x: 0, y: 0 });
  }

  return (
    <div
      className="relative aspect-[16/10] w-full overflow-hidden rounded-[2.6rem] border border-white/10 bg-[#02060a]/78 glow-frame"
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_16%,rgba(250,204,21,.08),transparent_18%),radial-gradient(circle_at_78%_20%,rgba(56,189,248,.08),transparent_20%),radial-gradient(circle_at_58%_58%,rgba(255,255,255,.05),transparent_26%),linear-gradient(180deg,rgba(255,255,255,.02),rgba(2,6,23,.22)_28%,rgba(2,6,23,.78))]" />
      <div className="absolute inset-0 panel-grid opacity-[0.08]" />
      <div className="absolute inset-x-[2.5rem] top-[1.8rem] h-[5rem] border-x border-t border-white/8 portrait:inset-x-[1rem]" />
      <div className="absolute inset-x-[2.5rem] bottom-[1.8rem] h-[5rem] border-x border-b border-white/8 portrait:inset-x-[1rem]" />

      <svg
        className="absolute inset-0 h-full w-full"
        viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`}
        fill="none"
        preserveAspectRatio="xMidYMid meet"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="terrain-front" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(33, 45, 56, 0.82)" />
            <stop offset="100%" stopColor="rgba(4, 7, 12, 0.95)" />
          </linearGradient>
          <linearGradient id="terrain-side" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="rgba(28, 40, 52, 0.8)" />
            <stop offset="100%" stopColor="rgba(3, 6, 10, 0.98)" />
          </linearGradient>
          <radialGradient id="terrain-shadow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(0, 0, 0, 0.55)" />
            <stop offset="100%" stopColor="rgba(0, 0, 0, 0)" />
          </radialGradient>
        </defs>

        <ellipse cx="704" cy="690" rx="420" ry="120" fill="url(#terrain-shadow)" opacity="0.78" />
        <path d={terrain.frontFace} fill="url(#terrain-front)" stroke="rgba(255,255,255,0.08)" strokeWidth="1.2" />
        <path d={terrain.rightFace} fill="url(#terrain-side)" stroke="rgba(255,255,255,0.08)" strokeWidth="1.2" />

        {terrain.cells.map((cell) => (
          <path key={`${cell.depth}-${cell.d.slice(0, 24)}`} d={cell.d} fill={cell.fill} stroke={cell.stroke} strokeWidth="0.7" />
        ))}

        {terrain.rowLines.map((line, index) => (
          <path key={`row-${index}`} d={line} stroke="rgba(255,255,255,0.08)" strokeWidth="1" />
        ))}

        {terrain.colLines.map((line, index) => (
          <path key={`col-${index}`} d={line} stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
        ))}

        <path d={terrain.river} stroke="rgba(255,255,255,0.12)" strokeWidth="16" strokeLinecap="round" opacity="0.35" />
        <path d={terrain.river} stroke="rgba(96,165,250,0.95)" strokeWidth="5.8" strokeLinecap="round" />
        <path d={terrain.river} stroke="rgba(186,230,253,0.8)" strokeWidth="1.6" strokeLinecap="round" />
        <path d={terrain.rim} stroke="rgba(255,255,255,0.12)" strokeWidth="1.6" />

        {terrain.campPoints.map(({ camp, point }) => (
          <g key={`glow-${camp.id}`} opacity={activeId === camp.id ? 1 : 0.58}>
            <circle cx={point.x} cy={point.y} r="34" fill={camp.accent} opacity="0.08" />
            <circle cx={point.x} cy={point.y} r="13" fill={camp.accent} opacity="0.18" />
          </g>
        ))}
      </svg>

      <div className="absolute inset-0 z-[3]">
        {terrain.campPoints.map(({ camp, left, top }, index) => {
          const selected = activeId === camp.id;
          return (
            <a
              key={camp.id}
              href={camp.href}
              target="_self"
              onMouseEnter={() => onActivate(camp.id)}
              onFocus={() => onActivate(camp.id)}
              className="group absolute -translate-x-1/2 -translate-y-1/2 text-inherit no-underline"
              style={{ left: `${left}%`, top: `${top}%` }}
            >
              <span
                className="pointer-events-none absolute left-1/2 top-[1.1rem] h-[3.7rem] w-px -translate-x-1/2 bg-white/35"
                style={{ boxShadow: `0 0 16px ${camp.accent}` }}
              />
              <span className="pointer-events-none absolute left-1/2 top-1/2 h-4 w-4 -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/25 bg-black/40" />
              <span
                className="pointer-events-none absolute left-1/2 top-1/2 h-9 w-9 -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/12"
                style={{
                  animation: `terrain-beacon ${3.6 + index * 0.4}s ease-out infinite`,
                  boxShadow: `0 0 20px ${camp.accent}`,
                }}
              />

              <span
                className={`relative z-[2] flex items-center gap-2 rounded-full border border-white/12 bg-black/58 px-3 py-1.5 text-[0.72rem] font-benderBold tracking-[0.28em] backdrop-blur-md transition-all duration-300 ${camp.glowClass} ${selected ? "scale-100" : "scale-[.96] opacity-90"}`}
              >
                <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: camp.accent, boxShadow: `0 0 14px ${camp.accent}` }} />
                <span className={camp.textClass}>{camp.id}</span>
              </span>

              <span
                className={`absolute left-1/2 top-[-2.9rem] min-w-[6.4rem] -translate-x-1/2 rounded-full border border-white/12 bg-black/78 px-3 py-1.5 text-center text-[0.82rem] text-white/88 opacity-0 transition-all duration-300 group-hover:top-[-3.2rem] group-hover:opacity-100 ${
                  selected ? "top-[-3.2rem] opacity-100" : ""
                }`}
              >
                {camp.hint}
              </span>
            </a>
          );
        })}
      </div>
    </div>
  );
}
