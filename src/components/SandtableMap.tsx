import { useEffect, useRef } from "react";
import * as THREE from "three";

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

type GridPoint = { x: number; z: number };
type RiverData = {
  points: GridPoint[];
  radius: number;
  glowRadius: number;
  particleCount: number;
  coreColor: number;
  glowColor: number;
};
type HeightField = {
  cols: number;
  rows: number;
  heights: number[][];
  rivers: RiverData[];
};

const TERRAIN_WIDTH = 18.5;
const TERRAIN_DEPTH = 12.5;
const TERRAIN_HEIGHT = 5.2;
const HEIGHT_GRID_X = 110;
const HEIGHT_GRID_Z = 78;
const ALTITUDE_COLORS = [0x04111a, 0x072033, 0x0a3250, 0x104569, 0x155781, 0x1c6997, 0x267cad, 0x3c9bc6, 0x72c4ea, 0xbef2ff];
const MARCHING_CASES: Record<number, [number, number][]> = {
  1: [[3, 2]],
  2: [[2, 1]],
  3: [[3, 1]],
  4: [[0, 1]],
  5: [
    [0, 3],
    [2, 1],
  ],
  6: [[0, 2]],
  7: [[0, 3]],
  8: [[0, 3]],
  9: [[0, 2]],
  10: [
    [0, 1],
    [2, 3],
  ],
  11: [[0, 1]],
  12: [[3, 1]],
  13: [[2, 1]],
  14: [[3, 2]],
};

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function lerp(a: number, b: number, t: number) {
  return a + (b - a) * t;
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

function normalizedToWorld(nx: number, nz: number, height: number) {
  return new THREE.Vector3(nx * (TERRAIN_WIDTH / 2), height * TERRAIN_HEIGHT, nz * (TERRAIN_DEPTH / 2));
}

function baseHeight(nx: number, nz: number) {
  let h = 0.06;
  h += ridge(nx, nz, -0.78, 0.22, -0.96, 0.78, 0.12, 1.02);
  h += ridge(nx, nz, -0.34, 0.04, -0.68, 0.66, 0.14, 1.14);
  h += ridge(nx, nz, 0.04, -0.08, -0.48, 0.54, 0.16, 0.98);
  h += ridge(nx, nz, 0.44, -0.16, -0.28, 0.44, 0.18, 0.72);
  h += ridge(nx, nz, 0.74, 0.18, 0.18, 0.32, 0.2, 0.42);
  h += 0.18 * Math.exp(-(((nx + 0.84) * (nx + 0.84)) + ((nz - 0.58) * (nz - 0.58))) / 0.1);
  h += 0.12 * Math.exp(-(((nx - 0.62) * (nx - 0.62)) + ((nz + 0.54) * (nz + 0.54))) / 0.12);
  h += 0.05 * Math.sin((nx + 0.12) * 7.2) * Math.cos((nz - 0.18) * 5.6);
  h -= 0.1 * Math.exp(-(((nx - 0.14) * (nx - 0.14)) + ((nz + 0.48) * (nz + 0.48))) / 0.08);
  return clamp(h, 0.02, 1.18);
}

function sampleHeightField(field: HeightField, gx: number, gz: number) {
  const x = clamp(gx, 0, field.cols);
  const z = clamp(gz, 0, field.rows);
  const x0 = Math.floor(x);
  const z0 = Math.floor(z);
  const x1 = Math.min(field.cols, x0 + 1);
  const z1 = Math.min(field.rows, z0 + 1);
  const tx = x - x0;
  const tz = z - z0;

  const top = lerp(field.heights[z0][x0], field.heights[z0][x1], tx);
  const bottom = lerp(field.heights[z1][x0], field.heights[z1][x1], tx);
  return lerp(top, bottom, tz);
}

function gridToWorld(field: HeightField, point: GridPoint, extraY = 0) {
  const nx = point.x / field.cols * 2 - 1;
  const nz = point.z / field.rows * 2 - 1;
  const height = sampleHeightField(field, point.x, point.z);
  const world = normalizedToWorld(nx, nz, height);
  world.y += extraY;
  return world;
}

function smoothPath(points: GridPoint[], iterations: number) {
  let output = points.slice();

  for (let i = 0; i < iterations; i += 1) {
    output = output.map((point, index) => {
      if (index === 0 || index === output.length - 1) return point;
      const prev = output[index - 1];
      const next = output[index + 1];
      return {
        x: (prev.x + point.x * 2 + next.x) / 4,
        z: (prev.z + point.z * 2 + next.z) / 4,
      };
    });
  }

  return output;
}

function traceRiver(heights: number[][], start: GridPoint, goal: GridPoint, maxSteps: number) {
  const rows = heights.length - 1;
  const cols = heights[0].length - 1;
  const visited = new Set<string>();
  const path: GridPoint[] = [{ ...start }];
  let current = { ...start };

  const directions = [
    { x: 1, z: 0 },
    { x: 1, z: 1 },
    { x: 0, z: 1 },
    { x: -1, z: 1 },
    { x: 1, z: -1 },
    { x: -1, z: 0 },
    { x: 0, z: -1 },
    { x: -1, z: -1 },
  ];

  for (let step = 0; step < maxSteps; step += 1) {
    const distanceToGoal = Math.hypot(goal.x - current.x, goal.z - current.z);
    if (distanceToGoal < 2.4) {
      path.push({ ...goal });
      break;
    }

    visited.add(`${Math.round(current.x)}:${Math.round(current.z)}`);

    const currentHeight = sampleHeightField(
      { cols, rows, heights, rivers: [] },
      current.x,
      current.z,
    );

    let bestCandidate: GridPoint | null = null;
    let bestScore = Number.POSITIVE_INFINITY;

    directions.forEach((direction) => {
      const candidate = { x: current.x + direction.x, z: current.z + direction.z };
      if (candidate.x < 1 || candidate.x > cols - 1 || candidate.z < 1 || candidate.z > rows - 1) return;

      const key = `${Math.round(candidate.x)}:${Math.round(candidate.z)}`;
      const candidateHeight = sampleHeightField({ cols, rows, heights, rivers: [] }, candidate.x, candidate.z);
      const downhillPenalty = Math.max(0, candidateHeight - currentHeight) * 12;
      const revisitPenalty = visited.has(key) ? 4 : 0;
      const goalDistance = Math.hypot(goal.x - candidate.x, goal.z - candidate.z);
      const alignmentPenalty = direction.x < 0 ? 0.9 : 0;
      const score = candidateHeight * 5.2 + goalDistance * 0.05 + downhillPenalty + revisitPenalty + alignmentPenalty;

      if (score < bestScore) {
        bestScore = score;
        bestCandidate = candidate;
      }
    });

    if (!bestCandidate) break;
    current = bestCandidate;
    path.push({ ...current });
  }

  return smoothPath(path, 3);
}

function carveRiver(heights: number[][], path: GridPoint[], depth: number, radius: number) {
  const rows = heights.length - 1;
  const cols = heights[0].length - 1;

  path.forEach((point) => {
    const minX = Math.max(0, Math.floor(point.x - radius * 1.8));
    const maxX = Math.min(cols, Math.ceil(point.x + radius * 1.8));
    const minZ = Math.max(0, Math.floor(point.z - radius * 1.8));
    const maxZ = Math.min(rows, Math.ceil(point.z + radius * 1.8));

    for (let z = minZ; z <= maxZ; z += 1) {
      for (let x = minX; x <= maxX; x += 1) {
        const distance = Math.hypot(x - point.x, z - point.z);
        const influence = Math.exp(-(distance * distance) / (radius * radius));
        heights[z][x] = Math.max(0.015, heights[z][x] - depth * influence);
      }
    }
  });
}

function createHeightField(cols: number, rows: number): HeightField {
  const heights = Array.from({ length: rows + 1 }, (_, row) =>
    Array.from({ length: cols + 1 }, (_, col) => {
      const nx = col / cols * 2 - 1;
      const nz = row / rows * 2 - 1;
      return baseHeight(nx, nz);
    }),
  );

  const mainRiverPath = traceRiver(heights, { x: 12, z: 10 }, { x: cols - 8, z: rows - 10 }, 180);
  const branchGoal = mainRiverPath[Math.floor(mainRiverPath.length * 0.58)] ?? { x: cols * 0.58, z: rows * 0.52 };
  const tributaryPath = traceRiver(heights, { x: 44, z: 12 }, branchGoal, 96);

  carveRiver(heights, mainRiverPath, 0.18, 2.9);
  carveRiver(heights, tributaryPath, 0.12, 2.2);

  return {
    cols,
    rows,
    heights,
    rivers: [
      {
        points: mainRiverPath,
        radius: 0.075,
        glowRadius: 0.22,
        particleCount: 42,
        coreColor: 0x86f6ff,
        glowColor: 0x1fb8ff,
      },
      {
        points: tributaryPath,
        radius: 0.05,
        glowRadius: 0.14,
        particleCount: 24,
        coreColor: 0x66dbff,
        glowColor: 0x1d95ff,
      },
    ],
  };
}

function altitudeColor(height: number) {
  const bandIndex = clamp(Math.floor(height * ALTITUDE_COLORS.length), 0, ALTITUDE_COLORS.length - 1);
  return new THREE.Color(ALTITUDE_COLORS[bandIndex]);
}

function buildTerrainMesh(field: HeightField) {
  const geometry = new THREE.PlaneGeometry(TERRAIN_WIDTH, TERRAIN_DEPTH, field.cols, field.rows).toNonIndexed();
  geometry.rotateX(-Math.PI / 2);

  const position = geometry.attributes.position as THREE.BufferAttribute;
  const colors = new Float32Array(position.count * 3);

  for (let index = 0; index < position.count; index += 3) {
    let triangleHeight = 0;

    for (let offset = 0; offset < 3; offset += 1) {
      const vertexIndex = index + offset;
      const nx = position.getX(vertexIndex) / (TERRAIN_WIDTH / 2);
      const nz = position.getZ(vertexIndex) / (TERRAIN_DEPTH / 2);
      const gx = (nx + 1) * 0.5 * field.cols;
      const gz = (nz + 1) * 0.5 * field.rows;
      const height = sampleHeightField(field, gx, gz);
      position.setY(vertexIndex, height * TERRAIN_HEIGHT);
      triangleHeight += height;
    }

    const color = altitudeColor(triangleHeight / 3);
    for (let offset = 0; offset < 3; offset += 1) {
      const colorIndex = (index + offset) * 3;
      colors[colorIndex] = color.r;
      colors[colorIndex + 1] = color.g;
      colors[colorIndex + 2] = color.b;
    }
  }

  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  geometry.computeVertexNormals();

  const terrain = new THREE.Mesh(
    geometry,
    new THREE.MeshStandardMaterial({
      vertexColors: true,
      flatShading: true,
      roughness: 0.28,
      metalness: 0.08,
      emissive: new THREE.Color(0x082233),
      emissiveIntensity: 0.28,
    }),
  );

  const wire = new THREE.LineSegments(
    new THREE.WireframeGeometry(geometry.clone()),
    new THREE.LineBasicMaterial({
      color: 0x8be7ff,
      transparent: true,
      opacity: 0.045,
    }),
  );
  wire.position.y += 0.03;

  return { terrain, wire };
}

function contourEdgePoint(
  edge: number,
  x0: number,
  z0: number,
  stepX: number,
  stepZ: number,
  tl: number,
  tr: number,
  br: number,
  bl: number,
  threshold: number,
) {
  switch (edge) {
    case 0: {
      const t = (threshold - tl) / ((tr - tl) || 1e-6);
      return { x: x0 + stepX * t, z: z0 };
    }
    case 1: {
      const t = (threshold - tr) / ((br - tr) || 1e-6);
      return { x: x0 + stepX, z: z0 + stepZ * t };
    }
    case 2: {
      const t = (threshold - bl) / ((br - bl) || 1e-6);
      return { x: x0 + stepX * t, z: z0 + stepZ };
    }
    default: {
      const t = (threshold - tl) / ((bl - tl) || 1e-6);
      return { x: x0, z: z0 + stepZ * t };
    }
  }
}

function buildContourGroup(field: HeightField) {
  const group = new THREE.Group();
  const thresholds = Array.from({ length: 11 }, (_, index) => 0.1 + index * 0.08);
  const stepX = field.cols / field.cols;
  const stepZ = field.rows / field.rows;

  thresholds.forEach((threshold, thresholdIndex) => {
    const positions: number[] = [];

    for (let row = 0; row < field.rows; row += 1) {
      for (let col = 0; col < field.cols; col += 1) {
        const tl = field.heights[row][col];
        const tr = field.heights[row][col + 1];
        const br = field.heights[row + 1][col + 1];
        const bl = field.heights[row + 1][col];
        const mask = (tl > threshold ? 8 : 0) | (tr > threshold ? 4 : 0) | (br > threshold ? 2 : 0) | (bl > threshold ? 1 : 0);
        const segments = MARCHING_CASES[mask];
        if (!segments) continue;

        segments.forEach(([edgeA, edgeB]) => {
          const pointA = contourEdgePoint(edgeA, col, row, stepX, stepZ, tl, tr, br, bl, threshold);
          const pointB = contourEdgePoint(edgeB, col, row, stepX, stepZ, tl, tr, br, bl, threshold);
          const worldA = gridToWorld(field, pointA, 0.03 + thresholdIndex * 0.008);
          const worldB = gridToWorld(field, pointB, 0.03 + thresholdIndex * 0.008);

          positions.push(worldA.x, worldA.y, worldA.z, worldB.x, worldB.y, worldB.z);
        });
      }
    }

    if (positions.length === 0) return;

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));

    group.add(
      new THREE.LineSegments(
        geometry,
        new THREE.LineBasicMaterial({
          color: new THREE.Color().setHSL(0.55, 0.92, 0.5 + thresholdIndex * 0.02),
          transparent: true,
          opacity: 0.12 + thresholdIndex * 0.012,
          blending: THREE.AdditiveBlending,
        }),
      ),
    );
  });

  return group;
}

function buildRiverGroup(field: HeightField) {
  const group = new THREE.Group();
  const flows: { curve: THREE.CatmullRomCurve3; particles: THREE.Points; positions: Float32Array; speed: number }[] = [];

  field.rivers.forEach((river, riverIndex) => {
    const points = river.points.map((point) => gridToWorld(field, point, 0.06));
    const curve = new THREE.CatmullRomCurve3(points);

    const glow = new THREE.Mesh(
      new THREE.TubeGeometry(curve, 220, river.glowRadius, 10, false),
      new THREE.MeshBasicMaterial({
        color: river.glowColor,
        transparent: true,
        opacity: 0.2,
        blending: THREE.AdditiveBlending,
      }),
    );

    const core = new THREE.Mesh(
      new THREE.TubeGeometry(curve, 220, river.radius, 10, false),
      new THREE.MeshBasicMaterial({
        color: river.coreColor,
        transparent: true,
        opacity: 0.9,
      }),
    );

    const particleGeometry = new THREE.BufferGeometry();
    const positions = new Float32Array(river.particleCount * 3);
    particleGeometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));

    const particles = new THREE.Points(
      particleGeometry,
      new THREE.PointsMaterial({
        color: river.coreColor,
        size: riverIndex === 0 ? 0.14 : 0.11,
        transparent: true,
        opacity: 0.82,
        blending: THREE.AdditiveBlending,
        sizeAttenuation: true,
      }),
    );

    group.add(glow, core, particles);
    flows.push({ curve, particles, positions, speed: riverIndex === 0 ? 0.028 : 0.038 });
  });

  return { group, flows };
}

function buildBeacon(field: HeightField, camp: SandtableCamp) {
  const point = {
    x: camp.position.x / 100 * field.cols,
    z: camp.position.y / 100 * field.rows,
  };
  const anchor = gridToWorld(field, point, 0.08);
  const accent = new THREE.Color(camp.accent);
  const group = new THREE.Group();

  const beam = new THREE.Mesh(
    new THREE.CylinderGeometry(0.018, 0.018, 1.4, 8),
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.56 }),
  );
  beam.position.y = 0.72;
  group.add(beam);

  const orb = new THREE.Mesh(
    new THREE.SphereGeometry(0.11, 16, 16),
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.98 }),
  );
  orb.position.y = 1.42;
  group.add(orb);

  const halo = new THREE.Mesh(
    new THREE.RingGeometry(0.16, 0.28, 48),
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.5, side: THREE.DoubleSide }),
  );
  halo.rotation.x = -Math.PI / 2;
  halo.position.y = 0.08;
  group.add(halo);

  group.position.copy(anchor);
  return { group, anchor, beam, orb, halo };
}

function buildBasePlate() {
  const group = new THREE.Group();

  const plate = new THREE.Mesh(
    new THREE.BoxGeometry(TERRAIN_WIDTH + 1.4, 0.14, TERRAIN_DEPTH + 1.2),
    new THREE.MeshStandardMaterial({
      color: 0x041019,
      emissive: new THREE.Color(0x061d29),
      emissiveIntensity: 0.35,
      roughness: 0.42,
      metalness: 0.08,
      transparent: true,
      opacity: 0.82,
    }),
  );
  plate.position.y = -0.34;
  group.add(plate);

  const outline = new THREE.LineSegments(
    new THREE.EdgesGeometry(new THREE.BoxGeometry(TERRAIN_WIDTH + 1.4, 0.14, TERRAIN_DEPTH + 1.2)),
    new THREE.LineBasicMaterial({
      color: 0x64dfff,
      transparent: true,
      opacity: 0.22,
    }),
  );
  outline.position.y = -0.34;
  group.add(outline);

  return group;
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
  const containerRef = useRef<HTMLDivElement | null>(null);
  const markerRefs = useRef<Record<string, HTMLAnchorElement | null>>({});
  const activeIdRef = useRef(activeId);

  useEffect(() => {
    activeIdRef.current = activeId;
  }, [activeId]);

  useEffect(() => {
    const mount = containerRef.current;
    if (!mount) return undefined;
    const element = mount;

    const field = createHeightField(HEIGHT_GRID_X, HEIGHT_GRID_Z);
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x02070c, 0.04);

    const camera = new THREE.PerspectiveCamera(28, 1, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.domElement.className = "h-full w-full";
    element.appendChild(renderer.domElement);

    const root = new THREE.Group();
    scene.add(root);

    const ambient = new THREE.HemisphereLight(0xb8f6ff, 0x02070c, 1.1);
    const sun = new THREE.DirectionalLight(0x8ee8ff, 1.3);
    sun.position.set(6, 9, 5);
    const rim = new THREE.PointLight(0x52dfff, 2.2, 26, 2);
    rim.position.set(-5, 4, 4);
    scene.add(ambient, sun, rim);

    const plate = buildBasePlate();
    const { terrain, wire } = buildTerrainMesh(field);
    const contours = buildContourGroup(field);
    const { group: riverGroup, flows } = buildRiverGroup(field);
    root.add(plate, terrain, wire, contours, riverGroup);

    const beacons = camps.map((camp) => buildBeacon(field, camp));
    beacons.forEach((beacon) => root.add(beacon.group));

    const controls = {
      active: false,
      lastX: 0,
      lastY: 0,
      azimuth: 0.02,
      polar: 0.86,
      targetAzimuth: 0.02,
      targetPolar: 0.86,
    };

    const handlePointerDown = (event: PointerEvent) => {
      controls.active = true;
      controls.lastX = event.clientX;
      controls.lastY = event.clientY;
      element.style.cursor = "grabbing";
      element.setPointerCapture(event.pointerId);
    };

    const handlePointerMove = (event: PointerEvent) => {
      if (!controls.active) return;
      const dx = event.clientX - controls.lastX;
      const dy = event.clientY - controls.lastY;
      controls.lastX = event.clientX;
      controls.lastY = event.clientY;
      controls.targetAzimuth = clamp(controls.targetAzimuth - dx * 0.0056, -0.5, 0.5);
      controls.targetPolar = clamp(controls.targetPolar + dy * 0.0046, 0.72, 1.08);
    };

    const handlePointerUp = (event: PointerEvent) => {
      controls.active = false;
      element.style.cursor = "grab";
      if (element.hasPointerCapture(event.pointerId)) {
        element.releasePointerCapture(event.pointerId);
      }
    };

    element.style.cursor = "grab";
    element.addEventListener("pointerdown", handlePointerDown);
    element.addEventListener("pointermove", handlePointerMove);
    element.addEventListener("pointerup", handlePointerUp);
    element.addEventListener("pointercancel", handlePointerUp);

    function resize() {
      const width = element.clientWidth;
      const height = element.clientHeight;
      camera.aspect = width / Math.max(height, 1);
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
    }

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(element);
    resize();

    const focusPoint = new THREE.Vector3(0, 1.5, 0.3);
    let frame = 0;

    const updateMarkerPositions = () => {
      beacons.forEach((beacon, index) => {
        const marker = markerRefs.current[camps[index].id];
        if (!marker) return;

        const projected = beacon.anchor.clone().add(new THREE.Vector3(0, 1.45, 0)).project(camera);
        const visible = projected.z > -1 && projected.z < 1;
        marker.style.left = `${(projected.x * 0.5 + 0.5) * 100}%`;
        marker.style.top = `${(-projected.y * 0.5 + 0.5) * 100}%`;
        marker.style.opacity = visible ? "1" : "0";
      });
    };

    const animate = () => {
      frame = window.requestAnimationFrame(animate);
      const time = performance.now() * 0.001;

      controls.azimuth += (controls.targetAzimuth - controls.azimuth) * 0.08;
      controls.polar += (controls.targetPolar - controls.polar) * 0.08;

      const radius = 23;
      camera.position.set(
        Math.sin(controls.azimuth) * Math.sin(controls.polar) * radius,
        Math.cos(controls.polar) * radius + 7.6,
        Math.cos(controls.azimuth) * Math.sin(controls.polar) * radius,
      );
      camera.lookAt(focusPoint);

      sun.position.x = 6 + Math.sin(time * 0.24) * 1.2;
      rim.position.z = 4 + Math.cos(time * 0.31) * 1.1;

      flows.forEach((flow, flowIndex) => {
        for (let index = 0; index < flow.positions.length / 3; index += 1) {
          const sample = (time * flow.speed + index / (flow.positions.length / 3) + flowIndex * 0.18) % 1;
          const point = flow.curve.getPointAt(sample);
          flow.positions[index * 3] = point.x;
          flow.positions[index * 3 + 1] = point.y + 0.03;
          flow.positions[index * 3 + 2] = point.z;
        }
        flow.particles.geometry.attributes.position.needsUpdate = true;
      });

      beacons.forEach((beacon, index) => {
        const selected = activeIdRef.current === camps[index].id;
        const pulse = 0.86 + Math.sin(time * 3 + index * 0.8) * 0.15;
        const beamMaterial = beacon.beam.material as THREE.MeshBasicMaterial;
        const orbMaterial = beacon.orb.material as THREE.MeshBasicMaterial;
        const haloMaterial = beacon.halo.material as THREE.MeshBasicMaterial;

        beamMaterial.opacity = selected ? 0.88 : 0.46;
        orbMaterial.opacity = selected ? 1 : 0.76;
        haloMaterial.opacity = selected ? 0.8 : 0.38;
        beacon.orb.scale.setScalar(selected ? pulse * 1.06 : pulse * 0.9);
        beacon.halo.scale.setScalar(selected ? 1.12 + pulse * 0.08 : 1);
      });

      updateMarkerPositions();
      renderer.render(scene, camera);
    };

    animate();

    return () => {
      window.cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      element.removeEventListener("pointerdown", handlePointerDown);
      element.removeEventListener("pointermove", handlePointerMove);
      element.removeEventListener("pointerup", handlePointerUp);
      element.removeEventListener("pointercancel", handlePointerUp);
      renderer.dispose();
      scene.traverse((object: THREE.Object3D) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.LineSegments || object instanceof THREE.Points) {
          object.geometry.dispose();
          if (Array.isArray(object.material)) {
            object.material.forEach((material: THREE.Material) => material.dispose());
          } else {
            object.material.dispose();
          }
        }
      });
      element.removeChild(renderer.domElement);
    };
  }, [camps]);

  return (
    <div className="relative h-full w-full overflow-hidden rounded-[2.8rem] border border-cyan-100/10 bg-[#02060a]/88 shadow-[0_30px_120px_rgba(0,0,0,.46)]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_14%,rgba(34,211,238,.1),transparent_18%),radial-gradient(circle_at_78%_22%,rgba(125,211,252,.1),transparent_18%),linear-gradient(180deg,rgba(255,255,255,.02),rgba(2,6,23,.22)_30%,rgba(2,6,23,.82))]" />
      <div className="absolute inset-0 panel-grid opacity-[0.08]" />
      <div className="absolute inset-[1.2rem] rounded-[2.1rem] border border-cyan-100/10 portrait:inset-[.85rem]" />
      <div className="absolute inset-[2.2rem] rounded-[1.75rem] border border-white/6 portrait:inset-[1.5rem]" />
      <div ref={containerRef} className="absolute inset-0 touch-none" />

      <div className="pointer-events-none absolute inset-0 z-[2]">
        {camps.map((camp) => {
          const selected = activeId === camp.id;
          return (
            <a
              key={camp.id}
              ref={(node) => {
                markerRefs.current[camp.id] = node;
              }}
              href={camp.href}
              target="_self"
              onMouseEnter={() => onActivate(camp.id)}
              onFocus={() => onActivate(camp.id)}
              className="pointer-events-auto group absolute -translate-x-1/2 -translate-y-1/2 text-inherit no-underline transition-opacity duration-300"
              style={{ left: "50%", top: "50%" }}
            >
              <span
                className={`relative z-[2] flex items-center gap-2 rounded-full border border-cyan-100/15 bg-black/60 px-3 py-1.5 text-[0.72rem] font-benderBold tracking-[0.28em] backdrop-blur-md transition-all duration-300 ${camp.glowClass} ${
                  selected ? "scale-100" : "scale-[.96] opacity-92"
                }`}
              >
                <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: camp.accent, boxShadow: `0 0 14px ${camp.accent}` }} />
                <span className={camp.textClass}>{camp.id}</span>
              </span>

              <span
                className={`absolute left-1/2 top-[-2.8rem] min-w-[6.4rem] -translate-x-1/2 rounded-full border border-white/12 bg-black/78 px-3 py-1.5 text-center text-[0.82rem] text-white/88 opacity-0 transition-all duration-300 group-hover:top-[-3.1rem] group-hover:opacity-100 ${
                  selected ? "top-[-3.1rem] opacity-100" : ""
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
