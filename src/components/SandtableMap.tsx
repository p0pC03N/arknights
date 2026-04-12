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
type HeightField = {
  cols: number;
  rows: number;
  heights: number[][];
};

const TERRAIN_WIDTH = 18.5;
const TERRAIN_DEPTH = 12.5;
const TERRAIN_HEIGHT = 5.5;
const HEIGHT_GRID_X = 144;
const HEIGHT_GRID_Z = 96;
const ALTITUDE_COLORS = [
  0x01070d,
  0x03111d,
  0x071c2b,
  0x0a273a,
  0x10334b,
  0x15415d,
  0x1e5270,
  0x2b6a88,
  0x3f86a3,
  0x58a8c4,
  0x83d3ec,
  0xc2f8ff,
];
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

function smoothstep(edge0: number, edge1: number, value: number) {
  const t = clamp((value - edge0) / (edge1 - edge0), 0, 1);
  return t * t * (3 - 2 * t);
}

function gaussian(x: number, z: number, centerX: number, centerZ: number, radiusX: number, radiusZ: number, intensity: number) {
  return intensity * Math.exp(-(((x - centerX) * (x - centerX)) / (radiusX * radiusX) + ((z - centerZ) * (z - centerZ)) / (radiusZ * radiusZ)));
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

function terrainNoise(x: number, z: number) {
  return (
    Math.sin(x * 8.2) * Math.cos(z * 5.7) * 0.018 +
    Math.sin((x - z) * 12.4) * 0.014 +
    Math.cos((x + z) * 9.1) * 0.01
  );
}

function normalizedToWorld(nx: number, nz: number, height: number) {
  return new THREE.Vector3(nx * (TERRAIN_WIDTH / 2), height * TERRAIN_HEIGHT, nz * (TERRAIN_DEPTH / 2));
}

function terraceHeight(height: number) {
  const stepped = Math.floor(height * 18) / 18;
  return lerp(height, stepped, 0.74);
}

function baseHeight(nx: number, nz: number) {
  const warpedX = nx + Math.sin(nz * 4.2) * 0.045 + Math.sin((nx + nz) * 6.5) * 0.02;
  const warpedZ = nz + Math.cos(nx * 3.6) * 0.04 + Math.sin((nz - nx) * 5.1) * 0.018;

  const westRange = Math.max(
    ridge(warpedX, warpedZ, -0.74, -0.34, 0.88, 0.42, 0.08, 0.92),
    gaussian(warpedX, warpedZ, -0.82, -0.48, 0.12, 0.1, 0.74),
    gaussian(warpedX, warpedZ, -0.66, -0.22, 0.13, 0.11, 0.7),
    gaussian(warpedX, warpedZ, -0.54, 0.02, 0.16, 0.12, 0.42),
  );

  const centralRange = Math.max(
    ridge(warpedX, warpedZ, -0.16, 0.04, 0.66, 0.4, 0.09, 1.02),
    gaussian(warpedX, warpedZ, -0.24, -0.08, 0.12, 0.09, 0.84),
    gaussian(warpedX, warpedZ, -0.08, 0.12, 0.13, 0.11, 0.78),
    gaussian(warpedX, warpedZ, 0.08, 0.26, 0.16, 0.12, 0.5),
  );

  const eastRange = Math.max(
    ridge(warpedX, warpedZ, 0.38, -0.08, 0.36, 0.34, 0.1, 0.96),
    gaussian(warpedX, warpedZ, 0.28, -0.18, 0.12, 0.09, 0.74),
    gaussian(warpedX, warpedZ, 0.46, 0.02, 0.12, 0.1, 0.82),
    gaussian(warpedX, warpedZ, 0.62, 0.16, 0.16, 0.12, 0.46),
  );

  const farMassif = Math.max(
    ridge(warpedX, warpedZ, 0.74, 0.26, 0.12, 0.24, 0.09, 0.62),
    gaussian(warpedX, warpedZ, 0.84, 0.24, 0.09, 0.08, 0.54),
  );

  const southernHills =
    gaussian(warpedX, warpedZ, -0.46, 0.54, 0.2, 0.14, 0.18) +
    gaussian(warpedX, warpedZ, 0.12, 0.62, 0.24, 0.16, 0.12);

  let height = 0.025 + terrainNoise(warpedX, warpedZ);
  height += Math.max(westRange, centralRange, eastRange, farMassif);
  height += southernHills;
  height -= gaussian(warpedX, warpedZ, -0.42, 0.18, 0.16, 0.14, 0.13);
  height -= gaussian(warpedX, warpedZ, 0.18, 0.22, 0.18, 0.16, 0.1);
  height -= gaussian(warpedX, warpedZ, 0.58, 0.42, 0.14, 0.12, 0.08);

  const edgeFade = 1 - smoothstep(0.76, 1.06, Math.max(Math.abs(nx), Math.abs(nz)));
  height *= 0.26 + edgeFade * 0.74;

  return clamp(terraceHeight(height), 0.01, 1.08);
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
  const world = normalizedToWorld(nx, nz, sampleHeightField(field, point.x, point.z));
  world.y += extraY;
  return world;
}

function createHeightField(cols: number, rows: number): HeightField {
  return {
    cols,
    rows,
    heights: Array.from({ length: rows + 1 }, (_, row) =>
      Array.from({ length: cols + 1 }, (_, col) => {
        const nx = col / cols * 2 - 1;
        const nz = row / rows * 2 - 1;
        return baseHeight(nx, nz);
      }),
    ),
  };
}

function altitudeColor(height: number) {
  const shaped = Math.pow(clamp(height / 1.08, 0, 1), 0.92);
  const bandIndex = clamp(Math.floor(shaped * ALTITUDE_COLORS.length), 0, ALTITUDE_COLORS.length - 1);
  return new THREE.Color(ALTITUDE_COLORS[bandIndex]);
}

function buildTerrainMesh(field: HeightField) {
  const geometry = new THREE.PlaneGeometry(TERRAIN_WIDTH, TERRAIN_DEPTH, field.cols, field.rows).toNonIndexed();
  geometry.rotateX(-Math.PI / 2);

  const position = geometry.attributes.position as THREE.BufferAttribute;
  const colors = new Float32Array(position.count * 3);

  for (let index = 0; index < position.count; index += 3) {
    const triangleHeights: number[] = [];

    for (let offset = 0; offset < 3; offset += 1) {
      const vertexIndex = index + offset;
      const nx = position.getX(vertexIndex) / (TERRAIN_WIDTH / 2);
      const nz = position.getZ(vertexIndex) / (TERRAIN_DEPTH / 2);
      const gx = (nx + 1) * 0.5 * field.cols;
      const gz = (nz + 1) * 0.5 * field.rows;
      const height = sampleHeightField(field, gx, gz);
      position.setY(vertexIndex, height * TERRAIN_HEIGHT);
      triangleHeights.push(height);
    }

    const meanHeight = triangleHeights.reduce((sum, value) => sum + value, 0) / triangleHeights.length;
    const color = altitudeColor(meanHeight);
    for (let offset = 0; offset < 3; offset += 1) {
      const colorIndex = (index + offset) * 3;
      colors[colorIndex] = color.r;
      colors[colorIndex + 1] = color.g;
      colors[colorIndex + 2] = color.b;
    }
  }

  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  geometry.computeVertexNormals();

  return new THREE.Mesh(
    geometry,
    new THREE.MeshStandardMaterial({
      vertexColors: true,
      flatShading: true,
      roughness: 0.34,
      metalness: 0.06,
      emissive: new THREE.Color(0x071724),
      emissiveIntensity: 0.26,
    }),
  );
}

function contourEdgePoint(
  edge: number,
  x0: number,
  z0: number,
  tl: number,
  tr: number,
  br: number,
  bl: number,
  threshold: number,
) {
  switch (edge) {
    case 0: {
      const t = (threshold - tl) / ((tr - tl) || 1e-6);
      return { x: x0 + t, z: z0 };
    }
    case 1: {
      const t = (threshold - tr) / ((br - tr) || 1e-6);
      return { x: x0 + 1, z: z0 + t };
    }
    case 2: {
      const t = (threshold - bl) / ((br - bl) || 1e-6);
      return { x: x0 + t, z: z0 + 1 };
    }
    default: {
      const t = (threshold - tl) / ((bl - tl) || 1e-6);
      return { x: x0, z: z0 + t };
    }
  }
}

function buildContourGroup(field: HeightField) {
  const group = new THREE.Group();
  const thresholds = Array.from({ length: 22 }, (_, index) => 0.05 + index * 0.043);

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
          const pointA = contourEdgePoint(edgeA, col, row, tl, tr, br, bl, threshold);
          const pointB = contourEdgePoint(edgeB, col, row, tl, tr, br, bl, threshold);
          const worldA = gridToWorld(field, pointA, 0.05 + thresholdIndex * 0.003);
          const worldB = gridToWorld(field, pointB, 0.05 + thresholdIndex * 0.003);
          positions.push(worldA.x, worldA.y, worldA.z, worldB.x, worldB.y, worldB.z);
        });
      }
    }

    if (positions.length === 0) return;

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    const majorLine = thresholdIndex % 4 === 0;

    group.add(
      new THREE.LineSegments(
        geometry,
        new THREE.LineBasicMaterial({
          color: majorLine ? 0x9af7ff : 0x51dfff,
          transparent: true,
          opacity: majorLine ? 0.55 : 0.28,
          blending: THREE.AdditiveBlending,
        }),
      ),
    );
  });

  return group;
}

function buildFoothillGlow() {
  const geometry = new THREE.PlaneGeometry(TERRAIN_WIDTH + 0.4, TERRAIN_DEPTH + 0.4, 1, 1);
  geometry.rotateX(-Math.PI / 2);

  return new THREE.Mesh(
    geometry,
    new THREE.MeshBasicMaterial({
      color: 0x0f3550,
      transparent: true,
      opacity: 0.3,
      blending: THREE.AdditiveBlending,
      side: THREE.DoubleSide,
    }),
  );
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
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.6 }),
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
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.54, side: THREE.DoubleSide }),
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
    new THREE.BoxGeometry(TERRAIN_WIDTH + 1.6, 0.18, TERRAIN_DEPTH + 1.5),
    new THREE.MeshStandardMaterial({
      color: 0x020811,
      emissive: new THREE.Color(0x061523),
      emissiveIntensity: 0.36,
      roughness: 0.44,
      metalness: 0.08,
      transparent: true,
      opacity: 0.9,
    }),
  );
  plate.position.y = -0.42;
  group.add(plate);

  const outline = new THREE.LineSegments(
    new THREE.EdgesGeometry(new THREE.BoxGeometry(TERRAIN_WIDTH + 1.6, 0.18, TERRAIN_DEPTH + 1.5)),
    new THREE.LineBasicMaterial({
      color: 0x64dfff,
      transparent: true,
      opacity: 0.22,
    }),
  );
  outline.position.y = -0.42;
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
    scene.fog = new THREE.FogExp2(0x01050a, 0.032);

    const camera = new THREE.PerspectiveCamera(28, 1, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.domElement.className = "h-full w-full";
    element.appendChild(renderer.domElement);

    const root = new THREE.Group();
    scene.add(root);

    const ambient = new THREE.HemisphereLight(0xc8fbff, 0x01050a, 1.05);
    const keyLight = new THREE.DirectionalLight(0x8de7ff, 1.36);
    keyLight.position.set(4.8, 9.8, 6.2);
    const fill = new THREE.PointLight(0x38bdf8, 2.2, 26, 2);
    fill.position.set(-5, 4.5, 3.4);
    scene.add(ambient, keyLight, fill);

    const basePlate = buildBasePlate();
    const foothillGlow = buildFoothillGlow();
    foothillGlow.position.y = -0.02;
    const terrain = buildTerrainMesh(field);
    const contours = buildContourGroup(field);
    root.add(basePlate, foothillGlow, terrain, contours);

    const beacons = camps.map((camp) => buildBeacon(field, camp));
    beacons.forEach((beacon) => root.add(beacon.group));

    const controls = {
      active: false,
      lastX: 0,
      lastY: 0,
      azimuth: -0.08,
      polar: 0.94,
      targetAzimuth: -0.08,
      targetPolar: 0.94,
    };

    const handlePointerDown = (event: PointerEvent) => {
      if ((event.target as HTMLElement | null)?.closest("a")) return;
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
      controls.targetAzimuth = clamp(controls.targetAzimuth - dx * 0.0042, -0.42, 0.38);
      controls.targetPolar = clamp(controls.targetPolar + dy * 0.0036, 0.82, 1.02);
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

    const focusPoint = new THREE.Vector3(0.35, 1.05, 0.22);
    let frame = 0;

    const updateMarkerPositions = () => {
      beacons.forEach((beacon, index) => {
        const marker = markerRefs.current[camps[index].id];
        if (!marker) return;

        const projected = beacon.anchor.clone().add(new THREE.Vector3(0, 1.48, 0)).project(camera);
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

      const radius = 22.8;
      camera.position.set(
        Math.sin(controls.azimuth) * Math.sin(controls.polar) * radius,
        Math.cos(controls.polar) * radius + 7.4,
        Math.cos(controls.azimuth) * Math.sin(controls.polar) * radius,
      );
      camera.lookAt(focusPoint);

      keyLight.position.x = 4.8 + Math.sin(time * 0.18) * 0.8;
      fill.position.z = 3.4 + Math.cos(time * 0.24) * 0.7;

      beacons.forEach((beacon, index) => {
        const selected = activeIdRef.current === camps[index].id;
        const pulse = 0.88 + Math.sin(time * 2.7 + index * 0.7) * 0.14;
        const beamMaterial = beacon.beam.material as THREE.MeshBasicMaterial;
        const orbMaterial = beacon.orb.material as THREE.MeshBasicMaterial;
        const haloMaterial = beacon.halo.material as THREE.MeshBasicMaterial;

        beamMaterial.opacity = selected ? 0.92 : 0.48;
        orbMaterial.opacity = selected ? 1 : 0.78;
        haloMaterial.opacity = selected ? 0.82 : 0.42;
        beacon.orb.scale.setScalar(selected ? pulse * 1.06 : pulse * 0.9);
        beacon.halo.scale.setScalar(selected ? 1.14 + pulse * 0.08 : 1);
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
        if (object instanceof THREE.Mesh || object instanceof THREE.LineSegments) {
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
    <div className="relative h-full w-full overflow-hidden rounded-[2.8rem] border border-cyan-100/10 bg-[#01050a]/92 shadow-[0_30px_120px_rgba(0,0,0,.46)]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_14%,rgba(56,189,248,.08),transparent_18%),radial-gradient(circle_at_78%_22%,rgba(186,230,253,.08),transparent_18%),linear-gradient(180deg,rgba(255,255,255,.02),rgba(2,6,23,.18)_30%,rgba(2,6,23,.84))]" />
      <div className="absolute inset-0 panel-grid opacity-[0.07]" />
      <div className="absolute inset-[1.1rem] rounded-[2.15rem] border border-cyan-100/10 portrait:inset-[.85rem]" />
      <div className="absolute inset-[2rem] rounded-[1.8rem] border border-white/6 portrait:inset-[1.4rem]" />
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
                className={`relative z-[2] flex items-center gap-2 rounded-full border border-cyan-100/15 bg-black/68 px-3 py-1.5 text-[0.72rem] font-benderBold tracking-[0.28em] backdrop-blur-md transition-all duration-300 ${camp.glowClass} ${
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
