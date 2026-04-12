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

const TERRAIN_WIDTH = 18;
const TERRAIN_DEPTH = 12;
const TERRAIN_HEIGHT = 4.8;
const HEIGHT_GRID_X = 96;
const HEIGHT_GRID_Z = 68;

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

function riverCenter(x: number) {
  return 0.28 * Math.sin((x + 0.2) * 2.1) - 0.12 + 0.08 * Math.sin((x - 0.4) * 4.6);
}

function terrainHeight(nx: number, nz: number) {
  const river = riverCenter(nx);
  const riverCut = Math.exp(-Math.pow(nz - river, 2) / 0.02);

  let h = 0.08;
  h += ridge(nx, nz, -0.72, 0.22, -0.92, 0.72, 0.12, 0.88);
  h += ridge(nx, nz, -0.18, -0.05, -0.64, 0.62, 0.13, 1.08);
  h += ridge(nx, nz, 0.32, -0.16, -0.38, 0.56, 0.16, 0.94);
  h += ridge(nx, nz, 0.66, 0.12, 0.22, 0.42, 0.19, 0.48);
  h += 0.18 * Math.exp(-(((nx + 0.78) * (nx + 0.78)) + ((nz - 0.56) * (nz - 0.56))) / 0.12);
  h += 0.14 * Math.exp(-(((nx - 0.54) * (nx - 0.54)) + ((nz + 0.48) * (nz + 0.48))) / 0.09);
  h += 0.06 * Math.cos((nx - 0.24) * 5.2) * Math.sin((nz + 0.08) * 4.1);
  h -= riverCut * 0.38;
  h -= 0.08 * Math.exp(-(((nx + 0.08) * (nx + 0.08)) + ((nz + 0.52) * (nz + 0.52))) / 0.08);

  return clamp(h, 0.02, 1.18);
}

function toWorld(nx: number, nz: number) {
  return {
    x: nx * (TERRAIN_WIDTH / 2),
    y: terrainHeight(nx, nz) * TERRAIN_HEIGHT,
    z: nz * (TERRAIN_DEPTH / 2),
  };
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

function buildContourGroup() {
  const group = new THREE.Group();
  const thresholds = [0.18, 0.28, 0.38, 0.48, 0.58, 0.68, 0.78, 0.88, 0.98];
  const stepX = 2 / HEIGHT_GRID_X;
  const stepZ = 2 / HEIGHT_GRID_Z;
  const heights = Array.from({ length: HEIGHT_GRID_Z + 1 }, (_, row) =>
    Array.from({ length: HEIGHT_GRID_X + 1 }, (_, col) => {
      const nx = -1 + col * stepX;
      const nz = -1 + row * stepZ;
      return terrainHeight(nx, nz);
    }),
  );

  thresholds.forEach((threshold, thresholdIndex) => {
    const positions: number[] = [];

    for (let row = 0; row < HEIGHT_GRID_Z; row += 1) {
      for (let col = 0; col < HEIGHT_GRID_X; col += 1) {
        const tl = heights[row][col];
        const tr = heights[row][col + 1];
        const br = heights[row + 1][col + 1];
        const bl = heights[row + 1][col];
        const mask = (tl > threshold ? 8 : 0) | (tr > threshold ? 4 : 0) | (br > threshold ? 2 : 0) | (bl > threshold ? 1 : 0);
        const segments = MARCHING_CASES[mask];
        if (!segments) continue;

        const x0 = -1 + col * stepX;
        const z0 = -1 + row * stepZ;

        segments.forEach(([edgeA, edgeB]) => {
          const pointA = contourEdgePoint(edgeA, x0, z0, stepX, stepZ, tl, tr, br, bl, threshold);
          const pointB = contourEdgePoint(edgeB, x0, z0, stepX, stepZ, tl, tr, br, bl, threshold);
          const y = threshold * TERRAIN_HEIGHT + 0.02 + thresholdIndex * 0.01;

          positions.push(
            pointA.x * (TERRAIN_WIDTH / 2),
            y,
            pointA.z * (TERRAIN_DEPTH / 2),
            pointB.x * (TERRAIN_WIDTH / 2),
            y,
            pointB.z * (TERRAIN_DEPTH / 2),
          );
        });
      }
    }

    if (positions.length === 0) return;

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));

    const material = new THREE.LineBasicMaterial({
      color: new THREE.Color().setHSL(0.54, 0.9, 0.64 - thresholdIndex * 0.02),
      transparent: true,
      opacity: 0.12 + thresholdIndex * 0.015,
      blending: THREE.AdditiveBlending,
    });

    group.add(new THREE.LineSegments(geometry, material));
  });

  return group;
}

function buildTerrainMesh() {
  const geometry = new THREE.PlaneGeometry(TERRAIN_WIDTH, TERRAIN_DEPTH, 220, 160);
  geometry.rotateX(-Math.PI / 2);

  const position = geometry.attributes.position;
  const colors = new Float32Array(position.count * 3);
  const color = new THREE.Color();

  for (let index = 0; index < position.count; index += 1) {
    const x = position.getX(index) / (TERRAIN_WIDTH / 2);
    const z = position.getZ(index) / (TERRAIN_DEPTH / 2);
    const height = terrainHeight(x, z);

    position.setY(index, height * TERRAIN_HEIGHT);

    const hue = 0.55 - height * 0.03;
    const saturation = 0.72 - height * 0.12;
    const lightness = 0.15 + height * 0.18;
    color.setHSL(hue, saturation, lightness);
    colors[index * 3] = color.r;
    colors[index * 3 + 1] = color.g;
    colors[index * 3 + 2] = color.b;
  }

  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  geometry.computeVertexNormals();

  const material = new THREE.MeshPhysicalMaterial({
    vertexColors: true,
    roughness: 0.18,
    metalness: 0.08,
    clearcoat: 0.42,
    transparent: true,
    opacity: 0.96,
    flatShading: true,
  });

  const mesh = new THREE.Mesh(geometry, material);

  const glow = new THREE.Mesh(
    geometry.clone(),
    new THREE.MeshBasicMaterial({
      color: 0x7ce7ff,
      transparent: true,
      opacity: 0.08,
      blending: THREE.AdditiveBlending,
    }),
  );
  glow.position.y += 0.05;

  const edges = new THREE.LineSegments(
    new THREE.WireframeGeometry(geometry.clone()),
    new THREE.LineBasicMaterial({
      color: 0x7ddcff,
      transparent: true,
      opacity: 0.06,
    }),
  );
  edges.position.y += 0.025;

  return { mesh, glow, edges };
}

function buildRiver() {
  const points: THREE.Vector3[] = [];
  for (let step = 0; step <= 52; step += 1) {
    const nx = -0.98 + (step / 52) * 1.96;
    const nz = riverCenter(nx);
    const point = toWorld(nx, nz);
    points.push(new THREE.Vector3(point.x, point.y + 0.08, point.z));
  }

  const curve = new THREE.CatmullRomCurve3(points);

  const riverGlow = new THREE.Mesh(
    new THREE.TubeGeometry(curve, 180, 0.18, 12, false),
    new THREE.MeshBasicMaterial({
      color: 0x1fb8ff,
      transparent: true,
      opacity: 0.18,
      blending: THREE.AdditiveBlending,
    }),
  );

  const riverCore = new THREE.Mesh(
    new THREE.TubeGeometry(curve, 180, 0.052, 10, false),
    new THREE.MeshBasicMaterial({
      color: 0x86f6ff,
      transparent: true,
      opacity: 0.95,
    }),
  );

  const particleCount = 34;
  const particleGeometry = new THREE.BufferGeometry();
  const particlePositions = new Float32Array(particleCount * 3);
  particleGeometry.setAttribute("position", new THREE.BufferAttribute(particlePositions, 3));

  const particles = new THREE.Points(
    particleGeometry,
    new THREE.PointsMaterial({
      color: 0xa7fbff,
      size: 0.16,
      transparent: true,
      opacity: 0.88,
      sizeAttenuation: true,
      blending: THREE.AdditiveBlending,
    }),
  );

  return { curve, riverGlow, riverCore, particles, particlePositions };
}

function buildBeacon(camp: SandtableCamp) {
  const nx = camp.position.x / 50 - 1;
  const nz = camp.position.y / 50 - 1;
  const point = toWorld(nx, nz);
  const anchor = new THREE.Vector3(point.x, point.y + 0.1, point.z);
  const accent = new THREE.Color(camp.accent);

  const group = new THREE.Group();
  const beam = new THREE.Mesh(
    new THREE.CylinderGeometry(0.018, 0.018, 1.2, 8),
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.55 }),
  );
  beam.position.y = 0.6;
  group.add(beam);

  const orb = new THREE.Mesh(
    new THREE.SphereGeometry(0.1, 16, 16),
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.95 }),
  );
  orb.position.y = 1.25;
  group.add(orb);

  const halo = new THREE.Mesh(
    new THREE.RingGeometry(0.16, 0.24, 32),
    new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.52, side: THREE.DoubleSide }),
  );
  halo.rotation.x = -Math.PI / 2;
  halo.position.y = 0.08;
  group.add(halo);

  group.position.copy(anchor);

  return { group, anchor, beam, orb, halo };
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
    const container = containerRef.current;
    if (!container) return undefined;
    const mount = container;

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x02070c, 0.042);

    const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.domElement.className = "h-full w-full";
    mount.appendChild(renderer.domElement);

    const root = new THREE.Group();
    scene.add(root);

    const ambient = new THREE.HemisphereLight(0xa7efff, 0x02070c, 1.2);
    const directional = new THREE.DirectionalLight(0x90e7ff, 1.35);
    directional.position.set(8, 10, 6);
    const rim = new THREE.PointLight(0x6de7ff, 2.2, 18, 2);
    rim.position.set(-6, 4, 2);
    scene.add(ambient, directional, rim);

    const { mesh, glow, edges } = buildTerrainMesh();
    const contours = buildContourGroup();
    const { curve, riverGlow, riverCore, particles, particlePositions } = buildRiver();

    root.add(mesh, glow, edges, contours, riverGlow, riverCore, particles);

    const beacons = camps.map((camp) => buildBeacon(camp));
    beacons.forEach((beacon) => root.add(beacon.group));

    const baseTheta = 0.14;
    const basePhi = 0.96;
    const drag = {
      active: false,
      lastX: 0,
      lastY: 0,
      theta: baseTheta,
      phi: basePhi,
      targetTheta: baseTheta,
      targetPhi: basePhi,
    };

    const handlePointerDown = (event: PointerEvent) => {
      drag.active = true;
      drag.lastX = event.clientX;
      drag.lastY = event.clientY;
      container.style.cursor = "grabbing";
      mount.setPointerCapture(event.pointerId);
    };

    const handlePointerMove = (event: PointerEvent) => {
      if (!drag.active) return;
      const dx = event.clientX - drag.lastX;
      const dy = event.clientY - drag.lastY;
      drag.lastX = event.clientX;
      drag.lastY = event.clientY;
      drag.targetTheta = clamp(drag.targetTheta - dx * 0.0062, -0.52, 0.52);
      drag.targetPhi = clamp(drag.targetPhi + dy * 0.0048, 0.72, 1.18);
    };

    const handlePointerUp = (event: PointerEvent) => {
      drag.active = false;
      mount.style.cursor = "grab";
      if (mount.hasPointerCapture?.(event.pointerId)) {
        mount.releasePointerCapture(event.pointerId);
      }
    };

    mount.style.cursor = "grab";
    mount.addEventListener("pointerdown", handlePointerDown);
    mount.addEventListener("pointermove", handlePointerMove);
    mount.addEventListener("pointerup", handlePointerUp);
    mount.addEventListener("pointercancel", handlePointerUp);

    function resize() {
      const width = mount.clientWidth;
      const height = mount.clientHeight;
      camera.aspect = width / Math.max(height, 1);
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
    }

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(mount);
    resize();

    const up = new THREE.Vector3(0, 1, 0);
    const center = new THREE.Vector3(0, 1.9, 0);
    let frame = 0;

    const updateMarkerScreenPositions = () => {
      beacons.forEach((beacon, index) => {
        const marker = markerRefs.current[camps[index].id];
        if (!marker) return;

        const projected = beacon.anchor.clone().add(new THREE.Vector3(0, 1.25, 0)).project(camera);
        const visible = projected.z > -1 && projected.z < 1;
        const left = (projected.x * 0.5 + 0.5) * 100;
        const top = (-projected.y * 0.5 + 0.5) * 100;

        marker.style.left = `${left}%`;
        marker.style.top = `${top}%`;
        marker.style.opacity = visible ? "1" : "0";
      });
    };

    const animate = () => {
      frame = window.requestAnimationFrame(animate);

      drag.theta += (drag.targetTheta - drag.theta) * 0.08;
      drag.phi += (drag.targetPhi - drag.phi) * 0.08;

      const radius = 18.5;
      camera.position.set(
        Math.sin(drag.theta) * Math.sin(drag.phi) * radius,
        Math.cos(drag.phi) * radius + 8.4,
        Math.cos(drag.theta) * Math.sin(drag.phi) * radius,
      );
      camera.lookAt(center);
      camera.up.copy(up);

      const time = performance.now() * 0.001;
      root.rotation.y = Math.sin(time * 0.08) * 0.02;

      for (let i = 0; i < particlePositions.length / 3; i += 1) {
        const sample = (time * 0.035 + i / (particlePositions.length / 3)) % 1;
        const point = curve.getPointAt(sample);
        particlePositions[i * 3] = point.x;
        particlePositions[i * 3 + 1] = point.y + 0.03;
        particlePositions[i * 3 + 2] = point.z;
      }
      particles.geometry.attributes.position.needsUpdate = true;

      beacons.forEach((beacon, index) => {
        const camp = camps[index];
        const selected = activeIdRef.current === camp.id;
        const pulse = 0.82 + Math.sin(time * 3.2 + index * 0.8) * 0.18;
        const beamMaterial = beacon.beam.material as THREE.MeshBasicMaterial;
        const orbMaterial = beacon.orb.material as THREE.MeshBasicMaterial;
        const haloMaterial = beacon.halo.material as THREE.MeshBasicMaterial;

        beamMaterial.opacity = selected ? 0.88 : 0.44;
        orbMaterial.opacity = selected ? 1 : 0.72;
        haloMaterial.opacity = selected ? 0.78 : 0.36;
        beacon.orb.scale.setScalar(selected ? pulse * 1.1 : pulse * 0.86);
        beacon.halo.scale.setScalar(selected ? 1.18 + pulse * 0.08 : 1);
      });

      updateMarkerScreenPositions();
      renderer.render(scene, camera);
    };

    animate();

    return () => {
      window.cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      mount.removeEventListener("pointerdown", handlePointerDown);
      mount.removeEventListener("pointermove", handlePointerMove);
      mount.removeEventListener("pointerup", handlePointerUp);
      mount.removeEventListener("pointercancel", handlePointerUp);
      renderer.dispose();
      scene.traverse((object: THREE.Object3D) => {
        if (object instanceof THREE.Mesh) {
          object.geometry.dispose();
          if (Array.isArray(object.material)) {
            object.material.forEach((material: THREE.Material) => material.dispose());
          } else {
            object.material.dispose();
          }
        }

        if (object instanceof THREE.LineSegments) {
          object.geometry.dispose();
          if (Array.isArray(object.material)) {
            object.material.forEach((material: THREE.Material) => material.dispose());
          } else {
            object.material.dispose();
          }
        }

        if (object instanceof THREE.Points) {
          object.geometry.dispose();
          if (Array.isArray(object.material)) {
            object.material.forEach((material: THREE.Material) => material.dispose());
          } else {
            object.material.dispose();
          }
        }
      });
      mount.removeChild(renderer.domElement);
    };
  }, [camps]);

  return (
    <div className="relative h-full w-full overflow-hidden rounded-[2.8rem] border border-cyan-100/10 bg-[#02060a]/88 shadow-[0_30px_120px_rgba(0,0,0,.46)]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_14%,rgba(34,211,238,.1),transparent_18%),radial-gradient(circle_at_78%_22%,rgba(125,211,252,.1),transparent_18%),linear-gradient(180deg,rgba(255,255,255,.02),rgba(2,6,23,.22)_30%,rgba(2,6,23,.82))]" />
      <div className="absolute inset-0 panel-grid opacity-[0.08]" />
      <div className="absolute inset-[1.35rem] rounded-[2.1rem] border border-cyan-100/10 portrait:inset-[.85rem]" />
      <div className="absolute inset-[2.4rem] rounded-[1.75rem] border border-white/6 portrait:inset-[1.5rem]" />
      <div ref={containerRef} className="absolute inset-0 touch-none" />

      <div className="absolute inset-0 z-[2]">
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
              onPointerDown={(event) => event.stopPropagation()}
              className="group absolute -translate-x-1/2 -translate-y-1/2 text-inherit no-underline transition-opacity duration-300"
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
