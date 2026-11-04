import * as THREE from "three";
import FRIEND_POOL from "../data/friend-links.json";

const base = import.meta.env.BASE_URL;
const artUrl = (name) => `${base}friend-links-deck/${name}.webp`;
const FRIEND_LINKS_DECK_ASSETS = Object.fromEntries(
  ["back", "lovers", "star", "moon", "sun", "wheel", "strength", "magician", "fool"].map((name) => [name, artUrl(name)])
);
const compact = matchMedia("(max-width: 720px)").matches;
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

const CARD_COUNT = 21;
const CARD_ART_POOL = [
  { image: FRIEND_LINKS_DECK_ASSETS.lovers, accent: "#d7c0ff" },
  { image: FRIEND_LINKS_DECK_ASSETS.star, accent: "#ffe09d" },
  { image: FRIEND_LINKS_DECK_ASSETS.moon, accent: "#b5c7ff" },
  { image: FRIEND_LINKS_DECK_ASSETS.sun, accent: "#f7d18d" },
  { image: FRIEND_LINKS_DECK_ASSETS.wheel, accent: "#c0f1d8" },
  { image: FRIEND_LINKS_DECK_ASSETS.strength, accent: "#f1c2ff" },
  { image: FRIEND_LINKS_DECK_ASSETS.magician, accent: "#ffc7df" },
  { image: FRIEND_LINKS_DECK_ASSETS.fool, accent: "#f6d8a9" },
];
const CARD_VISUALS = Array.from({ length: CARD_COUNT }, (_, index) => ({
  id: `card-${String(index + 1).padStart(2, "0")}`,
  ...CARD_ART_POOL[index % CARD_ART_POOL.length],
}));

const BACK_IMAGE = FRIEND_LINKS_DECK_ASSETS.back;
const STATES = Object.freeze({ LOADING: "LOADING", IDLE: "IDLE", REVEALED: "REVEALED", DISSOLVING: "DISSOLVING" });
const CONFIG = {
  spacing: 5.72,
  baseScale: 1.04,
  hoverScale: 1.13,
  revealScale: 1.36,
  revealDistance: 8.5,
  wheelScrollFactor: 0.0115,
  dragScrollFactor: 0.042,
  scrollSpring: 0.138,
  scrollDamping: 0.88,
  scrollMaxSpeed: 4.4,
  floatY: 0.11,
  floatZ: 0.06,
  swayZ: 0.024,
  swayX: 0.02,
};

const ui = {
  whisperTitle: document.getElementById("whisper-title"),
  whisperText: document.getElementById("whisper-text"),
  nameplate: document.getElementById("nameplate"),
  nameplateTitle: document.getElementById("nameplate-title"),
  nameplateState: document.getElementById("nameplate-state"),
};

let scene;
let camera;
let renderer;
let raycaster;
let deckGroup;
let galaxySystem;
let particles = null;
let particleLife = 0;
let cards = [];
let appState = STATES.LOADING;
let currentCard = null;
let deckScroll = 0;
let deckScrollTarget = 0;
let deckScrollVelocity = 0;
let deckMaxScroll = 0;
let dragPointerId = null;
let dragStartX = 0;
let dragStartScroll = 0;
let isDraggingDeck = false;
let drawQueue = [];
let lastDrawId = null;

const mouse = new THREE.Vector2(0, 0);
const targetMouse = new THREE.Vector2(0, 0);

function setState(state) {
  appState = state;
}

function setWhisper(title, text) {
  ui.whisperTitle.textContent = title;
  ui.whisperText.textContent = text;
}

let circleTexture;
function createCircleTexture() {
  if (circleTexture) return circleTexture;
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const ctx = canvas.getContext("2d");
  const gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, "rgba(255,255,255,1)");
  gradient.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 64, 64);
  circleTexture = new THREE.CanvasTexture(canvas);
  return circleTexture;
}

function shuffle(array) {
  const copy = array.slice();
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(Math.random() * (index + 1));
    [copy[index], copy[swapIndex]] = [copy[swapIndex], copy[index]];
  }
  return copy;
}

function refillDrawQueue() {
  drawQueue = shuffle(FRIEND_POOL);
  if (drawQueue.length > 1 && lastDrawId && drawQueue[0].id === lastDrawId) {
    [drawQueue[0], drawQueue[1]] = [drawQueue[1], drawQueue[0]];
  }
}

function assignLinkToCard(card) {
  if (card.userData.assignedLink) return card.userData.assignedLink;
  if (drawQueue.length === 0) refillDrawQueue();
  const link = drawQueue.shift();
  card.userData.assignedLink = link;
  lastDrawId = link.id;
  return link;
}

// Share GPU textures. Only the card back is required for the first interactive frame.
const textureCache = new Map();
function loadTexture(src) {
  if (!textureCache.has(src)) {
    const promise = new THREE.TextureLoader().loadAsync(src).then((texture) => {
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.anisotropy = Math.min(4, renderer.capabilities.getMaxAnisotropy());
      return texture;
    }).catch((error) => {
      textureCache.delete(src);
      throw error;
    });
    textureCache.set(src, promise);
  }
  return textureCache.get(src);
}
let backTexture;
let revealRequest = 0;
let frameId = 0;
let pageActive = true;
let ready = false;

function failScene() {
  ready = false;
  cancelAnimationFrame(frameId);
  window.dispatchEvent(new Event("arcana:error"));
}

function updateActivity() {
  cancelAnimationFrame(frameId);
  frameId = 0;
  if (ready && pageActive && !document.hidden) animate();
}

addEventListener("message", (event) => {
  if (event.origin !== location.origin || event.source !== parent || event.data?.type !== "arcana:activity") return;
  pageActive = event.data.active === true;
  updateActivity();
});
addEventListener("visibilitychange", updateActivity);

function createGalaxy() {
  const count = compact ? 1400 : 3600;
  const positions = new Float32Array(count * 3);
  const colors = new Float32Array(count * 3);
  const geometry = new THREE.BufferGeometry();
  const white = new THREE.Color(0xffffff);
  const gold = new THREE.Color(0xf4d59a);

  for (let index = 0; index < count; index += 1) {
    const radius = Math.random() * 52 + 3;
    const spin = radius * 0.15;
    const angle = Math.random() * Math.PI * 2 + spin;
    positions[index * 3] = Math.cos(angle) * radius + (Math.random() - 0.5) * 2.2;
    positions[index * 3 + 1] = (Math.random() - 0.5) * radius * 0.18;
    positions[index * 3 + 2] = Math.sin(angle) * radius - 10;

    const mixed = white.clone().lerp(gold, Math.random() * 0.2);
    colors[index * 3] = mixed.r;
    colors[index * 3 + 1] = mixed.g;
    colors[index * 3 + 2] = mixed.b;
  }

  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  galaxySystem = new THREE.Points(
    geometry,
    new THREE.PointsMaterial({
      size: 0.12,
      vertexColors: true,
      transparent: true,
      opacity: 0.92,
      sizeAttenuation: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      map: createCircleTexture(),
    })
  );
  scene.add(galaxySystem);
}

function updateDeckScrollBounds() {
  const totalWidth = (CARD_COUNT - 1) * CONFIG.spacing + 3.2;
  const viewHeight = 2 * Math.tan(THREE.MathUtils.degToRad(camera.fov * 0.5)) * camera.position.z;
  const viewWidth = viewHeight * camera.aspect;
  deckMaxScroll = Math.max(0, (totalWidth - viewWidth * 0.76) * 0.5);
  deckScrollTarget = THREE.MathUtils.clamp(deckScrollTarget, -deckMaxScroll, deckMaxScroll);
  deckScroll = THREE.MathUtils.clamp(deckScroll, -deckMaxScroll, deckMaxScroll);
  deckScrollVelocity = THREE.MathUtils.clamp(deckScrollVelocity, -CONFIG.scrollMaxSpeed, CONFIG.scrollMaxSpeed);
}

function applyDeckScroll(delta) {
  if (appState !== STATES.IDLE) return;
  deckScrollTarget = THREE.MathUtils.clamp(deckScrollTarget + delta, -deckMaxScroll, deckMaxScroll);
  deckScrollVelocity = THREE.MathUtils.clamp(deckScrollVelocity + delta * 0.18, -CONFIG.scrollMaxSpeed, CONFIG.scrollMaxSpeed);
}

const cardGeometry = new THREE.BoxGeometry(2.95, 5.18, 0.12);
function buildCard(cardVisual, index, total) {
  const accent = new THREE.Color(cardVisual.accent);
  const edgeMaterial = new THREE.MeshStandardMaterial({
    color: 0x18121d,
    emissive: accent.clone().multiplyScalar(0.12),
    roughness: 0.76,
    metalness: 0.22,
  });
  const frontMaterial = new THREE.MeshStandardMaterial({
    emissive: new THREE.Color(0xffffff),
    emissiveIntensity: 0.12,
    roughness: 0.3,
    metalness: 0.08,
  });
  const backMaterial = new THREE.MeshStandardMaterial({
    map: backTexture,
    emissive: accent.clone().multiplyScalar(0.04),
    emissiveIntensity: 0.18,
    roughness: 0.42,
    metalness: 0.14,
  });
  const mesh = new THREE.Mesh(
    cardGeometry,
    [edgeMaterial, edgeMaterial, edgeMaterial, edgeMaterial, frontMaterial, backMaterial]
  );

  mesh.position.x = (index - (total - 1) / 2) * CONFIG.spacing;
  mesh.position.y = -0.72 + ((index % 2) * 0.05);
  mesh.position.z = -Math.abs(index - (total - 1) / 2) * 0.02;
  mesh.rotation.y = Math.PI;
  mesh.rotation.z = ((index % 3) - 1) * 0.028;
  mesh.scale.setScalar(CONFIG.baseScale);
  mesh.userData = {
    cardId: cardVisual.id,
    art: cardVisual.image,
    assignedLink: null,
    basePos: mesh.position.clone(),
    baseRotZ: mesh.rotation.z,
    floatPhase: index * 0.43,
    floatSpeed: 0.72 + (index % 5) * 0.08,
  };
  cards.push(mesh);
  deckGroup.add(mesh);
}

async function initScene() {
  scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x06040a, 0.02);

  camera = new THREE.PerspectiveCamera(48, innerWidth / innerHeight, 0.1, 1000);
  camera.position.z = 26;

  renderer = new THREE.WebGLRenderer({ antialias: !compact, alpha: true, powerPreference: "low-power" });
  renderer.setSize(innerWidth, innerHeight);
  renderer.setPixelRatio(Math.min(devicePixelRatio, compact ? 1.25 : 1.75));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  document.getElementById("scene-root").appendChild(renderer.domElement);
  renderer.domElement.tabIndex = 0;
  renderer.domElement.dataset.cursor = "default";
  renderer.domElement.setAttribute("role", "button");
  renderer.domElement.setAttribute("aria-label", "Tarot deck: arrow keys to browse, Enter to reveal and visit, Escape to return");

  scene.add(new THREE.AmbientLight(0xffffff, 0.86));

  const key = new THREE.DirectionalLight(0xffffff, 1.08);
  key.position.set(0, 10, 12);
  scene.add(key);

  const rim = new THREE.PointLight(0xffd5c9, 0.78, 36);
  rim.position.set(0, -2, 8);
  scene.add(rim);

  renderer.domElement.addEventListener("webglcontextlost", (event) => {
    event.preventDefault();
    failScene();
  });
  backTexture = await loadTexture(BACK_IMAGE);
  if (document.documentElement.dataset.arcanaFailed === "true") return;
  createGalaxy();

  deckGroup = new THREE.Group();
  scene.add(deckGroup);
  CARD_VISUALS.forEach((cardVisual, index) => buildCard(cardVisual, index, CARD_VISUALS.length));
  updateDeckScrollBounds();

  raycaster = new THREE.Raycaster();
  bindInput();
  addEventListener("resize", onResize);

  setState(STATES.IDLE);
  setWhisper("The Arcana", "Drag or scroll to explore · Click to reveal");
  ready = true;
  updateActivity();
  window.dispatchEvent(new Event("arcana:ready"));
  parent.postMessage({ type: "arcana:ready" }, location.origin);
}

function getHoveredCard() {
  scene.updateMatrixWorld();
  raycaster.setFromCamera(mouse, camera);
  return raycaster.intersectObjects(cards, false)[0]?.object ?? null;
}

async function revealCard(card) {
  if (appState !== STATES.IDLE) return;
  const request = ++revealRequest;
  let timeout;
  setState(STATES.LOADING);
  setWhisper("Parting the veil", "A hidden world is coming into view…");
  try {
    const texture = await Promise.race([
      loadTexture(card.userData.art),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("Card timed out")), 8000); }),
    ]);
    if (request !== revealRequest) return;
    card.material[4].map = texture;
    card.material[4].needsUpdate = true;
    const link = assignLinkToCard(card);
    currentCard = card;
    setState(STATES.REVEALED);
    ui.nameplateTitle.textContent = link.name;
    ui.nameplateState.textContent = "Click once more to open the gate";
    ui.nameplate.classList.add("is-visible");
    setWhisper("Beyond the veil", "Click again to visit · Click outside or Esc to return");
  } catch {
    if (request !== revealRequest) return;
    setState(STATES.IDLE);
    setWhisper("The veil remains", "The card could not be revealed. Try again, or use Kindred Worlds below.");
    document.getElementById("quick-links").open = true;
  } finally {
    clearTimeout(timeout);
  }
}

function returnToDeck() {
  if (appState === STATES.DISSOLVING) return;
  revealRequest += 1;
  if (currentCard) currentCard.userData.assignedLink = null;
  currentCard = null;
  ui.nameplate.classList.remove("is-visible");
  setState(STATES.IDLE);
  setWhisper("The Arcana", "Drag or scroll to explore · Click to reveal");
}

function resetAfterOpen() {
  if (currentCard) {
    currentCard.visible = true;
    currentCard.userData.assignedLink = null;
  }
  currentCard = null;
  ui.nameplate.classList.remove("is-visible");
  setState(STATES.IDLE);
  setWhisper("The Arcana", "Drag or scroll to explore · Click to reveal");
}

function spawnDissolve(card) {
  const count = compact ? 500 : 1200;
  const positions = new Float32Array(count * 3);
  const velocities = new Float32Array(count * 3);
  const center = new THREE.Vector3();
  card.getWorldPosition(center);

  for (let index = 0; index < count; index += 1) {
    positions[index * 3] = center.x + (Math.random() - 0.5) * 3.1;
    positions[index * 3 + 1] = center.y + (Math.random() - 0.5) * 4.8;
    positions[index * 3 + 2] = center.z + (Math.random() - 0.5) * 0.8;

    const speed = 0.08 + Math.random() * 0.18;
    velocities[index * 3] = (Math.random() - 0.5) * speed;
    velocities[index * 3 + 1] = (Math.random() - 0.5) * speed;
    velocities[index * 3 + 2] = (Math.random() - 0.5) * speed;
  }

  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  geometry.setAttribute("velocity", new THREE.BufferAttribute(velocities, 3));
  particles = new THREE.Points(
    geometry,
    new THREE.PointsMaterial({
      color: 0xffffff,
      size: 0.09,
      map: createCircleTexture(),
      transparent: true,
      opacity: 0.86,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
  );
  particleLife = 1;
  scene.add(particles);
}

function openCurrentCard() {
  if (!currentCard || appState !== STATES.REVEALED) return;
  const link = currentCard.userData.assignedLink;
  if (!link) return;
  const gate = new URL(`${base}friend-links-gate/`, location.origin);
  gate.searchParams.set("friend", link.id);
  gate.searchParams.set("art", currentCard.userData.art.split("/").pop().replace(".webp", ""));
  let destination;
  try {
    destination = window.open(gate.href, "_blank");
    if (destination) destination.opener = null;
  } catch {
    destination = null;
  }
  if (!destination) {
    setWhisper("The gate awaits", "Your browser held the gate closed. Visit a world using Kindred Worlds below.");
    document.getElementById("quick-links").open = true;
    return;
  }
  setState(STATES.DISSOLVING);
  setWhisper("The gate is open", "Let the stardust carry you to another world.");
  if (!reducedMotion) spawnDissolve(currentCard);
  currentCard.visible = false;
  setTimeout(resetAfterOpen, 1000);
}

function updateMouse(event) {
  if (!renderer) return;
  const rect = renderer.domElement.getBoundingClientRect();
  targetMouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  targetMouse.y = -(((event.clientY - rect.top) / rect.height) * 2 - 1);
}

function onPointerDown(event) {
  if (event.target !== renderer.domElement || appState === STATES.LOADING) return;
  updateMouse(event);
  dragPointerId = event.pointerId;
  dragStartX = event.clientX;
  dragStartScroll = deckScrollTarget;
  isDraggingDeck = false;
}

function onPointerMove(event) {
  updateMouse(event);
  if (dragPointerId !== event.pointerId || currentCard || appState !== STATES.IDLE) return;
  const deltaX = event.clientX - dragStartX;
  if (!isDraggingDeck && Math.abs(deltaX) > 6) isDraggingDeck = true;
  if (!isDraggingDeck) return;
  const nextScroll = THREE.MathUtils.clamp(dragStartScroll - deltaX * CONFIG.dragScrollFactor, -deckMaxScroll, deckMaxScroll);
  deckScrollVelocity = THREE.MathUtils.clamp((nextScroll - deckScrollTarget) * 0.55, -CONFIG.scrollMaxSpeed, CONFIG.scrollMaxSpeed);
  deckScrollTarget = nextScroll;
}

function onPointerUp(event) {
  if (event.target !== renderer.domElement || appState === STATES.LOADING) return;
  updateMouse(event);
  mouse.copy(targetMouse);
  const hovered = getHoveredCard();
  const dragged = dragPointerId === event.pointerId && isDraggingDeck;

  if (dragPointerId === event.pointerId) {
    dragPointerId = null;
    isDraggingDeck = false;
  }

  if (dragged) return;

  if (currentCard) {
    if (hovered === currentCard) openCurrentCard();
    else returnToDeck();
    return;
  }

  if (hovered) revealCard(hovered);
}

function bindInput() {
  addEventListener("pointermove", onPointerMove);
  addEventListener("pointerdown", onPointerDown);
  addEventListener("pointerup", onPointerUp);
  addEventListener("pointercancel", () => {
    dragPointerId = null;
    isDraggingDeck = false;
  });
  addEventListener("wheel", (event) => {
    if (currentCard || event.target !== renderer.domElement) return;
    event.preventDefault();
    applyDeckScroll((event.deltaX + event.deltaY) * CONFIG.wheelScrollFactor);
  }, { passive: false });
  addEventListener("keydown", (event) => {
    if (event.key === "Escape") returnToDeck();
    if (event.target !== renderer.domElement || event.repeat) return;
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      applyDeckScroll(event.key === "ArrowLeft" ? CONFIG.spacing : -CONFIG.spacing);
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (currentCard) openCurrentCard();
      else {
        const centered = cards.reduce((nearest, card) =>
          Math.abs(card.position.x + deckGroup.position.x) < Math.abs(nearest.position.x + deckGroup.position.x) ? card : nearest
        );
        revealCard(centered);
      }
    }
  });
}

function onResize() {
  camera.aspect = innerWidth / innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(innerWidth, innerHeight);
  renderer.setPixelRatio(Math.min(devicePixelRatio, compact ? 1.25 : 1.75));
  updateDeckScrollBounds();
}

function animateParticles() {
  if (!particles) return;
  const positions = particles.geometry.attributes.position;
  const velocities = particles.geometry.attributes.velocity;
  for (let index = 0; index < positions.count; index += 1) {
    positions.setXYZ(
      index,
      positions.getX(index) + velocities.getX(index),
      positions.getY(index) + velocities.getY(index),
      positions.getZ(index) + velocities.getZ(index)
    );
  }
  positions.needsUpdate = true;
  particleLife -= 0.02;
  particles.material.opacity = Math.max(0, particleLife) * 0.86;
  if (particleLife <= 0) {
    scene.remove(particles);
    particles.geometry.dispose();
    particles.material.dispose();
    particles = null;
  }
}

const scratchPosition = new THREE.Vector3();
const scratchScale = new THREE.Vector3();

function animate() {
  if (!ready || !pageActive || document.hidden) return;
  frameId = requestAnimationFrame(animate);

  mouse.lerp(targetMouse, 0.18);
  const time = performance.now() * 0.001;

  if (galaxySystem && !reducedMotion) {
    galaxySystem.rotation.y += 0.00055;
    galaxySystem.rotation.z += 0.00012;
  }

  const hovered = appState === STATES.IDLE || appState === STATES.REVEALED ? getHoveredCard() : null;
  const cursor = hovered && (!currentCard || hovered === currentCard) ? "interactive" : "default";
  if (renderer.domElement.dataset.cursor !== cursor) renderer.domElement.dataset.cursor = cursor;

  cards.forEach((card) => {
    const { basePos, baseRotZ, floatPhase, floatSpeed } = card.userData;
    const targetPos = scratchPosition.copy(basePos);
    const targetRotY = Math.PI;
    let targetRotZ = baseRotZ;
    let targetRotX = 0;
    let targetScale = CONFIG.baseScale;

    if (appState === STATES.IDLE && !reducedMotion) {
      targetPos.y += Math.sin(time * floatSpeed + floatPhase) * CONFIG.floatY;
      targetPos.z += Math.cos(time * (floatSpeed * 0.85) + floatPhase) * CONFIG.floatZ;
      targetRotZ += Math.sin(time * (floatSpeed * 0.7) + floatPhase) * CONFIG.swayZ;
      targetRotX += Math.cos(time * (floatSpeed * 0.55) + floatPhase) * CONFIG.swayX;
    }

    if (appState === STATES.IDLE && hovered === card) {
      targetPos.z += 0.86;
      targetPos.y += 0.14;
      targetScale = CONFIG.hoverScale;
      targetRotX *= 0.35;
    }

    if (currentCard === card) {
      targetPos.set(0, 0.14, CONFIG.revealDistance);
      targetScale = CONFIG.revealScale;
      card.rotation.x = THREE.MathUtils.lerp(card.rotation.x, 0, 0.12);
      card.rotation.y = THREE.MathUtils.lerp(card.rotation.y, 0, 0.12);
      card.rotation.z = THREE.MathUtils.lerp(card.rotation.z, 0, 0.12);
    } else {
      card.rotation.x = THREE.MathUtils.lerp(card.rotation.x, targetRotX, 0.12);
      card.rotation.y = THREE.MathUtils.lerp(card.rotation.y, targetRotY, 0.12);
      card.rotation.z = THREE.MathUtils.lerp(card.rotation.z, targetRotZ, 0.12);
    }

    card.position.lerp(targetPos, 0.12);
    card.scale.lerp(scratchScale.setScalar(targetScale), 0.12);

    if (!card.visible && appState !== STATES.DISSOLVING) card.visible = true;
  });

  if (appState === STATES.IDLE) {
    deckScrollVelocity += (deckScrollTarget - deckScroll) * CONFIG.scrollSpring;
    deckScrollVelocity *= CONFIG.scrollDamping;
    deckScrollVelocity = THREE.MathUtils.clamp(deckScrollVelocity, -CONFIG.scrollMaxSpeed, CONFIG.scrollMaxSpeed);
    deckScroll += deckScrollVelocity;

    if (deckScroll < -deckMaxScroll || deckScroll > deckMaxScroll) {
      deckScroll = THREE.MathUtils.clamp(deckScroll, -deckMaxScroll, deckMaxScroll);
      deckScrollVelocity *= 0.55;
      deckScrollTarget = THREE.MathUtils.clamp(deckScrollTarget, -deckMaxScroll, deckMaxScroll);
    }

    deckGroup.position.x = THREE.MathUtils.lerp(deckGroup.position.x, deckScroll, 0.16);
    deckGroup.rotation.y = THREE.MathUtils.lerp(deckGroup.rotation.y, mouse.x * 0.028, 0.05);
  } else {
    deckGroup.position.x = THREE.MathUtils.lerp(deckGroup.position.x, 0, 0.08);
    deckGroup.rotation.y = THREE.MathUtils.lerp(deckGroup.rotation.y, 0, 0.08);
  }

  animateParticles();
  renderer.render(scene, camera);
}

initScene().catch(failScene);
