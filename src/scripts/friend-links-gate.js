import friends from "../data/friend-links.json";

const params = new URLSearchParams(location.search);
// Destinations come exclusively from the same friend list as the deck.
const friend = friends.find((entry) => entry.id === params.get("friend"));
const canvas = document.getElementById("stargate");
const phase = document.getElementById("phase");
const destination = document.getElementById("destination");
const continueLink = document.getElementById("continue");

if (friend) {
  document.title = `${friend.name} · Stargate`;
  document.getElementById("friend-name").textContent = friend.name;
  document.getElementById("host").textContent = new URL(friend.url).hostname;
  continueLink.href = friend.url;
  continueLink.hidden = false;
  document.getElementById("fallback").hidden = true;
  startGate().catch(() => {
    // Animation is optional: a failed image/canvas never blocks the destination.
    destination.classList.add("visible");
    phase.textContent = "The gate is open. Your journey begins.";
    location.replace(friend.url);
  });
} else {
  phase.textContent = "This gate has no destination. Choose a kindred world below.";
}

async function startGate() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    destination.classList.add("visible");
    location.replace(friend.url);
    return;
  }

  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas unavailable");
  const artworks = ["lovers", "star", "moon", "sun", "wheel", "strength", "magician", "fool"];
  const art = artworks.includes(params.get("art")) ? params.get("art") : "moon";
  const image = new Image();
  image.src = `${import.meta.env.BASE_URL}friend-links-deck/${art}.webp`;
  // Cached from the revealed card in normal use. Direct visits have a bounded wait.
  await Promise.race([image.decode().catch(() => {}), new Promise((resolve) => setTimeout(resolve, 900))]);

  let width, height, unit, cx, cy;
  function resize() {
    width = innerWidth;
    height = innerHeight;
    unit = Math.min(width / 3.25, height / 3.8, 185);
    cx = width / 2;
    cy = height / 2;
    const dpr = Math.min(devicePixelRatio || 1, 1.5);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  addEventListener("resize", resize);

  const random = (min, max) => min + Math.random() * (max - min);
  const stars = Array.from({ length: width < 720 ? 70 : 140 }, () => ({
    x: Math.random(), y: Math.random(), radius: random(.3, 1.1), alpha: random(.12, .55),
  }));
  const particleCount = width < 720 ? 700 : 1400;
  const dust = Array.from({ length: particleCount }, (_, index) => ({
    x: random(-.53, .53), y: random(-.93, .93),
    angle: index * Math.PI * 2 / particleCount, drift: random(.05, .5), wave: random(-1, 1),
    size: random(.45, 1.5), alpha: random(.35, 1),
  }));
  const clamp = (value) => Math.max(0, Math.min(1, value));
  const smooth = (value) => { const t = clamp(value); return t * t * (3 - 2 * t); };
  const mix = (a, b, t) => a + (b - a) * t;
  // Count foreground animation time, so opening a background tab doesn't skip the effect.
  let elapsed = 0;
  let previous = null;
  let frameId;
  const duration = 1800;

  function draw(now) {
    if (document.hidden) { previous = null; return; }
    if (previous !== null) elapsed += now - previous;
    previous = now;
    const t = Math.min(elapsed / duration, 1);
    document.documentElement.dataset.gatePhase = t < .23 ? "illuminate" : t < .64 ? "dissolve" : "gate";
    const dissolve = smooth((t - .2) / .34);
    const gather = smooth((t - .4) / .34);
    const opening = smooth((t - .7) / .3);
    const orbit = elapsed * .00065;
    const floatX = Math.sin(elapsed * .0024) * unit * .025 * gather;
    const floatY = Math.sin(elapsed * .0032) * unit * .045 * gather;
    const gateX = cx + floatX;
    const gateY = cy + floatY;
    ctx.clearRect(0, 0, width, height);

    for (const star of stars) {
      ctx.globalAlpha = star.alpha;
      ctx.fillStyle = "#dacdeb";
      ctx.beginPath();
      ctx.arc(star.x * width, star.y * height, star.radius, 0, Math.PI * 2);
      ctx.fill();
    }

    // The original card frame lights up before its surface dissolves.
    if (dissolve < 1) {
      ctx.save();
      ctx.translate(cx, cy);
      ctx.globalAlpha = 1 - dissolve;
      const cardWidth = unit * 1.06;
      const cardHeight = unit * 1.86;
      if (image.complete && image.naturalWidth) ctx.drawImage(image, -cardWidth / 2, -cardHeight / 2, cardWidth, cardHeight);
      ctx.shadowBlur = 12 + smooth(t / .22) * 32;
      ctx.shadowColor = "#efd3a2";
      ctx.strokeStyle = "#f5dcac";
      ctx.lineWidth = 1 + smooth(t / .22);
      ctx.strokeRect(-cardWidth / 2 - 5, -cardHeight / 2 - 5, cardWidth + 10, cardHeight + 10);
      ctx.restore();
    }

    ctx.save();
    ctx.globalCompositeOperation = "lighter";
    if (gather > 0) {
      const glow = ctx.createRadialGradient(gateX, gateY, unit * .2, gateX, gateY, unit * 1.8);
      glow.addColorStop(0, `rgba(138,105,182,${gather * .14})`);
      glow.addColorStop(.6, `rgba(230,197,136,${gather * .07})`);
      glow.addColorStop(1, "rgba(100,70,140,0)");
      ctx.globalAlpha = 1;
      ctx.fillStyle = glow;
      ctx.fillRect(0, 0, width, height);
    }
    for (const particle of dust) {
      const angle = particle.angle + orbit;
      const scatterX = particle.x + Math.cos(angle) * particle.drift * dissolve;
      const scatterY = particle.y + Math.sin(angle) * particle.drift * dissolve;
      // One circular orbit, with breathing dust and no drawn inner/outer traces.
      const radius = 1 + particle.wave * .035 + opening * .08 + Math.sin(elapsed * .004 + particle.angle * 3) * .012;
      const gx = Math.cos(angle) * radius;
      const gy = Math.sin(angle) * radius;
      const x = cx + floatX + mix(scatterX, gx, gather) * unit;
      const y = cy + floatY + mix(scatterY, gy, gather) * unit;
      ctx.globalAlpha = particle.alpha * smooth((t - .17) / .2) * (.8 + .2 * Math.sin(particle.angle * 4 + orbit * 2));
      ctx.fillStyle = particle.wave > .1 ? "#e5d4fc" : "#f5d69a";
      ctx.beginPath();
      ctx.arc(x, y, particle.size * (1 + gather * .35), 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
    ctx.globalAlpha = 1;
    destination.classList.toggle("visible", t > .65);
    phase.textContent = t < .23 ? "The arcana awakens" : t < .64 ? "All things return to stardust" : "A world awaits beyond the stars";
    if (t < 1) frameId = requestAnimationFrame(draw);
    else {
      removeEventListener("resize", resize);
      removeEventListener("visibilitychange", onVisibility);
      phase.textContent = "The gate is open. Your journey begins.";
      location.replace(friend.url);
    }
  }

  function onVisibility() {
    cancelAnimationFrame(frameId);
    previous = null;
    if (!document.hidden) frameId = requestAnimationFrame(draw);
  }
  addEventListener("visibilitychange", onVisibility);
  frameId = requestAnimationFrame(draw);
}
