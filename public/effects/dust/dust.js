function startDust(canvas) {
  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return;

  let width = 0;
  let height = 0;
  let devicePixelRatio = 1;
  let running = true;

  const particles = [];
  let targetX = 0;
  let targetY = 0;

  function resize() {
    devicePixelRatio = Math.min(2, window.devicePixelRatio || 1);
    width = Math.floor(window.innerWidth);
    height = Math.floor(window.innerHeight);
    canvas.width = Math.floor(width * devicePixelRatio);
    canvas.height = Math.floor(height * devicePixelRatio);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  }

  function rand(min, max) {
    return min + Math.random() * (max - min);
  }

  function spawn(count) {
    for (let index = 0; index < count; index += 1) {
      particles.push({
        x: rand(0, width),
        y: rand(0, height),
        r: rand(0.6, 2.2),
        vx: rand(-0.08, 0.08),
        vy: rand(-0.25, -0.05),
        a: rand(0.06, 0.22),
      });
    }
  }

  function tick() {
    if (!running) return;

    ctx.clearRect(0, 0, width, height);
    ctx.globalCompositeOperation = "lighter";

    const parallaxX = (targetX - width / 2) * 0.015;
    const parallaxY = (targetY - height / 2) * 0.015;

    for (const particle of particles) {
      particle.x += particle.vx;
      particle.y += particle.vy;

      if (particle.y < -10) particle.y = height + 10;
      if (particle.x < -10) particle.x = width + 10;
      if (particle.x > width + 10) particle.x = -10;

      ctx.globalAlpha = particle.a;
      ctx.beginPath();
      ctx.arc(particle.x + parallaxX, particle.y + parallaxY, particle.r, 0, Math.PI * 2);
      ctx.fill();
    }

    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = "source-over";

    window.requestAnimationFrame(tick);
  }

  function resetParticles() {
    particles.length = 0;
    const baseCount = Math.floor((width * height) / 18000);
    const count = Math.max(30, Math.min(140, baseCount));
    spawn(count);
  }

  function onPointerMove(event) {
    targetX = event.clientX;
    targetY = event.clientY;
  }

  function onVisibilityChange() {
    running = document.visibilityState !== "hidden";
    if (running) window.requestAnimationFrame(tick);
  }

  function onResize() {
    resize();
    resetParticles();
  }

  resize();
  resetParticles();

  window.addEventListener("resize", onResize, { passive: true });
  window.addEventListener("mousemove", onPointerMove, { passive: true });
  document.addEventListener("visibilitychange", onVisibilityChange);

  window.requestAnimationFrame(tick);
}

const canvas = document.getElementById("canvas-dust");
if (canvas instanceof HTMLCanvasElement) {
  startDust(canvas);
}
