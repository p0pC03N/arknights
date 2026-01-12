export function startDust(canvas) {
  const ctx = canvas.getContext("2d", { alpha: true });

  let w = 0, h = 0, dpr = 1;
  let running = true;

  const particles = [];
  let targetX = 0, targetY = 0; // 轻微视差

  function resize() {
    dpr = Math.min(2, window.devicePixelRatio || 1);
    w = Math.floor(window.innerWidth);
    h = Math.floor(window.innerHeight);
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function rand(a, b) { return a + Math.random() * (b - a); }

  function spawn(n) {
    for (let i = 0; i < n; i++) {
      particles.push({
        x: rand(0, w),
        y: rand(0, h),
        r: rand(0.6, 2.2),
        vx: rand(-0.08, 0.08),
        vy: rand(-0.25, -0.05),      // 往上飘
        a: rand(0.06, 0.22),         // 透明度
      });
    }
  }

  function tick() {
    if (!running) return;

    ctx.clearRect(0, 0, w, h);

    // 很轻的“雾感/发光感”，不喜欢就删掉
    ctx.globalCompositeOperation = "lighter";

    const px = (targetX - w / 2) * 0.015;
    const py = (targetY - h / 2) * 0.015;

    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;

      // 边界循环
      if (p.y < -10) p.y = h + 10;
      if (p.x < -10) p.x = w + 10;
      if (p.x > w + 10) p.x = -10;

      const x = p.x + px;
      const y = p.y + py;

      ctx.globalAlpha = p.a;
      ctx.beginPath();
      ctx.arc(x, y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }

    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = "source-over";

    requestAnimationFrame(tick);
  }

  // 粒子数量：按屏幕面积给一个上限，避免太吃性能
  function resetParticles() {
    particles.length = 0;
    const base = Math.floor((w * h) / 18000); // 数值越小粒子越多
    const count = Math.max(30, Math.min(140, base));
    spawn(count);
  }

  function onMove(e) {
    targetX = e.clientX;
    targetY = e.clientY;
  }

  function onVisibility() {
    running = document.visibilityState !== "hidden";
    if (running) requestAnimationFrame(tick);
  }

  resize();
  resetParticles();
  window.addEventListener("resize", () => { resize(); resetParticles(); }, { passive: true });
  window.addEventListener("mousemove", onMove, { passive: true });
  document.addEventListener("visibilitychange", onVisibility);

  requestAnimationFrame(tick);

  // 返回销毁函数（以后你要做路由切换/卸载可用）
  return () => {
    running = false;
    window.removeEventListener("mousemove", onMove);
    document.removeEventListener("visibilitychange", onVisibility);
  };
}
