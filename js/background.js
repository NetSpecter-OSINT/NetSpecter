// background.js - all 5 background renderers

let currentBg  = null;
let animFrame  = null;
const canvas   = () => document.getElementById('bg-canvas');
const ctx      = () => canvas().getContext('2d');

function accent(alpha = 1) {
  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue('--accent').trim();
  // raw is hex like #00ff41 - parse to rgba
  const hex = raw.replace('#', '');
  const r   = parseInt(hex.slice(0, 2), 16);
  const g   = parseInt(hex.slice(2, 4), 16);
  const b   = parseInt(hex.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

function resize() {
  const c  = canvas();
  c.width  = window.innerWidth;
  c.height = window.innerHeight;
}

function stopCurrent() {
  if (animFrame) { cancelAnimationFrame(animFrame); animFrame = null; }
  const c = canvas();
  ctx().clearRect(0, 0, c.width, c.height);
  currentBg = null;
}

// ============================================================
// 1. RADAR SWEEP
// ============================================================
function startRadar() {
  stopCurrent();
  currentBg = 'radar';
  const c   = ctx();

  let angle  = 0;
  const RINGS    = 5;
  const BLIPS    = [];
  const MAX_BLIPS = 18;

  // Seed some blips
  function spawnBlip(cx, cy, maxR) {
    const r   = Math.random() * maxR * 0.88 + maxR * 0.08;
    const a   = Math.random() * Math.PI * 2;
    BLIPS.push({ x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r, born: angle, life: 1 });
  }

  function draw() {
    const W  = canvas().width;
    const H  = canvas().height;
    const cx = W * 0.5;
    const cy = H * 0.5;
    const maxR = Math.max(W, H) * 0.62;

    c.clearRect(0, 0, W, H);

    // Rings
    for (let i = 1; i <= RINGS; i++) {
      const r = (maxR / RINGS) * i;
      c.beginPath();
      c.arc(cx, cy, r, 0, Math.PI * 2);
      c.strokeStyle = accent(0.07);
      c.lineWidth   = 1;
      c.stroke();
    }

    // Cross hairs
    c.strokeStyle = accent(0.06);
    c.lineWidth   = 1;
    c.beginPath(); c.moveTo(cx, 0);   c.lineTo(cx, H);   c.stroke();
    c.beginPath(); c.moveTo(0, cy);   c.lineTo(W, cy);   c.stroke();

    // Sweep gradient
    const grad = c.createConicalGradient
      ? c.createConicalGradient(cx, cy, angle)
      : null;

    // Fallback sweep arc (works everywhere)
    const sweepSpan = 0.55;
    for (let i = 0; i < 28; i++) {
      const frac  = i / 28;
      const a0    = angle - sweepSpan * frac;
      c.beginPath();
      c.moveTo(cx, cy);
      c.arc(cx, cy, maxR, a0 - sweepSpan / 28, a0);
      c.closePath();
      c.fillStyle = accent(0.012 * (1 - frac));
      c.fill();
    }

    // Sweep arm
    c.beginPath();
    c.moveTo(cx, cy);
    c.lineTo(cx + Math.cos(angle) * maxR, cy + Math.sin(angle) * maxR);
    c.strokeStyle = accent(0.55);
    c.lineWidth   = 1.5;
    c.stroke();

    // Spawn blip near sweep arm occasionally
    if (BLIPS.length < MAX_BLIPS && Math.random() < 0.04) spawnBlip(cx, cy, maxR);

    // Draw + age blips
    for (let i = BLIPS.length - 1; i >= 0; i--) {
      const b    = BLIPS[i];
      const age  = ((angle - b.born) % (Math.PI * 2)) / (Math.PI * 2);
      b.life     = Math.max(0, 1 - age * 1.4);
      if (b.life <= 0) { BLIPS.splice(i, 1); continue; }
      c.beginPath();
      c.arc(b.x, b.y, 2.5, 0, Math.PI * 2);
      c.fillStyle = accent(b.life * 0.9);
      c.fill();
      // halo
      c.beginPath();
      c.arc(b.x, b.y, 5, 0, Math.PI * 2);
      c.fillStyle = accent(b.life * 0.15);
      c.fill();
    }

    angle += 0.008;
    animFrame = requestAnimationFrame(draw);
  }
  draw();
}

// ============================================================
// 2. NETWORK TOPOLOGY
// ============================================================
function startNetwork() {
  stopCurrent();
  currentBg = 'network';
  const c   = ctx();

  const NODES = [];
  const COUNT = 42;

  function makeNode(W, H) {
    return {
      x:  Math.random() * W,
      y:  Math.random() * H,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r:  Math.random() > 0.85 ? 3 : 1.5,
    };
  }

  const W = canvas().width;
  const H = canvas().height;
  for (let i = 0; i < COUNT; i++) NODES.push(makeNode(W, H));

  const LINK_DIST = 160;

  function draw() {
    const W = canvas().width;
    const H = canvas().height;
    c.clearRect(0, 0, W, H);

    // Move nodes
    for (const n of NODES) {
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > W) n.vx *= -1;
      if (n.y < 0 || n.y > H) n.vy *= -1;
    }

    // Links
    for (let i = 0; i < NODES.length; i++) {
      for (let j = i + 1; j < NODES.length; j++) {
        const a = NODES[i], b = NODES[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < LINK_DIST) {
          const alpha = (1 - d / LINK_DIST) * 0.18;
          c.beginPath();
          c.moveTo(a.x, a.y);
          c.lineTo(b.x, b.y);
          c.strokeStyle = accent(alpha);
          c.lineWidth   = 0.8;
          c.stroke();
        }
      }
    }

    // Nodes
    for (const n of NODES) {
      c.beginPath();
      c.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      c.fillStyle = accent(n.r > 2 ? 0.55 : 0.3);
      c.fill();
    }

    animFrame = requestAnimationFrame(draw);
  }
  draw();
}

// ============================================================
// 3. HEX DUMP
// ============================================================
function startHexDump() {
  stopCurrent();
  currentBg = 'hexdump';
  const c   = ctx();

  const COL_W  = 38;
  const ROW_H  = 16;
  const SPEED  = 0.4;
  const COLS   = [];

  function initCols(W, H) {
    COLS.length  = 0;
    const numCols = Math.ceil(W / COL_W) + 1;
    for (let i = 0; i < numCols; i++) {
      COLS.push({
        x:      i * COL_W,
        offset: Math.random() * 1000,
        speed:  SPEED * (0.4 + Math.random() * 0.8),
      });
    }
  }

  initCols(canvas().width, canvas().height);

  function randHex() {
    return Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase();
  }

  let tick = 0;
  const cache = {};

  function draw() {
    const W = canvas().width;
    const H = canvas().height;
    c.clearRect(0, 0, W, H);
    c.font = '11px "Share Tech Mono", monospace';

    const rows = Math.ceil(H / ROW_H) + 1;

    for (const col of COLS) {
      col.offset += col.speed;

      for (let r = 0; r < rows; r++) {
        const key   = Math.floor((col.offset / ROW_H + r) * 100) + '_' + col.x;
        if (!cache[key]) cache[key] = randHex();
        const hex   = cache[key];
        const y     = (r * ROW_H - (col.offset % ROW_H));
        const distFromEdge = Math.min(y / (H * 0.3), (H - y) / (H * 0.3), 1);
        const alpha = Math.max(0, distFromEdge * 0.12);
        c.fillStyle = accent(alpha);
        c.fillText(hex, col.x, y);
      }
    }

    // Purge cache occasionally
    tick++;
    if (tick % 600 === 0) { Object.keys(cache).forEach(k => delete cache[k]); }

    animFrame = requestAnimationFrame(draw);
  }
  draw();
}

// ============================================================
// 4. CIRCUIT BOARD (static CSS pattern)
// ============================================================
function startCircuit() {
  stopCurrent();
  currentBg = 'circuit';

  // We draw a tileable circuit pattern once onto the canvas at 120x120,
  // then use CSS background-repeat on a hidden img - actually we'll just
  // draw it repeatedly across the canvas once and leave it static.
  const c  = ctx();
  const W  = canvas().width;
  const H  = canvas().height;
  c.clearRect(0, 0, W, H);

  const TILE = 80;
  const numX = Math.ceil(W / TILE) + 1;
  const numY = Math.ceil(H / TILE) + 1;

  // Define a few trace patterns as offsets within a tile
  const TRACES = [
    // horizontal traces
    (tx, ty) => { c.moveTo(tx, ty + 20); c.lineTo(tx + TILE, ty + 20); },
    (tx, ty) => { c.moveTo(tx, ty + 55); c.lineTo(tx + TILE, ty + 55); },
    // vertical traces
    (tx, ty) => { c.moveTo(tx + 15, ty); c.lineTo(tx + 15, ty + TILE); },
    (tx, ty) => { c.moveTo(tx + 60, ty); c.lineTo(tx + 60, ty + TILE); },
    // L-bends
    (tx, ty) => {
      c.moveTo(tx + 15, ty);
      c.lineTo(tx + 15, ty + 20);
      c.lineTo(tx + 60, ty + 20);
      c.lineTo(tx + 60, ty + TILE);
    },
    (tx, ty) => {
      c.moveTo(tx, ty + 55);
      c.lineTo(tx + 60, ty + 55);
      c.lineTo(tx + 60, ty + 20);
      c.lineTo(tx + TILE, ty + 20);
    },
  ];

  // Seeded random using tile position for consistency
  function seededRand(x, y, n) {
    const s = Math.sin(x * 127.1 + y * 311.7 + n * 74.3) * 43758.5;
    return s - Math.floor(s);
  }

  c.strokeStyle = accent(0.09);
  c.lineWidth   = 1;
  c.lineCap     = 'square';

  for (let ix = 0; ix < numX; ix++) {
    for (let iy = 0; iy < numY; iy++) {
      const tx = ix * TILE;
      const ty = iy * TILE;
      // Pick 1-2 traces per tile
      const t1 = Math.floor(seededRand(ix, iy, 0) * TRACES.length);
      const t2 = Math.floor(seededRand(ix, iy, 1) * TRACES.length);
      c.beginPath();
      TRACES[t1](tx, ty);
      if (seededRand(ix, iy, 2) > 0.5) TRACES[t2](tx, ty);
      c.stroke();

      // Via dots at trace intersections
      if (seededRand(ix, iy, 3) > 0.55) {
        const vx = tx + [15, 60][Math.floor(seededRand(ix, iy, 4) * 2)];
        const vy = ty + [20, 55][Math.floor(seededRand(ix, iy, 5) * 2)];
        c.beginPath();
        c.arc(vx, vy, 2.5, 0, Math.PI * 2);
        c.fillStyle  = accent(0.18);
        c.fill();
        c.beginPath();
        c.arc(vx, vy, 1, 0, Math.PI * 2);
        c.fillStyle  = accent(0.35);
        c.fill();
      }
    }
  }
  // Circuit is static - no animation loop needed
}

// ============================================================
// 5. CRT NOISE
// ============================================================
function startCRTNoise() {
  stopCurrent();
  currentBg = 'crt';
  const c   = ctx();

  // We'll draw sparse coloured noise pixels slowly refreshing
  let imageData = null;

  function buildNoise(W, H) {
    const data = new Uint8ClampedArray(W * H * 4);
    const raw  = getComputedStyle(document.documentElement)
      .getPropertyValue('--accent').trim().replace('#', '');
    const ar   = parseInt(raw.slice(0, 2), 16);
    const ag   = parseInt(raw.slice(2, 4), 16);
    const ab   = parseInt(raw.slice(4, 6), 16);

    for (let i = 0; i < W * H; i++) {
      if (Math.random() < 0.018) {
        const idx  = i * 4;
        const bright = 0.3 + Math.random() * 0.7;
        data[idx]     = ar * bright;
        data[idx + 1] = ag * bright;
        data[idx + 2] = ab * bright;
        data[idx + 3] = Math.floor(Math.random() * 55 + 15);
      }
    }
    return new ImageData(data, W, H);
  }

  let frameCount = 0;
  function draw() {
    const W = canvas().width;
    const H = canvas().height;

    // Redraw noise every ~6 frames for that slow-burn static feel
    if (frameCount % 6 === 0) {
      imageData = buildNoise(W, H);
    }
    c.clearRect(0, 0, W, H);
    if (imageData) c.putImageData(imageData, 0, 0);

    // Occasional horizontal interference line
    if (Math.random() < 0.012) {
      const y = Math.random() * H;
      const h = 1 + Math.floor(Math.random() * 2);
      c.fillStyle = accent(0.04 + Math.random() * 0.06);
      c.fillRect(0, y, W, h);
    }

    frameCount++;
    animFrame = requestAnimationFrame(draw);
  }
  draw();
}

// ============================================================
// PUBLIC API
// ============================================================
const BG_MAP = {
  radar:   startRadar,
  network: startNetwork,
  hexdump: startHexDump,
  circuit: startCircuit,
  crt:     startCRTNoise,
  none:    stopCurrent,
};

export function setBg(name) {
  const fn = BG_MAP[name];
  if (fn) {
    fn();
    localStorage.setItem('netspecter-bg', name);
    document.querySelectorAll('.bg-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.bg === name);
    });
  }
}

export function initBackground() {
  resize();
  window.addEventListener('resize', () => {
    resize();
    // Restart current bg on resize so it fills correctly
    if (currentBg) setBg(currentBg);
    else if (currentBg === null) {
      const saved = localStorage.getItem('netspecter-bg') || 'radar';
      setBg(saved);
    }
  });

  // Theme changes should restart the current bg with the new accent colour
  document.querySelectorAll('.swatch').forEach(s => {
    s.addEventListener('click', () => {
      setTimeout(() => { if (currentBg) setBg(currentBg); }, 50);
    });
  });

  const saved = localStorage.getItem('netspecter-bg') || 'radar';
  setBg(saved);
}