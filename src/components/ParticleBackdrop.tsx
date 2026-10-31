import { useEffect, useRef } from "react";

interface NodePoint {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  baseAlpha: number;
  pulsePhase: number;
  color: string;
}

export function ParticleBackdrop() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let width = window.innerWidth;
    let height = window.innerHeight;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.scale(dpr, dpr);
    };

    resize();

    // Palette of tactical cybersecurity colors
    const colors = [
      "rgba(56, 189, 248, ",   // Cyber Sky Blue
      "rgba(99, 102, 241, ",   // Electric Indigo
      "rgba(52, 211, 153, ",   // Defense Emerald
      "rgba(147, 197, 253, ",  // Ice Blue
    ];

    const isMobile = width < 768;
    const nodeCount = isMobile ? 32 : 68;
    const maxDistance = isMobile ? 95 : 140;

    const nodes: NodePoint[] = Array.from({ length: nodeCount }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      radius: 1.2 + Math.random() * 1.8,
      baseAlpha: 0.25 + Math.random() * 0.5,
      pulsePhase: Math.random() * Math.PI * 2,
      color: colors[Math.floor(Math.random() * colors.length)],
    }));

    // Decorative particles only; this background never represents network traffic or incidents.

    // Mouse tracking for interactive distortion
    const mouse = { x: -9999, y: -9999, radius: 150 };

    const handleMouseMove = (e: MouseEvent) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    };

    const handleMouseLeave = () => {
      mouse.x = -9999;
      mouse.y = -9999;
    };

    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    window.addEventListener("mouseleave", handleMouseLeave, { passive: true });
    window.addEventListener("resize", resize);

    let animationFrameId = 0;
    let radarAngle = 0;

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Subtle tactical radar sweep line across the background
      radarAngle += 0.008;
      const radarCenterX = width * 0.75;
      const radarCenterY = height * 0.3;
      const radarRadius = Math.max(width, height) * 0.6;

      const radarGrad = ctx.createRadialGradient(
        radarCenterX, radarCenterY, 5,
        radarCenterX, radarCenterY, radarRadius
      );
      radarGrad.addColorStop(0, "rgba(56, 189, 248, 0.04)");
      radarGrad.addColorStop(0.5, "rgba(99, 102, 241, 0.02)");
      radarGrad.addColorStop(1, "transparent");

      ctx.fillStyle = radarGrad;
      ctx.beginPath();
      ctx.arc(radarCenterX, radarCenterY, radarRadius, 0, Math.PI * 2);
      ctx.fill();

      // 2. Update and draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];

        if (!prefersReducedMotion) {
          n.x += n.vx;
          n.y += n.vy;

          // Bounce off edges smoothly
          if (n.x < 0) { n.x = 0; n.vx *= -1; }
          if (n.x > width) { n.x = width; n.vx *= -1; }
          if (n.y < 0) { n.y = 0; n.vy *= -1; }
          if (n.y > height) { n.y = height; n.vy *= -1; }

          // Interactive subtle mouse repulsion
          const dx = n.x - mouse.x;
          const dy = n.y - mouse.y;
          const distToMouse = Math.hypot(dx, dy);
          if (distToMouse < mouse.radius && distToMouse > 0) {
            const force = (1 - distToMouse / mouse.radius) * 1.5;
            n.x += (dx / distToMouse) * force;
            n.y += (dy / distToMouse) * force;
          }

          n.pulsePhase += 0.025;
        }

        const currentAlpha = Math.max(0.15, n.baseAlpha + Math.sin(n.pulsePhase) * 0.2);

        // Draw node glow aura
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius * 2.8, 0, Math.PI * 2);
        ctx.fillStyle = `${n.color}${currentAlpha * 0.25})`;
        ctx.fill();

        // Draw core node
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = `${n.color}${currentAlpha})`;
        ctx.fill();
      }

      // 3. Draw decorative connection filaments between nearby background particles
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.hypot(dx, dy);

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * 0.18;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
            ctx.lineWidth = 0.85;
            ctx.stroke();

          }
        }

        // Draw filament to mouse cursor if within range
        const distMouse = Math.hypot(nodes[i].x - mouse.x, nodes[i].y - mouse.y);
        if (distMouse < mouse.radius) {
          const alpha = (1 - distMouse / mouse.radius) * 0.35;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = `rgba(52, 211, 153, ${alpha})`;
          ctx.lineWidth = 1.1;
          ctx.stroke();
        }
      }

      if (!prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(render);
      }
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseleave", handleMouseLeave);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <div
      className="cyber-background-container"
      style={{
        position: "fixed",
        inset: 0,
        pointerEvents: "none",
        zIndex: 0,
        overflow: "hidden",
      }}
      aria-hidden="true"
    >
      {/* Animated tactical ambient glow blobs */}
      <div className="ambient-glow ambient-glow-1" />
      <div className="ambient-glow ambient-glow-2" />
      <div className="ambient-glow ambient-glow-3" />
      
      {/* Interactive Canvas Grid */}
      <canvas
        ref={canvasRef}
        style={{
          position: "absolute",
          inset: 0,
          width: "100%",
          height: "100%",
          opacity: 0.85,
        }}
      />

      {/* High-tech tactical grid overlay */}
      <div className="tactical-grid-overlay" />
      
      {/* Scanning laser line */}
      <div className="tactical-scanline" />
    </div>
  );
}
