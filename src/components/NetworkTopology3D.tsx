import { useEffect, useRef, useState, useId } from "react";
import * as THREE from "three";
import { Shield, ZoomIn, ZoomOut, RotateCcw, X } from "lucide-react";

export type VisualTone = "COOL" | "AMBER" | "ROSE";

interface NodeData {
  id: string;
  name: string;
  role: string;
  category: "agent" | "core" | "ingress" | "target";
  status: string;
  latency: string;
  flows: string;
  color: number;
  description: string;
  contract: string;
}

const NODES_METADATA: Record<string, NodeData> = {
  core: {
    id: "core",
    name: "CyberSentinel Nexus Core",
    role: "Stateful Replay & Ingress Decision Bus",
    category: "core",
    status: "SCHEMATIC",
    latency: "Not measured in schematic",
    flows: "No live telemetry",
    color: 0x38bdf8,
    description: "Checks policies activated by earlier records before allowing a flow into the decision pipeline. Classification outputs are still retained for every record.",
    contract: "Input: Organizer flow record -> Output: Causal replay gate (ALLOW / BLOCK)",
  },
  agent1: {
    id: "agent1",
    name: "Agent 1: Threat Detection",
    role: "Supervised Multiclass Classifier (Random Forest)",
    category: "agent",
    status: "MODEL-DEPENDENT",
    latency: "Not measured in schematic",
    flows: "No live telemetry",
    color: 0x06b6d4, // Cyan
    description: "Evaluates 78 numeric network flow features to classify known attack families (DoS, DDoS, PortScan, BruteForce) with model confidence (not probability-calibrated).",
    contract: "Input: 78 numeric flow features -> Output: Class + Confidence",
  },
  agent2: {
    id: "agent2",
    name: "Agent 2: Anomaly Detection",
    role: "Unsupervised Baseline Isolation Forest",
    category: "agent",
    status: "MODEL-DEPENDENT",
    latency: "Measured per inference",
    flows: "Awaiting measured replay",
    color: 0xa855f7, // Purple
    description: "Trained exclusively on benign baseline traffic with no label leakage. Computes a bounded anomaly index against the benign training baseline; the index is not a probability.",
    contract: "Input: 78 numeric flow features -> Output: Bounded anomaly index [0, 1] + Flag",
  },
  agent3: {
    id: "agent3",
    name: "Agent 3: Evidence Fusion",
    role: "Tactical Consensus Matrix Arbiter",
    category: "agent",
    status: "CODE PRESENT",
    latency: "Not independently measured",
    flows: "Deterministic evidence fusion",
    color: 0x10b981, // Emerald
    description: "Combines A1/A2 outputs into AGREE, CONFLICT, or UNCERTAIN evidence and a deterministic recommendation. The replay gate, not this schematic, determines the final ALLOW/BLOCK action.",
    contract: "Input: ThreatResult + AnomalyResult -> Output: Action + Rationale",
  },
  agent4: {
    id: "agent4",
    name: "Agent 4: Temporal Correlation",
    role: "Sliding-Window Campaign Correlator",
    category: "agent",
    status: "CODE PRESENT",
    latency: "Not independently measured",
    flows: "Observed-window correlation",
    color: 0xf59e0b, // Amber
    description: "Maintains causal sliding windows to group multi-flow attack patterns: Horizontal Port Scans (>=5 ports), DDoS convergence, and brute-force auth sweeps.",
    contract: "Input: Flow summary + History -> Output: Group ID + Pattern Rationale",
  },
  agent5: {
    id: "agent5",
    name: "Agent 5: Adaptive Defense",
    role: "Simulated Quarantine Policy Synthesizer",
    category: "agent",
    status: "SIMULATED ONLY",
    latency: "Not independently measured",
    flows: "Temporary simulated policies",
    color: 0xf43f5e, // Rose / Red
    description: "Creates temporary simulated policy records for observed source endpoints. No operating-system or network firewall is modified.",
    contract: "Input: Consensus evidence -> Output: Policy ID + Expiry boundary",
  },
  ingress: {
    id: "ingress",
    name: "Ingress Edge Cluster",
    role: "Offline Organizer Replay Input",
    category: "ingress",
    status: "OFFLINE INPUT",
    latency: "Not measured",
    flows: "Organizer-provided observed endpoints",
    color: 0x60a5fa,
    description: "Represents the offline organizer-input boundary. Only literal observed source/destination endpoint fields are used; missing endpoints remain unknown.",
    contract: "Organizer row -> 78 flow features + observed endpoint metadata",
  },
  target: {
    id: "target",
    name: "Illustrative downstream service",
    role: "Diagram-only target node",
    category: "target",
    status: "ILLUSTRATIVE",
    latency: "Not measured",
    flows: "Schematic target; no live network connection",
    color: 0x34d399,
    description: "Illustrative protected service endpoint for the architecture view. No traffic is sent to or received from a real datacenter.",
    contract: "Illustrative target only; no live network egress",
  },
};

export function NetworkTopology3D({ visualTone = "COOL" }: { visualTone?: VisualTone }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hasWebGL, setHasWebGL] = useState(true);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [hoveredNode, setHoveredNode] = useState<NodeData | null>(null);
  const [zoomLevel, setZoomLevel] = useState<number>(7.5);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const gradientId = useId();

  // Zoom controls
  const handleZoom = (delta: number) => {
    if (!cameraRef.current) return;
    const newZ = Math.max(4.0, Math.min(13.0, cameraRef.current.position.z + delta));
    cameraRef.current.position.z = newZ;
    setZoomLevel(newZ);
  };

  const handleResetCamera = () => {
    if (!cameraRef.current) return;
    cameraRef.current.position.set(0, 0, 7.5);
    setZoomLevel(7.5);
  };

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Check WebGL availability
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        alpha: true,
        powerPreference: "high-performance",
      });
    } catch {
      setHasWebGL(false);
      return;
    }

    rendererRef.current = renderer;
    const W = container.clientWidth || 700;
    const H = container.clientHeight || 360;
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(48, W / H, 0.1, 100);
    camera.position.set(0, 0, zoomLevel);
    cameraRef.current = camera;

    // Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.85);
    scene.add(ambientLight);

    const mainLight = new THREE.PointLight(0x38bdf8, 50, 25);
    mainLight.position.set(4, 5, 5);
    scene.add(mainLight);

    const threatColorHex =
      visualTone === "ROSE" ? 0xef4444 : visualTone === "AMBER" ? 0xf59e0b : 0x0284c7;
    const threatLight = new THREE.PointLight(threatColorHex, 45, 20);
    threatLight.position.set(-5, -3, 3);
    scene.add(threatLight);

    const rootGroup = new THREE.Group();
    scene.add(rootGroup);

    // Interactive Mesh Registry for Raycasting
    const interactiveMeshes: THREE.Mesh[] = [];

    // Helper: Create Glowing Node
    const createNodeMesh = (
      data: NodeData,
      pos: THREE.Vector3,
      size: number,
      wireRadius?: number
    ): THREE.Mesh => {
      const geo = new THREE.SphereGeometry(size, 24, 24);
      const mat = new THREE.MeshStandardMaterial({
        color: data.color,
        emissive: data.color,
        emissiveIntensity: 0.9,
        roughness: 0.2,
        metalness: 0.8,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      mesh.userData = { nodeData: data };
      rootGroup.add(mesh);
      interactiveMeshes.push(mesh);

      // Outer Wireframe Cage if specified
      if (wireRadius) {
        const cageGeo = new THREE.IcosahedronGeometry(wireRadius, 1);
        const cageMat = new THREE.MeshBasicMaterial({
          color: data.color,
          wireframe: true,
          transparent: true,
          opacity: 0.35,
        });
        const cage = new THREE.Mesh(cageGeo, cageMat);
        cage.position.copy(pos);
        rootGroup.add(cage);
        // store cage reference for rotation
        (mesh as any).cage = cage;
      }
      return mesh;
    };

    // 1. Central Core Node
    const coreMesh = createNodeMesh(NODES_METADATA.core, new THREE.Vector3(0, 0, 0), 0.42, 1.4);

    // 2. 5 Agent Orbit Nodes
    const agentKeys = ["agent1", "agent2", "agent3", "agent4", "agent5"];
    const agentMeshes: THREE.Mesh[] = [];
    const nodeCount = 5;
    const orbitRadius = 2.7;

    for (let i = 0; i < nodeCount; i++) {
      const angle = (i / nodeCount) * Math.PI * 2;
      const nx = Math.cos(angle) * orbitRadius;
      const ny = Math.sin(angle * 0.7) * 1.0;
      const nz = Math.sin(angle) * orbitRadius;
      const pos = new THREE.Vector3(nx, ny, nz);

      const aMesh = createNodeMesh(NODES_METADATA[agentKeys[i]], pos, 0.22, 0.45);
      agentMeshes.push(aMesh);

      // Connecting geodesic line to Core
      const curve = new THREE.CatmullRomCurve3([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(nx * 0.5, ny * 0.5 + 0.3, nz * 0.5),
        pos,
      ]);
      const tubeGeo = new THREE.TubeGeometry(curve, 20, 0.015, 6, false);
      const tubeMat = new THREE.MeshBasicMaterial({
        color: NODES_METADATA[agentKeys[i]].color,
        transparent: true,
        opacity: 0.38,
      });
      const tube = new THREE.Mesh(tubeGeo, tubeMat);
      rootGroup.add(tube);
    }

    // 3. Ingress Node (Client Network)
    createNodeMesh(
      NODES_METADATA.ingress,
      new THREE.Vector3(-4.2, 1.2, -1.0),
      0.3,
      0.6
    );

    // Ingress to Core Connection
    const ingressCurve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(-4.2, 1.2, -1.0),
      new THREE.Vector3(-2.1, 1.0, 0.5),
      new THREE.Vector3(0, 0, 0),
    ]);
    const ingressTubeGeo = new THREE.TubeGeometry(ingressCurve, 25, 0.02, 6, false);
    const ingressTubeMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.45,
    });
    rootGroup.add(new THREE.Mesh(ingressTubeGeo, ingressTubeMat));

    // 4. Target Node (Protected Datacenter)
    createNodeMesh(
      NODES_METADATA.target,
      new THREE.Vector3(4.2, -1.0, -1.0),
      0.3,
      0.6
    );

    // Core to Target Connection
    const targetCurve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(0, 0, 0),
      new THREE.Vector3(2.1, -0.6, 0.4),
      new THREE.Vector3(4.2, -1.0, -1.0),
    ]);
    const targetTubeGeo = new THREE.TubeGeometry(targetCurve, 25, 0.02, 6, false);
    const targetTubeMat = new THREE.MeshBasicMaterial({
      color: 0x10b981,
      transparent: true,
      opacity: 0.45,
    });
    rootGroup.add(new THREE.Mesh(targetTubeGeo, targetTubeMat));

    // No synthetic flow packets, random particles, or live-traffic animation are rendered.

    // Mouse Interaction: Pointer Tilt and Raycasting
    const pointer = new THREE.Vector2();
    const raycaster = new THREE.Raycaster();
    let isDragging = false;
    let prevMousePos = { x: 0, y: 0 };

    const onPointerMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);

      if (isDragging) {
        const dx = e.clientX - prevMousePos.x;
        const dy = e.clientY - prevMousePos.y;
        rootGroup.rotation.y += dx * 0.006;
        rootGroup.rotation.x += dy * 0.006;
        prevMousePos = { x: e.clientX, y: e.clientY };
      }

      // Raycast hover check
      raycaster.setFromCamera(pointer, camera);
      const intersects = raycaster.intersectObjects(interactiveMeshes);
      if (intersects.length > 0) {
        container.style.cursor = "pointer";
        const node = intersects[0].object.userData?.nodeData as NodeData | undefined;
        if (node) setHoveredNode(node);
      } else {
        container.style.cursor = isDragging ? "grabbing" : "grab";
        setHoveredNode(null);
      }
    };

    const onPointerDown = (e: MouseEvent) => {
      isDragging = true;
      prevMousePos = { x: e.clientX, y: e.clientY };
    };

    const onPointerUp = () => {
      isDragging = false;
    };

    const onPointerClick = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const clickPointer = new THREE.Vector2(
        ((e.clientX - rect.left) / rect.width) * 2 - 1,
        -(((e.clientY - rect.top) / rect.height) * 2 - 1)
      );
      raycaster.setFromCamera(clickPointer, camera);
      const intersects = raycaster.intersectObjects(interactiveMeshes);
      if (intersects.length > 0) {
        const node = intersects[0].object.userData?.nodeData as NodeData | undefined;
        if (node) setSelectedNode(node);
      }
    };

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      handleZoom(e.deltaY * 0.005);
    };

    container.addEventListener("mousemove", onPointerMove);
    container.addEventListener("mousedown", onPointerDown);
    window.addEventListener("mouseup", onPointerUp);
    container.addEventListener("click", onPointerClick);
    container.addEventListener("wheel", onWheel, { passive: false });

    // Resize
    const onResize = () => {
      const nW = container.clientWidth;
      const nH = container.clientHeight;
      if (nW && nH) {
        camera.aspect = nW / nH;
        camera.updateProjectionMatrix();
        renderer.setSize(nW, nH);
      }
    };
    window.addEventListener("resize", onResize);

    // Animation Loop
    let animId = 0;
    const clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      if (prefersReduced) {
        renderer.render(scene, camera);
        return;
      }
      const delta = clock.getDelta();
      const elapsed = clock.getElapsedTime();

      // Rotate Cages
      interactiveMeshes.forEach((mesh: any) => {
        if (mesh.cage) {
          mesh.cage.rotation.y += delta * 0.3;
          mesh.cage.rotation.x += delta * 0.15;
        }
      });

      // Ambient system rotation
      if (!isDragging) {
        rootGroup.rotation.y += delta * 0.06;
      }

      // Subtle pulse on Core
      const coreScale = 1.0 + Math.sin(elapsed * 2.5) * 0.04;
      coreMesh.scale.set(coreScale, coreScale, coreScale);

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", onResize);
      container.removeEventListener("mousemove", onPointerMove);
      container.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("mouseup", onPointerUp);
      container.removeEventListener("click", onPointerClick);
      container.removeEventListener("wheel", onWheel);
      if (renderer.domElement && renderer.domElement.parentNode) {
        renderer.domElement.parentNode.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [visualTone]);

  // 2D Fallback for environments without WebGL
  if (!hasWebGL) {
    return (
      <div
        style={{
          width: "100%",
          minHeight: 280,
          background: "radial-gradient(circle at center, #0f172a 0%, #030712 100%)",
          borderRadius: 8,
          padding: 16,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--muted)",
          border: "1px solid var(--line)",
        }}
      >
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
          <Shield size={24} color="#38bdf8" />
          <b style={{ color: "#fff", fontSize: 14 }}>CyberSentinel 2D Topological Fallback Active</b>
        </div>
        <p style={{ fontSize: 12, maxWidth: 500, textAlign: "center", margin: "0 0 16px 0" }}>
          WebGL acceleration is disabled or software-rendered. Displaying 2D deterministic agent connectivity diagram.
        </p>
        <svg width="100%" height="160" viewBox="0 0 700 160" style={{ maxWidth: 640 }}>
          <defs>
            <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="50%" stopColor="#a855f7" />
              <stop offset="100%" stopColor="#10b981" />
            </linearGradient>
          </defs>
          <line x1="50" y1="80" x2="650" y2="80" stroke={`url(#${gradientId})`} strokeWidth="3" strokeDasharray="6,4" />
          <circle cx="70" cy="80" r="24" fill="#0369a1" stroke="#38bdf8" strokeWidth="2" />
          <text x="70" y="84" fill="#fff" fontSize="10" textAnchor="middle">Ingress</text>
          <circle cx="210" cy="80" r="26" fill="#1e1b4b" stroke="#a855f7" strokeWidth="2" />
          <text x="210" y="78" fill="#fff" fontSize="9" textAnchor="middle">A1 Classifier</text>
          <text x="210" y="90" fill="#a855f7" fontSize="8" textAnchor="middle">A2 Anomaly</text>
          <circle cx="350" cy="80" r="30" fill="#064e3b" stroke="#10b981" strokeWidth="2" />
          <text x="350" y="84" fill="#fff" fontSize="10" textAnchor="middle">A3 Fusion</text>
          <circle cx="490" cy="80" r="26" fill="#451a03" stroke="#f59e0b" strokeWidth="2" />
          <text x="490" y="84" fill="#fff" fontSize="9" textAnchor="middle">A4 Temporal</text>
          <circle cx="630" cy="80" r="26" fill="#881337" stroke="#f43f5e" strokeWidth="2" />
          <text x="630" y="84" fill="#fff" fontSize="9" textAnchor="middle">A5 Defense</text>
        </svg>
      </div>
    );
  }

  return (
    <div style={{ position: "relative", width: "100%", height: "100%", minHeight: 320 }}>
      {/* 3D WebGL Canvas Mount Container */}
      <div
        ref={mountRef}
        style={{
          width: "100%",
          height: 320,
          background: "radial-gradient(circle at center, #0b1329 0%, #030712 100%)",
          borderRadius: 8,
          overflow: "hidden",
          cursor: "grab",
        }}
      />

      {/* Floating HUD Camera Toolbar */}
      <div
        style={{
          position: "absolute",
          top: 12,
          right: 12,
          display: "flex",
          gap: 6,
          background: "rgba(15, 23, 42, 0.85)",
          backdropFilter: "blur(8px)",
          border: "1px solid rgba(56, 189, 248, 0.25)",
          borderRadius: 6,
          padding: "4px 8px",
          zIndex: 10,
        }}
      >
        <button
          onClick={() => handleZoom(-1.0)}
          title="Zoom In"
          style={{
            background: "transparent",
            border: "none",
            color: "#94a3b8",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
          }}
        >
          <ZoomIn size={15} />
        </button>
        <button
          onClick={() => handleZoom(1.0)}
          title="Zoom Out"
          style={{
            background: "transparent",
            border: "none",
            color: "#94a3b8",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
          }}
        >
          <ZoomOut size={15} />
        </button>
        <button
          onClick={handleResetCamera}
          title="Reset Camera Angle"
          style={{
            background: "transparent",
            border: "none",
            color: "#94a3b8",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
          }}
        >
          <RotateCcw size={15} />
        </button>
      </div>

      {/* Hover Tooltip Overlay */}
      {hoveredNode && !selectedNode && (
        <div
          style={{
            position: "absolute",
            bottom: 14,
            left: 14,
            background: "rgba(3, 7, 18, 0.92)",
            border: `1px solid ${hoveredNode.color ? `#${hoveredNode.color.toString(16).padStart(6, "0")}` : "#38bdf8"}`,
            borderRadius: 6,
            padding: "8px 12px",
            zIndex: 15,
            pointerEvents: "none",
            maxWidth: 320,
            boxShadow: "0 4px 20px rgba(0, 0, 0, 0.6)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <b style={{ color: "#fff", fontSize: 12 }}>{hoveredNode.name}</b>
            <span
              style={{
                fontSize: 9,
                fontWeight: 600,
                padding: "2px 6px",
                borderRadius: 4,
                background: "rgba(56, 189, 248, 0.2)",
                color: "#38bdf8",
              }}
            >
              {hoveredNode.status}
            </span>
          </div>
          <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>{hoveredNode.role}</div>
          <div style={{ fontSize: 10, color: "#38bdf8", marginTop: 4 }}>
            Latency: <b>{hoveredNode.latency}</b> · {hoveredNode.flows}
          </div>
        </div>
      )}

      {/* Selected Node Deep-Inspection Drawer */}
      {selectedNode && (
        <div
          style={{
            position: "absolute",
            top: 12,
            left: 12,
            bottom: 12,
            width: 320,
            background: "rgba(10, 16, 31, 0.96)",
            backdropFilter: "blur(12px)",
            border: `1px solid #${selectedNode.color.toString(16).padStart(6, "0")}`,
            borderRadius: 8,
            padding: 14,
            zIndex: 20,
            overflowY: "auto",
            boxShadow: "0 8px 32px rgba(0, 0, 0, 0.8)",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 10, textTransform: "uppercase", color: `#${selectedNode.color.toString(16).padStart(6, "0")}`, fontWeight: 700 }}>
                {selectedNode.category} COMPONENT
              </div>
              <h4 style={{ margin: "2px 0 0 0", color: "#fff", fontSize: 14 }}>{selectedNode.name}</h4>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              style={{
                background: "transparent",
                border: "none",
                color: "var(--muted)",
                cursor: "pointer",
                padding: 4,
              }}
            >
              <X size={16} />
            </button>
          </div>

          <p style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.4, margin: "0 0 12px 0" }}>
            {selectedNode.description}
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 12 }}>
            <div style={{ background: "rgba(255,255,255,0.04)", padding: 8, borderRadius: 4 }}>
              <div style={{ fontSize: 10, color: "var(--muted)" }}>LATENCY</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "#38bdf8" }}>{selectedNode.latency}</div>
            </div>
            <div style={{ background: "rgba(255,255,255,0.04)", padding: 8, borderRadius: 4 }}>
              <div style={{ fontSize: 10, color: "var(--muted)" }}>THROUGHPUT</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "#10b981" }}>{selectedNode.flows}</div>
            </div>
          </div>

          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#e2e8f0", marginBottom: 4 }}>TYPED CONTRACT:</div>
            <div
              style={{
                fontSize: 11,
                fontFamily: "monospace",
                background: "rgba(0,0,0,0.5)",
                padding: 8,
                borderRadius: 4,
                color: "#94a3b8",
                border: "1px solid rgba(255,255,255,0.08)",
              }}
            >
              {selectedNode.contract}
            </div>
          </div>

          <div style={{ marginTop: "auto", borderTop: "1px solid var(--line)", paddingTop: 10, fontSize: 11, color: "var(--muted)" }}>
            Click outside or tap <RotateCcw size={12} style={{ display: "inline", verticalAlign: "middle" }} /> to reset camera.
          </div>
        </div>
      )}
    </div>
  );
}
