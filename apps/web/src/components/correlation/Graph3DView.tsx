'use client';

import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';

import {
  CLUSTER_COLORS,
  clusterGraph,
  describeCluster,
  type ClusterSummary,
} from '@/lib/graphCommunities';
import { layoutGraph3D } from '@/lib/graph3dLayout';
import { graphPalette, useGraphTheme, type GraphPalette } from '@/lib/graphTheme';
import type { CandidateGraph, CandidateGraphNode } from '@/hooks/useCaseCandidates';

/**
 * WebGL view of the correlation graph, built for demos and very large
 * campaigns. Loaded lazily (see `CandidateGraphView`) so nobody pays the three.js
 * bundle unless they ask for 3D.
 *
 * It is not a second layout engine: the same community partition that separates
 * the 2D bubbles is reused, and each community becomes a small sphere of nodes
 * placed on a larger sphere. No physics loop — the scene is deterministic and
 * opens instantly, and orbiting is what reveals structure in depth.
 */

/** Commands the 2D toolbar can forward while the orbit view is on screen. */
export interface Graph3DHandle {
  /** Dolly toward (factor > 1) or away from (factor < 1) the orbit target. */
  zoomBy: (factor: number) => void;
  resetView: () => void;
  /** Frame the whole scene (the toolbar's "Fit"). */
  fit: () => void;
  /** Put the orbit target on one node, keeping the current viewing angle. */
  focusNode: (id: string) => void;
  /** Frame one bubble: orbit target on its centre, distance to fit its shell. */
  focusCluster: (community: string) => void;
  /** PNG data URL of the current scene, as the camera sees it. */
  snapshot: () => string | null;
}

interface Graph3DViewProps {
  graph: CandidateGraph;
  hiddenIds: ReadonlySet<string>;
  removedIds: ReadonlySet<string>;
  /** Kind → colour, from the same KIND_META the 2D canvas uses. */
  colorFor: (kind: string) => string;
  /**
   * Kind → the outline the 2D canvas draws for it (`points` in the same −1..1
   * box, or `round` for the ellipse kinds). Passed in rather than duplicated so
   * the two projections cannot drift apart.
   */
  shapeFor?: (kind: string) => { points?: number[]; round?: boolean; height: number };
  onSelectNode?: (node: CandidateGraphNode | null) => void;
  /**
   * Edge tapped in the scene. It carries the same id the 2D canvas emits, so the
   * panel below the canvas and the highlight describe the same object.
   */
  onSelectEdge?: (edgeId: string | null) => void;
  /** Edge the inspector is showing; drawn bright on top of the faint links. */
  selectedEdgeId?: string | null;
  onClose: () => void;
  /**
   * The exact nodes / edges the 2D canvas is drawing. The graph passed in is the
   * whole candidate so bubbles keep their 2D names, but 3D must respect the
   * SHOW filters, the per-node neighbour budget (NBRS) and the pair-link toggle
   * — otherwise those controls silently do nothing after switching views.
   */
  drawnNodeIds?: ReadonlySet<string>;
  drawnEdgeIds?: ReadonlySet<string>;
  /** Compact spacing lays the cluster shells closer together. */
  compact?: boolean;
  /** Bubble keys the analyst collapsed — shared with the 2D canvas. */
  collapsedClusters?: ReadonlySet<string>;
  /** Collapse / expand one bubble; the same handler the 2D canvas uses. */
  onToggleCluster?: (key: string) => void;
  /** Members of the bubble the analyst focused, ringed like `activeId`. */
  activeClusterIds?: ReadonlySet<string>;
  /** Reports the bubbles for the entity panel's Clusters tab. */
  onClusters?: (clusters: ClusterSummary[]) => void;
  /** Row the analyst clicked in the entity list; drawn with a teal halo. */
  activeId?: string | null;
  /** Names for nodes and links. On by default, as they are on the 2D canvas. */
  showLabels?: boolean;
  onToggleLabels?: () => void;
  /**
   * Receives the camera commands for as long as the scene is mounted. The view
   * is loaded through `next/dynamic`, which does not forward refs, so the
   * toolbar's zoom buttons reach the camera through this callback instead.
   */
  onApi?: (api: Graph3DHandle | null) => void;
  /**
   * Undo Focus, expansion, Hide and Remove in one click. Shared with the 2D
   * canvas, so the control has to exist here too — otherwise an analyst who
   * switched to 3D could not get back to the whole campaign without leaving it.
   */
  onClearView?: () => void;
}

const EMPTY_CLUSTERS: ReadonlySet<string> = new Set();

interface Hovered3D {
  x: number;
  y: number;
  label: string;
  kind: string;
}

/**
 * One node kind's 2D silhouette, rasterised into a point sprite.
 *
 * A PointsMaterial has exactly one sprite for the whole cloud, so a kind gets a
 * cloud of its own — that is what lets the orbit view inherit the shapes the 2D
 * canvas draws (house, person, diamond, tag, octagon) instead of painting every
 * node as the same square of colour. The sprite is white so the per-vertex
 * colour still supplies the kind's colour.
 */
function makeShapeTexture(shape: { points?: number[]; round?: boolean }): THREE.Texture {
  const size = 64;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.fillStyle = '#ffffff';
    ctx.beginPath();
    if (shape.points && shape.points.length >= 6) {
      // The same −1..1 outlines the canvas paints, padded so the edges do not
      // touch the sprite border and get clipped.
      const scale = size * 0.44;
      for (let index = 0; index < shape.points.length; index += 2) {
        const x = size / 2 + shape.points[index] * scale;
        const y = size / 2 + shape.points[index + 1] * scale;
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
    } else if (shape.round) {
      ctx.arc(size / 2, size / 2, size * 0.42, 0, Math.PI * 2);
    } else {
      ctx.rect(size * 0.16, size * 0.16, size * 0.68, size * 0.68);
    }
    ctx.fill();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
}

/** A thin turquoise ring, drawn once and reused for the selected node. */
function makeRingTexture(color: string): THREE.Texture {
  const size = 128;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 9;
    ctx.beginPath();
    ctx.arc(size / 2, size / 2, size / 2 - 9, 0, Math.PI * 2);
    ctx.stroke();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
}

/** Same cut the 2D cluster pill applies to its title. */
function shortLabel(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

/** Trim a label to the width the canvas texture can show, without a mid-glyph cut. */
function fitText(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string {
  if (ctx.measureText(text).width <= maxWidth) return text;
  let cut = text;
  while (cut.length > 1 && ctx.measureText(`${cut}…`).width > maxWidth) {
    cut = cut.slice(0, -1);
  }
  return `${cut}…`;
}

/**
 * One floating name plate per bubble. A `Sprite` always faces the camera, so the
 * label stays readable while the scene orbits — no per-frame billboard work.
 */
function makeLabelSprite(
  title: string,
  subtitle: string,
  color: string,
  worldHeight: number,
  palette: GraphPalette
): THREE.Sprite {
  const canvas = document.createElement('canvas');
  const width = 480;
  const height = 132;
  const ratio = 2;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.scale(ratio, ratio);
    const radius = 18;
    ctx.beginPath();
    ctx.moveTo(radius, 0);
    ctx.arcTo(width, 0, width, height, radius);
    ctx.arcTo(width, height, 0, height, radius);
    ctx.arcTo(0, height, 0, 0, radius);
    ctx.arcTo(0, 0, width, 0, radius);
    ctx.closePath();
    ctx.fillStyle = palette.plateFill;
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.lineWidth = 3;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(30, 44, 9, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();

    ctx.font = '600 34px ui-sans-serif, system-ui, -apple-system, sans-serif';
    ctx.fillStyle = palette.ink;
    ctx.textBaseline = 'middle';
    ctx.fillText(fitText(ctx, title, width - 64), 52, 44);

    ctx.font = '24px ui-sans-serif, system-ui, -apple-system, sans-serif';
    ctx.fillStyle = palette.inkMuted;
    ctx.fillText(fitText(ctx, subtitle, width - 44), 22, 96);
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  const sprite = new THREE.Sprite(
    new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false })
  );
  sprite.scale.set((worldHeight * width) / height, worldHeight, 1);
  return sprite;
}

/**
 * A plain name, no plate.
 *
 * Leaf labels copied the bubble plate's rounded rectangle, so with names on the
 * canvas was a wall of boxes and a leaf read like one more cluster. A bubble is
 * the only thing that gets a plate; everything else is text with a dark halo so
 * it stays readable over nodes and links.
 */
function makeTextSprite(
  text: string,
  worldHeight: number,
  palette: GraphPalette
): THREE.Sprite {
  const width = 384;
  const height = 96;
  const ratio = 2;
  const canvas = document.createElement('canvas');
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.scale(ratio, ratio);
    ctx.font = '600 30px ui-sans-serif, system-ui, -apple-system, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const fitted = fitText(ctx, text, width - 20);
    ctx.lineWidth = 6;
    ctx.lineJoin = 'round';
    ctx.strokeStyle = palette.halo;
    ctx.strokeText(fitted, width / 2, height / 2);
    ctx.fillStyle = palette.ink;
    ctx.fillText(fitted, width / 2, height / 2);
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  const sprite = new THREE.Sprite(
    new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false })
  );
  sprite.scale.set((worldHeight * width) / height, worldHeight, 1);
  return sprite;
}

export function Graph3DView({
  graph,
  hiddenIds,
  removedIds,
  colorFor,
  shapeFor,
  onSelectNode,
  onSelectEdge,
  selectedEdgeId = null,
  onClose,
  onApi,
  drawnNodeIds,
  drawnEdgeIds,
  compact = false,
  collapsedClusters = EMPTY_CLUSTERS,
  activeClusterIds,
  onToggleCluster,
  onClusters,
  activeId = null,
  showLabels = true,
  onToggleLabels,
  onClearView,
}: Graph3DViewProps) {
  // three.js paints outside the stylesheet: the scene, the name plates and the
  // selection rings take their colours from the palette, not from a class.
  const palette = graphPalette(useGraphTheme());
  const containerRef = useRef<HTMLDivElement>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  /** Left-drag pans instead of orbiting. Also available as Shift+drag. */
  const [panMode, setPanMode] = useState(false);
  const panModeRef = useRef(false);
  const resetViewRef = useRef<(() => void) | null>(null);
  const zoomByRef = useRef<((factor: number) => void) | null>(null);
  const focusNodeRef = useRef<((id: string) => void) | null>(null);
  const focusClusterRef = useRef<((community: string) => void) | null>(null);
  // The selected node's halo lives outside the scene rebuild so clicking a row
  // does not reset the camera the click just moved.
  const activeIdRef = useRef<string | null>(activeId);
  const highlightRef = useRef<{
    mesh: THREE.Sprite;
    positions: Map<string, { x: number; y: number; z: number }>;
    radius: number;
  } | null>(null);
  // Everything a label needs, captured during the scene build so toggling names
  // does not rebuild the scene (and reset the camera).
  const labelDataRef = useRef<{
    group: THREE.Group;
    height: number;
    positions: Map<string, { x: number; y: number; z: number }>;
    nodes: { id: string; text: string; color: string; degree: number }[];
    links: { x: number; y: number; z: number; text: string; weight: number }[];
  } | null>(null);
  const [labelEpoch, setLabelEpoch] = useState(0);
  // Rings for the members of a focused bubble. Lives outside the scene build
  // for the same reason the node halo does: changing the focus must not reset
  // the camera the focus just moved.
  const clusterRingsRef = useRef<{
    group: THREE.Group;
    texture: THREE.Texture;
    radius: number;
    positions: Map<string, { x: number; y: number; z: number }>;
  } | null>(null);
  // Kept in a ref: the scene is rebuilt only when the graph or its visibility
  // changes, and a new toggle identity should not restart the camera.
  const toggleRef = useRef(onToggleCluster);
  // Collapsing a bubble rebuilds the scene (its nodes leave the clouds), and a
  // rebuild used to drop the camera back to the fitted view. Keeping the orbit
  // across rebuilds of the same graph is what makes collapse feel like a
  // toggle instead of a page change.
  const cameraStateRef = useRef<{
    graph: CandidateGraph;
    position: THREE.Vector3;
    target: THREE.Vector3;
  } | null>(null);
  const selectRef = useRef(onSelectNode);
  const edgeSelectRef = useRef(onSelectEdge);
  const selectedEdgeRef = useRef<string | null>(selectedEdgeId ?? null);
  const [autoRotate, setAutoRotate] = useState(true);
  // The scene is rebuilt on filter/collapse changes and used to hard-wire
  // rotation back on; the ref carries the current answer into that build.
  const autoRotateRef = useRef(true);
  const [hovered, setHovered] = useState<Hovered3D | null>(null);
  // Kept in a ref: the scene rebuild should not re-register a new callback as
  // a reason to run again.
  const clustersRef = useRef(onClusters);

  useEffect(() => {
    selectRef.current = onSelectNode;
  }, [onSelectNode]);

  useEffect(() => {
    edgeSelectRef.current = onSelectEdge;
  }, [onSelectEdge]);

  useEffect(() => {
    selectedEdgeRef.current = selectedEdgeId ?? null;
  }, [selectedEdgeId]);

  useEffect(() => {
    toggleRef.current = onToggleCluster;
  }, [onToggleCluster]);

  useEffect(() => {
    clustersRef.current = onClusters;
  }, [onClusters]);

  // Build / clear the name layer. Rebuilt only when the toggle flips or the
  // scene is rebuilt (`labelEpoch`), never as part of the camera-owning effect.
  useEffect(() => {
    const data = labelDataRef.current;
    if (!data) return;
    const group = data.group;
    const clear = () => {
      for (const child of [...group.children]) {
        group.remove(child);
        const material = (child as THREE.Sprite).material as THREE.SpriteMaterial;
        material.map?.dispose();
        material.dispose();
      }
    };
    clear();
    if (!showLabels) return;

    // One texture per name: a 900-node campaign cannot afford all of them, so
    // the busiest leaves and the strongest links are the ones that get labelled.
    const NODE_CAP = 150;
    const LINK_CAP = 120;
    const busiest = [...data.nodes]
      .sort((a, b) => b.degree - a.degree || a.id.localeCompare(b.id))
      .slice(0, NODE_CAP);
    for (const node of busiest) {
      const point = data.positions.get(node.id);
      if (!point) continue;
      const sprite = makeTextSprite(node.text, data.height, palette);
      sprite.position.set(point.x, point.y + data.height * 0.9, point.z);
      group.add(sprite);
    }
    const strongest = [...data.links].sort((a, b) => b.weight - a.weight).slice(0, LINK_CAP);
    for (const link of strongest) {
      const sprite = makeTextSprite(link.text, data.height * 0.7, palette);
      sprite.position.set(link.x, link.y, link.z);
      group.add(sprite);
    }
  }, [showLabels, labelEpoch, graph, palette]);

  // Follow the entity list selection without rebuilding the scene, so the
  // camera the row click just moved stays where it is.
  useEffect(() => {
    activeIdRef.current = activeId;
    const entry = highlightRef.current;
    if (!entry) return;
    const point = activeId ? entry.positions.get(activeId) : undefined;
    if (!point) {
      entry.mesh.visible = false;
      return;
    }
    entry.mesh.position.set(point.x, point.y, point.z);
    entry.mesh.scale.setScalar(entry.radius);
    entry.mesh.visible = true;
  }, [activeId]);

  // The 3D half of focusing a bubble: one ring per member, so the cluster the
  // analyst picked reads the same here as the bordered nodes read in 2D.
  // `labelEpoch` marks a finished scene build — the rings need its positions.
  useEffect(() => {
    const data = clusterRingsRef.current;
    if (!data) return;
    for (const child of [...data.group.children]) {
      data.group.remove(child);
      const material = (child as THREE.Sprite).material as THREE.SpriteMaterial;
      material.dispose();
    }
    if (!activeClusterIds || activeClusterIds.size === 0) return;
    for (const id of activeClusterIds) {
      const point = data.positions.get(id);
      if (!point) continue;
      const ring = new THREE.Sprite(
        new THREE.SpriteMaterial({
          map: data.texture,
          color: palette.selectionBorder,
          transparent: true,
          opacity: 0.8,
          depthTest: false,
          depthWrite: false,
        })
      );
      ring.position.set(point.x, point.y, point.z);
      ring.scale.setScalar(data.radius);
      data.group.add(ring);
    }
  }, [activeClusterIds, labelEpoch, palette]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const nodes = graph.nodes.filter(
      (node) =>
        !hiddenIds.has(node.id) &&
        !removedIds.has(node.id) &&
        (!drawnNodeIds || drawnNodeIds.has(node.id))
    );
    if (nodes.length === 0) return;
    const visible = new Set(nodes.map((node) => node.id));
    const links = graph.edges.filter(
      (edge) =>
        visible.has(edge.source) &&
        visible.has(edge.target) &&
        (!drawnEdgeIds || drawnEdgeIds.has(edge.id))
    );

    // Partition over *every* node, not just the visible ones: a collapsed
    // bubble must keep its name, colour and place instead of disappearing. The
    // 2D canvas builds its partition the same way (all nodes, all structural
    // edges), which is what makes the two views name a bubble identically.
    const allIds = graph.nodes.map((node) => node.id);
    const structure = graph.edges
      .filter((edge) => edge.kind !== 'CORRELATION')
      .map((edge) => ({ source: edge.source, target: edge.target }));
    const membership = clusterGraph(allIds, structure);
    const positions = layoutGraph3D(allIds, membership, { spread: compact ? 0.72 : 1 });

    // Under the same 40-node cut the 2D canvas uses, there are no bubbles — so
    // 3D shows no names either rather than inventing clusters of its own.
    const showClusters = allIds.length >= 40;
    const communities = showClusters
      ? [...new Set(membership.values())].sort((a, b) => a.localeCompare(b))
      : [];
    const clusterColor = new Map(
      communities.map((community, index) => [
        community,
        CLUSTER_COLORS[index % CLUSTER_COLORS.length],
      ])
    );

    // `preserveDrawingBuffer` keeps the frame readable after the draw call, so
    // the toolbar's PNG export can copy exactly what the camera is showing.
    const renderer = new THREE.WebGLRenderer({ antialias: true, preserveDrawingBuffer: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(container.clientWidth || 800, container.clientHeight || 600);
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(palette.surface);
    const camera = new THREE.PerspectiveCamera(
      55,
      (container.clientWidth || 800) / (container.clientHeight || 600),
      1,
      20000
    );

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.autoRotate = autoRotateRef.current;
    controls.autoRotateSpeed = 0.6;
    // Looking at another part of the scene was a right-drag away, which is
    // either impossible (trackpad) or undiscoverable, and left-drag is always
    // orbit. Shift turns the same drag into a pan, and the toolbar's `Pan`
    // button does it without a keyboard.
    controls.mouseButtons = {
      LEFT: THREE.MOUSE.ROTATE,
      MIDDLE: THREE.MOUSE.DOLLY,
      RIGHT: THREE.MOUSE.PAN,
    };
    // Zoom towards what the pointer is over instead of the orbit centre, so a
    // far cluster can be entered without panning to it first.
    controls.zoomToCursor = true;
    controls.zoomSpeed = 1.1;
    controlsRef.current = controls;
    const onPointerDownCapture = (event: PointerEvent) => {
      controls.mouseButtons.LEFT =
        panModeRef.current || event.shiftKey ? THREE.MOUSE.PAN : THREE.MOUSE.ROTATE;
    };
    renderer.domElement.addEventListener('pointerdown', onPointerDownCapture, true);

    // One frame around every node sets the camera distance and the orbit target.
    const bounds = new THREE.Box3();
    for (const node of nodes) {
      const position = positions.get(node.id)!;
      bounds.expandByPoint(new THREE.Vector3(position.x, position.y, position.z));
    }
    const sphere = bounds.getBoundingSphere(new THREE.Sphere());
    const eye = sphere.radius * 2.1;
    const remembered = cameraStateRef.current;
    if (remembered && remembered.graph === graph) {
      camera.position.copy(remembered.position);
      controls.target.copy(remembered.target);
    } else {
      camera.position.set(eye * 0.45, eye * 0.35, eye);
      controls.target.copy(sphere.center);
    }
    controls.update();
    const resetView = () => {
      camera.position.set(eye * 0.45, eye * 0.35, eye);
      controls.target.copy(sphere.center);
      controls.update();
    };
    resetViewRef.current = resetView;

    // Dolly along the camera→target axis. Scroll wheel zoom only works while the
    // pointer is over the canvas, so the toolbar's − / + buttons need the same
    // move as a command; keeping the target fixed is what makes it feel like the
    // canvas zoom rather than a pan.
    // Close enough to read one small bubble: 12% of the whole scene's radius
    // stopped the camera in open space, so a 9-node cluster could never fill the
    // frame.
    controls.minDistance = Math.max(0.8, sphere.radius * 0.004);
    controls.maxDistance = eye * 4;
    const zoomBy = (factor: number) => {
      const offset = camera.position.clone().sub(controls.target);
      const distance = offset.length();
      if (distance === 0) return;
      const next = Math.min(
        controls.maxDistance,
        Math.max(controls.minDistance, distance / factor)
      );
      camera.position.copy(controls.target).add(offset.setLength(next));
      controls.update();
    };
    zoomByRef.current = zoomBy;

    // Clicking a row in the entity list used to centre a hidden canvas. Here it
    // moves the orbit target to the node, keeping the angle the analyst chose.
    const focusNode = (id: string) => {
      const position = positions.get(id);
      if (!position) return;
      const point = new THREE.Vector3(position.x, position.y, position.z);
      const direction = camera.position.clone().sub(controls.target);
      if (direction.lengthSq() === 0) direction.set(0.45, 0.35, 1);
      direction.normalize();
      const distance = Math.min(
        controls.maxDistance,
        Math.max(controls.minDistance, sphere.radius * 0.55)
      );
      controls.target.copy(point);
      camera.position.copy(point).add(direction.multiplyScalar(distance));
      controls.update();
    };
    focusNodeRef.current = focusNode;
    onApi?.({
      zoomBy,
      resetView,
      fit: resetView,
      focusNode,
      // Declared now, wired once the bubbles exist further down the build.
      focusCluster: (community: string) => focusClusterRef.current?.(community),
      snapshot: () => {
        renderer.render(scene, camera);
        try {
          return renderer.domElement.toDataURL('image/png');
        } catch {
          return null;
        }
      },
    });

    // ── nodes: entities and observations are separate point clouds so the two
    // sizes can differ without a custom shader ────────────────────────────────
    /** One point cloud per node kind: a cloud is the only way a sprite per kind
     * can exist, because PointsMaterial carries a single map. */
    const buildCloud = (kind: string, members: CandidateGraphNode[]) => {
      const coords = new Float32Array(members.length * 3);
      const colors = new Float32Array(members.length * 3);
      members.forEach((node, index) => {
        const position = positions.get(node.id)!;
        coords[index * 3] = position.x;
        coords[index * 3 + 1] = position.y;
        coords[index * 3 + 2] = position.z;
        const color = new THREE.Color(colorFor(node.kind) || '#64748b');
        colors[index * 3] = color.r;
        colors[index * 3 + 1] = color.g;
        colors[index * 3 + 2] = color.b;
      });
      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.BufferAttribute(coords, 3));
      geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
      const meta = shapeFor?.(kind);
      // Observations are the subject of the campaign, so they stay the largest
      // mark; entities follow the 2D sizing table.
      // A silhouette covers less of its sprite box than a square did, so the
      // mark is sized up a notch to keep the same visual weight.
      //
      // The size is expressed against the scene's framing radius instead of in
      // fixed world units. A fixed 9-unit mark is a readable dot on a 19-node
      // campaign and a sub-pixel speck on a 900-node one; tying it to the radius
      // keeps the apparent size the same whatever the layout spreads to, and the
      // floor is what stops a leaf from disappearing when the camera is far out.
      // Observations barely lead the largest entity now: in 2D the hexagon is
      // clearly wider than a house, but a flat point sprite at that ratio read as
      // a blob that swallowed the entities it was supposed to point at.
      const scale = Math.max(1, sphere.radius / 150);
      const size =
        kind === 'observation'
          ? 20 * scale
          : Math.min(24, Math.max(11, (meta?.height ?? 26) * 0.5)) * scale;
      const material = new THREE.PointsMaterial({
        map: makeShapeTexture({ points: meta?.points, round: meta?.round }),
        size,
        // Cut the transparent border out of the depth buffer as well, or every
        // square sprite hides the marks behind it.
        alphaTest: 0.35,
        vertexColors: true,
        sizeAttenuation: true,
        transparent: true,
        opacity: 0.98,
      });
      const cloud = new THREE.Points(geometry, material);
      cloud.userData.ids = members.map((node) => node.id);
      scene.add(cloud);
      return cloud;
    };

    const clouds: THREE.Points[] = [];
    for (const kind of new Set(nodes.map((node) => node.kind))) {
      const members = nodes.filter((node) => node.kind === kind);
      if (members.length > 0) clouds.push(buildCloud(kind, members));
    }

    const kindOf = new Map(nodes.map((node) => [node.id, node.kind]));

    // ── links: coloured by the community the source belongs to, faint enough
    // that the node clouds stay the subject ────────────────────────────────────
    // Picking a link needs the object handle and its id order (two vertices per
    // edge), and the selected edge is drawn again in a bright colour because a
    // 1px line among hundreds cannot be "highlighted" by width.
    let linkLines: THREE.LineSegments | null = null;
    const linkFor = new Map<string, [THREE.Vector3, THREE.Vector3]>();
    if (links.length > 0) {
      const coords = new Float32Array(links.length * 6);
      const colors = new Float32Array(links.length * 6);
      links.forEach((edge, index) => {
        const from = positions.get(edge.source)!;
        const to = positions.get(edge.target)!;
        coords.set([from.x, from.y, from.z, to.x, to.y, to.z], index * 6);
        linkFor.set(edge.id, [
          new THREE.Vector3(from.x, from.y, from.z),
          new THREE.Vector3(to.x, to.y, to.z),
        ]);
        // Colour follows the 2D language: a bubble's community when the scene is
        // big enough to draw bubbles, otherwise the kind of the entity the link
        // ends on (`USES_IP` blue, `INVOLVES_USER` pink, …) with the score teal
        // for an observation↔observation pair. The flat grey fallback was what
        // every link on a campaign below the 40-node bubble cut got, so the whole
        // scene read black-and-white.
        const sourceKind = kindOf.get(edge.source);
        const targetKind = kindOf.get(edge.target);
        const entityKind = sourceKind === 'observation' ? targetKind : sourceKind;
        const color = new THREE.Color(
          clusterColor.get(membership.get(edge.source) ?? '') ??
            (edge.kind === 'CORRELATION'
              ? palette.scoreLine
              : colorFor(String(entityKind ?? '')) || '#64748b')
        );
        colors.set([color.r, color.g, color.b, color.r, color.g, color.b], index * 6);
      });
      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.BufferAttribute(coords, 3));
      geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
      linkLines = new THREE.LineSegments(
        geometry,
        new THREE.LineBasicMaterial({
          vertexColors: true,
          transparent: true,
          opacity: palette.linkOpacity,
        })
      );
      linkLines.userData.ids = links.map((edge) => edge.id);
      scene.add(linkLines);
    }
    // One object serves both link states: the selection is teal, the link under
    // the pointer is a light neutral, so "what I picked" and "what I am touching"
    // never look the same.
    const edgeHighlight = new THREE.LineSegments(
      new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), new THREE.Vector3()]),
      new THREE.LineBasicMaterial({ color: palette.selectionBorder, transparent: true, opacity: 1 })
    );
    edgeHighlight.visible = false;
    edgeHighlight.renderOrder = 2;
    scene.add(edgeHighlight);
    let hoveredEdgeId: string | null = null;

    // ── bubble geometry, names and the legend ────────────────────────────────
    // Each community's centre and extent are needed three times (shell, label,
    // legend), so compute them once from the same positions the spheres use.
    // Degree over the whole graph, exactly as the 2D label pass counts it, so
    // "dominant entity" comes out the same in both views even after a hide.
    const structuralDegree = new Map<string, number>();
    for (const edge of structure) {
      structuralDegree.set(edge.source, (structuralDegree.get(edge.source) ?? 0) + 1);
      structuralDegree.set(edge.target, (structuralDegree.get(edge.target) ?? 0) + 1);
    }

    const bubbles = communities.map((community) => {
      const members = graph.nodes.filter((node) => membership.get(node.id) === community);
      const visibleMembers = members.filter((member) => visible.has(member.id));
      const isCollapsed = collapsedClusters.has(community);
      const centre = new THREE.Vector3();
      for (const member of members) {
        const position = positions.get(member.id)!;
        centre.add(new THREE.Vector3(position.x, position.y, position.z));
      }
      if (members.length > 0) centre.divideScalar(members.length);
      let radius = 0;
      for (const member of members) {
        const position = positions.get(member.id)!;
        radius = Math.max(
          radius,
          centre.distanceTo(new THREE.Vector3(position.x, position.y, position.z))
        );
      }
      const { title, subtitle } = describeCluster(members, structuralDegree);
      return {
        community,
        members,
        visibleMembers,
        isCollapsed,
        centre,
        radius,
        title,
        subtitle,
        color: clusterColor.get(community) ?? '#334155',
      };
    })
      // A bubble the analyst hid node by node is gone; a bubble they collapsed
      // stays on screen as a marker, because it is a deliberate object.
      .filter((bubble) => bubble.isCollapsed || bubble.visibleMembers.length > 0);

    // Frame one bubble the way focusNode frames one node: keep the viewing
    // angle and dolly in until the whole shell fits. Collapsed bubbles are in
    // this list too, so the Clusters tab can still frame one.
    focusClusterRef.current = (community: string) => {
      const bubble = bubbles.find((entry) => entry.community === community);
      if (!bubble) return;
      const direction = camera.position.clone().sub(controls.target);
      if (direction.lengthSq() === 0) direction.set(0.45, 0.35, 1);
      direction.normalize();
      const distance = Math.min(
        controls.maxDistance,
        Math.max(controls.minDistance, Math.max(bubble.radius * 1.9, sphere.radius * 0.05))
      );
      controls.target.copy(bubble.centre);
      camera.position.copy(bubble.centre).add(direction.multiplyScalar(distance));
      controls.update();
    };

    // Labels scale with the whole scene so a 40-node graph and an 800-node one
    // read at the same on-screen size after the camera fit.
    const labelHeight = Math.max(12, Math.min(46, sphere.radius * 0.055));
    const labelTargets: THREE.Sprite[] = [];
    // Bubble name plates get their own layer. They are not part of the Labels
    // switch: leaf names are plain text and a bubble is a plate, so the two
    // read as different things and the plate stays put.
    const clusterLabelGroup = new THREE.Group();
    scene.add(clusterLabelGroup);
    for (const bubble of bubbles) {
      // A faint halo marks the community shell without adding geometry per node.
      if (!bubble.isCollapsed && bubble.members.length >= 4) {
        // A wireframe shell was legible from outside the cluster and unreadable
        // once the camera was inside it: the sphere's own lines crossed every
        // node-to-node edge and could not be told apart from them. A faint
        // back-side shell keeps the bubble's extent (rim + tint) and draws no
        // lines at all, and `depthWrite: false` stops it hiding the links.
        const shell = new THREE.Mesh(
          new THREE.SphereGeometry(bubble.radius * 1.05, 32, 18),
          new THREE.MeshBasicMaterial({
            color: new THREE.Color(bubble.color),
            transparent: true,
            opacity: 0.06,
            depthWrite: false,
            side: THREE.BackSide,
          })
        );
        shell.position.copy(bubble.centre);
        scene.add(shell);
      }

      // A collapsed bubble keeps a small solid core so the campaign's shape is
      // still readable while its nodes are off screen.
      if (bubble.isCollapsed) {
        const core = new THREE.Mesh(
          new THREE.SphereGeometry(Math.max(3, bubble.radius * 0.22), 16, 12),
          new THREE.MeshBasicMaterial({
            color: new THREE.Color(bubble.color),
            transparent: true,
            opacity: 0.32,
          })
        );
        core.position.copy(bubble.centre);
        scene.add(core);
      }

      // The 2D pill truncates its title to 22 characters; using the same cut
      // here keeps the two views naming a bubble the same way.
      const label = makeLabelSprite(
        shortLabel(bubble.title, 22),
        bubble.isCollapsed
          ? `${bubble.members.length} nodes · collapsed`
          : bubble.subtitle,
        bubble.color,
        labelHeight,
        palette
      );
      label.userData.community = bubble.community;
      labelTargets.push(label);
      // Above the bubble, and nudged outward so the name sits on the side the
      // camera sees first rather than inside the sphere of nodes.
      label.position
        .copy(bubble.centre)
        .add(new THREE.Vector3(0, bubble.radius + labelHeight * 0.8, 0));
      clusterLabelGroup.add(label);
    }

    // ── selected node halo ────────────────────────────────────────────────────
    // Moving the camera onto a leaf was not enough to tell which leaf it was in
    // a dense orbit; this is the 3D half of the 2D `entity-active` border. It is
    // a camera-facing ring at the node marker's own scale — a world-space sphere
    // read as a bubble several nodes wide.
    const highlightRadius = 15;
    const highlight = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: makeRingTexture(palette.selectionBorder),
        color: palette.selectionBorder,
        transparent: true,
        opacity: 0.95,
        depthTest: false,
        depthWrite: false,
      })
    );
    highlight.visible = false;
    scene.add(highlight);
    highlightRef.current = { mesh: highlight, positions, radius: highlightRadius };

    // Shared texture: one small ring per member of a focused bubble, drawn on
    // demand by the effect above.
    const clusterRingGroup = new THREE.Group();
    scene.add(clusterRingGroup);
    clusterRingsRef.current = {
      group: clusterRingGroup,
      texture: makeRingTexture(palette.selectionBorder),
      radius: highlightRadius * 0.85,
      positions,
    };
    const paintHighlight = (id: string | null) => {
      const point = id ? positions.get(id) : undefined;
      if (!point) {
        highlight.visible = false;
        return;
      }
      highlight.position.set(point.x, point.y, point.z);
      highlight.scale.setScalar(highlightRadius);
      highlight.visible = true;
    };
    paintHighlight(activeIdRef.current);

    // ── label layer ──────────────────────────────────────────────────────────
    // Names are off by default in 3D (they cost one texture each), so the data
    // they need is captured here and the sprites are built only when asked for.
    const labelGroup = new THREE.Group();
    scene.add(labelGroup);
    const nodeDegree = new Map<string, number>();
    for (const edge of links) {
      nodeDegree.set(edge.source, (nodeDegree.get(edge.source) ?? 0) + 1);
      nodeDegree.set(edge.target, (nodeDegree.get(edge.target) ?? 0) + 1);
    }
    labelDataRef.current = {
      group: labelGroup,
      height: Math.max(10, Math.min(30, sphere.radius * 0.035)),
      positions,
      nodes: nodes.map((node) => ({
        id: node.id,
        text: shortLabel(node.label, 26),
        color: colorFor(node.kind) || '#94a3b8',
        degree: nodeDegree.get(node.id) ?? 0,
      })),
      links: links.map((edge) => {
        const from = positions.get(edge.source)!;
        const to = positions.get(edge.target)!;
        return {
          x: (from.x + to.x) / 2,
          y: (from.y + to.y) / 2,
          z: (from.z + to.z) / 2,
          text: shortLabel(edge.role ?? String(edge.weight ?? ''), 18),
          weight: Number(edge.weight ?? 1),
        };
      }),
    };
    setLabelEpoch((value) => value + 1);

    clustersRef.current?.(
      bubbles
        .map((bubble) => ({
          community: bubble.community,
          title: bubble.title,
          subtitle: bubble.subtitle,
          color: bubble.color,
          size: bubble.members.length,
          collapsed: bubble.isCollapsed,
        }))
        .sort((a, b) => b.size - a.size || a.title.localeCompare(b.title))
    );

    // ── picking ───────────────────────────────────────────────────────────────
    const raycaster = new THREE.Raycaster();
    raycaster.params.Points!.threshold = 7;
    const pointer = new THREE.Vector2();
    const nodeById = new Map(nodes.map((node) => [node.id, node]));

    const pickEdge = (event: PointerEvent): string | null => {
      if (!linkLines) return null;
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      // A line has no thickness to hit: the threshold is in world units and has
      // to grow with the scene, or a 900-node campaign is unclickable.
      raycaster.params.Line!.threshold = Math.max(0.4, sphere.radius * 0.008);
      const hit = raycaster.intersectObject(linkLines, false)[0];
      if (!hit || hit.index === undefined) return null;
      const ids = linkLines.userData.ids as string[];
      return ids[Math.floor(hit.index / 2)] ?? null;
    };

    const pick = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      for (const hit of raycaster.intersectObjects(clouds, false)) {
        const index = hit.index;
        const list = hit.object.userData.ids as string[] | undefined;
        const id = index !== undefined && list ? list[index] : undefined;
        const node = id ? nodeById.get(id) : undefined;
        if (node) return node;
      }
      return null;
    };

    /** Which bubble's name plate is under the pointer, if any. */
    const pickLabel = (event: PointerEvent): string | null => {
      if (labelTargets.length === 0) return null;
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(labelTargets, false)[0];
      return (hit?.object.userData.community as string | undefined) ?? null;
    };

    const onPointerMove = (event: PointerEvent) => {
      // A name plate is a control: it collapses / expands its bubble, just like
      // the 2D pill. Say so with the cursor.
      renderer.domElement.style.cursor = pickLabel(event) ? 'pointer' : 'default';
      const node = pick(event);
      if (!node) {
        // A link is a target too: light it up, say so with the cursor, and let
        // the panel opening on click be expected rather than a surprise.
        hoveredEdgeId = pickEdge(event);
        if (hoveredEdgeId) {
          renderer.domElement.style.cursor = 'pointer';
          setHovered(null);
          return;
        }
        setHovered(null);
        return;
      }
      hoveredEdgeId = null;
      const rect = renderer.domElement.getBoundingClientRect();
      setHovered({
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
        label: node.label,
        kind: node.kind,
      });
    };
    const onPointerLeave = () => {
      hoveredEdgeId = null;
      setHovered(null);
      renderer.domElement.style.cursor = 'default';
    };
    const onClick = (event: MouseEvent) => {
      const community = pickLabel(event as unknown as PointerEvent);
      if (community && toggleRef.current) {
        toggleRef.current(community);
        return;
      }
      const node = pick(event as unknown as PointerEvent);
      if (node) {
        selectRef.current?.(node);
        return;
      }
      // Nothing under the pointer but a link: the panel below the canvas is the
      // same one the 2D projection opens, so the answer is identical.
      const edgeId = pickEdge(event as unknown as PointerEvent);
      if (edgeId) {
        selectRef.current?.(null);
        edgeSelectRef.current?.(edgeId);
        return;
      }
      edgeSelectRef.current?.(null);
      selectRef.current?.(null);
    };
    renderer.domElement.addEventListener('pointermove', onPointerMove);
    renderer.domElement.addEventListener('pointerleave', onPointerLeave);
    renderer.domElement.addEventListener('click', onClick);

    const resize = () => {
      const width = container.clientWidth || 800;
      const height = container.clientHeight || 600;
      renderer.setSize(width, height);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    };
    const observer =
      typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(resize);
    observer?.observe(container);

    let frame = 0;
    const animate = () => {
      frame = requestAnimationFrame(animate);
      controls.update();
      // The selected link is re-drawn brighter. It follows the camera for free
      // because the endpoints are model positions, not screen pixels.
      const selected = selectedEdgeRef.current;
      const marked = selected ?? hoveredEdgeId;
      const pair = marked ? linkFor.get(marked) : undefined;
      if (pair) {
        const attribute = edgeHighlight.geometry.getAttribute('position') as THREE.BufferAttribute;
        attribute.setXYZ(0, pair[0].x, pair[0].y, pair[0].z);
        attribute.setXYZ(1, pair[1].x, pair[1].y, pair[1].z);
        attribute.needsUpdate = true;
        (edgeHighlight.material as THREE.LineBasicMaterial).color.set(
          selected ? palette.selectionBorder : palette.hover
        );
        edgeHighlight.visible = true;
      } else {
        edgeHighlight.visible = false;
      }
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frame);
      observer?.disconnect();
      renderer.domElement.removeEventListener('pointerdown', onPointerDownCapture, true);
      renderer.domElement.removeEventListener('pointermove', onPointerMove);
      renderer.domElement.removeEventListener('pointerleave', onPointerLeave);
      renderer.domElement.removeEventListener('click', onClick);
      cameraStateRef.current = {
        graph,
        position: camera.position.clone(),
        target: controls.target.clone(),
      };
      controls.dispose();
      controlsRef.current = null;
      resetViewRef.current = null;
      zoomByRef.current = null;
      focusNodeRef.current = null;
      focusClusterRef.current = null;
      if (labelDataRef.current) {
        for (const child of labelDataRef.current.group.children) {
          const material = (child as THREE.Sprite).material as THREE.SpriteMaterial;
          material.map?.dispose();
          material.dispose();
        }
        labelDataRef.current = null;
      }
      if (highlightRef.current) {
        const material = highlightRef.current.mesh.material as THREE.SpriteMaterial;
        material.map?.dispose();
        material.dispose();
        highlightRef.current = null;
      }
      if (clusterRingsRef.current) {
        for (const child of [...clusterRingsRef.current.group.children]) {
          const material = (child as THREE.Sprite).material as THREE.SpriteMaterial;
          material.dispose();
        }
        clusterRingsRef.current.texture.dispose();
        clusterRingsRef.current = null;
      }
      onApi?.(null);
      setHovered(null);
      scene.traverse((object) => {
        if (object instanceof THREE.Sprite) {
          object.material.map?.dispose();
          object.material.dispose();
          return;
        }
        if (object instanceof THREE.Points || object instanceof THREE.LineSegments || object instanceof THREE.Mesh) {
          object.geometry.dispose();
          const material = object.material;
          if (Array.isArray(material)) material.forEach((item) => item.dispose());
          else material.dispose();
        }
      });
      renderer.dispose();
      container.removeChild(renderer.domElement);
    };
    // `colorFor` is a pure kind→colour lookup; rebuilding the scene on identity
    // changes would restart the camera for no reason.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, hiddenIds, removedIds, drawnNodeIds, drawnEdgeIds, compact, palette]);

  useEffect(() => {
    autoRotateRef.current = autoRotate;
    if (controlsRef.current) controlsRef.current.autoRotate = autoRotate;
  }, [autoRotate]);

  useEffect(() => {
    panModeRef.current = panMode;
  }, [panMode]);

  // Switching from 2D to 3D should give one slow reveal, not a carousel: the
  // orbit runs for five seconds and stops so the scene can be read. Only the
  // Auto-rotate button starts it again (and then it keeps running until the
  // analyst stops it).
  useEffect(() => {
    const timer = window.setTimeout(() => setAutoRotate(false), 5000);
    return () => window.clearTimeout(timer);
  }, []);

  return (
    <div className="relative min-h-0 flex-1 bg-dark-80">
      <div ref={containerRef} className="h-full w-full" />

      {drawnNodeIds && drawnNodeIds.size === 0 && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center bg-dark-80/80 px-6 text-center text-sm text-gray-400">
          Nothing matches the current filters — widen the kind switches or the
          neighbour budget in the toolbar.
        </div>
      )}

      <div className="pointer-events-none absolute left-3 top-2 text-[11px] text-gray-400">
        <span className="rounded bg-dark-40/70 px-1.5 py-0.5">
          {(graph.nodes ?? []).length} nodes · 3D
        </span>
      </div>

      {/* The controls own the top-right corner, so the hint line sits with the
          counts at the bottom — the same place the 2D canvas puts them. Sharing
          the top row made a narrow canvas run the buttons through the words. */}
      <p className="pointer-events-none absolute bottom-2 left-3 text-[11px] text-gray-600">
        drag to orbit · shift+drag or Pan to move · scroll to zoom · click a node or a link
        to inspect
      </p>

      <div className="absolute right-3 top-2 flex items-center gap-1 text-[11px]">
        <button
          type="button"
          onClick={onToggleLabels}
          aria-pressed={showLabels}
          title="Show or hide names for nodes and links (up to 150 nodes and 120 links in 3D; the busiest ones win). Clicking a link opens the same inspector the 2D canvas opens."
          className={
            showLabels
              ? 'rounded border border-teal-500/40 bg-teal-500/10 px-2 py-1 text-teal-200'
              : 'rounded border border-[#374151] bg-dark-70/85 px-2 py-1 text-gray-300 backdrop-blur-sm hover:border-gray-500'
          }
        >
          Labels
        </button>
        <button
          type="button"
          onClick={() => setPanMode((value) => !value)}
          aria-pressed={panMode}
          title="Left-drag moves the scene instead of orbiting it. Shift+drag does the same without the toggle."
          className={
            panMode
              ? 'rounded border border-teal-500/40 bg-teal-500/10 px-2 py-1 text-teal-200'
              : 'rounded border border-[#374151] bg-dark-70/85 px-2 py-1 text-gray-300 backdrop-blur-sm hover:border-gray-500'
          }
        >
          Pan
        </button>
        <button
          type="button"
          onClick={() => setAutoRotate((value) => !value)}
          aria-pressed={autoRotate}
          className={
            autoRotate
              ? 'rounded border border-teal-500/40 bg-teal-500/10 px-2 py-1 text-teal-200'
              : 'rounded border border-[#374151] bg-dark-70/85 px-2 py-1 text-gray-300 backdrop-blur-sm hover:border-gray-500'
          }
        >
          Auto-rotate
        </button>
        <div
          role="group"
          aria-label="3D zoom"
          className="flex overflow-hidden rounded border border-[#374151] bg-dark-70/85 backdrop-blur-sm"
        >
          <button
            type="button"
            onClick={() => zoomByRef.current?.(1 / 1.25)}
            aria-label="Zoom out"
            title="Zoom out"
            className="px-2 py-1 text-gray-300 transition-colors hover:bg-white/5"
          >
            −
          </button>
          <button
            type="button"
            onClick={() => zoomByRef.current?.(1.25)}
            aria-label="Zoom in"
            title="Zoom in"
            className="border-l border-[#374151] px-2 py-1 text-gray-300 transition-colors hover:bg-white/5"
          >
            +
          </button>
        </div>
        <button
          type="button"
          onClick={() => resetViewRef.current?.()}
          title="Frame the whole scene."
          className="rounded border border-[#374151] px-2 py-1 text-gray-300 hover:border-gray-500"
        >
          Fit
        </button>
        {onClearView && (
          <button
            type="button"
            onClick={onClearView}
            title="Undo Focus, expansion, Hide and Remove — back to the whole campaign."
            className="rounded border border-[#374151] bg-dark-70/85 px-2 py-1 text-gray-300 backdrop-blur-sm hover:border-teal-500/60 hover:text-teal-200"
          >
            Clear view
          </button>
        )}
        <button
          type="button"
          onClick={onClose}
          className="rounded border border-[#374151] px-2 py-1 text-gray-300 hover:border-gray-500"
        >
          Back to 2D
        </button>
      </div>

      {hovered && (
        <div
          className="pointer-events-none absolute z-10 max-w-[280px] rounded-md border border-[#374151] bg-dark-70/95 px-2 py-1 text-[11px] shadow-xl"
          style={{ left: hovered.x + 12, top: hovered.y + 12 }}
          role="tooltip"
        >
          <span className="block text-[9px] uppercase tracking-wide text-gray-500">
            {hovered.kind}
          </span>
          <span className="block break-all font-mono text-gray-100">{hovered.label}</span>
        </div>
      )}
    </div>
  );
}
