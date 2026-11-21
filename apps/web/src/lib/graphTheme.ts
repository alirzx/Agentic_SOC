'use client';

/**
 * Colours the correlation graph paints with, per theme.
 *
 * The canvas is not DOM. Cytoscape and three.js take literal colours, so the
 * `data-theme` token remap that flips every Tailwind utility (light-theme.css)
 * cannot reach a node label or a link. Without this table the graph stayed on
 * its dark palette after light mode shipped, and read as a black hole inside a
 * white modal.
 *
 * Light is not the dark palette inverted. A node's label is outlined in the
 * canvas colour — that halo is what separates text from a coloured node — and
 * the score label needs a darker teal to stay legible on white.
 */
import { useEffect, useState } from 'react';

export type GraphTheme = 'light' | 'dark';

export interface GraphPalette {
  /** Canvas fill, and the halo every 2D label is outlined with. */
  surface: string;
  /** Node and link labels. */
  ink: string;
  /** Secondary ink: a bubble's subtitle, a quiet count. */
  inkMuted: string;
  /** Halo behind a 3D name plate's text. */
  halo: string;
  /** Backdrop of a 3D bubble plate. */
  plateFill: string;
  /** A link with no rule of its own. */
  edge: string;
  /** Selected / focused link and node ring. */
  edgeStrong: string;
  /** A CORRELATION link: the pair cleared θ. */
  scoreLine: string;
  /** Its score label. */
  scoreInk: string;
  /** Label on an observation drawn as a relation. */
  actionInk: string;
  /** Selection language: underlay ring, and the border drawn on it. */
  selection: string;
  selectionBorder: string;
  /** A link (or the node it joins) under the pointer. */
  hover: string;
  /**
   * Alpha of the 3D link web. The same 22% that reads as a fine hairline on the
   * dark canvas disappears on white, so the light scene draws its links heavier.
   */
  linkOpacity: number;
}

const DARK: GraphPalette = {
  surface: '#0b1220',
  ink: '#e5e7eb',
  inkMuted: '#94a3b8',
  halo: 'rgba(2, 6, 23, 0.92)',
  plateFill: 'rgba(2, 6, 23, 0.78)',
  edge: '#475569',
  edgeStrong: '#f8fafc',
  scoreLine: '#2dd4bf',
  scoreInk: '#5eead4',
  actionInk: '#e2e8f0',
  selection: '#2dd4bf',
  selectionBorder: '#5eead4',
  hover: '#e2e8f0',
  linkOpacity: 0.22,
};

const LIGHT: GraphPalette = {
  surface: '#ffffff',
  ink: '#1f2937',
  inkMuted: '#4b5563',
  halo: 'rgba(255, 255, 255, 0.92)',
  plateFill: 'rgba(255, 255, 255, 0.9)',
  edge: '#64748b',
  edgeStrong: '#0f172a',
  scoreLine: '#0d9488',
  scoreInk: '#0f766e',
  actionInk: '#334155',
  selection: '#14b8a6',
  selectionBorder: '#0f766e',
  hover: '#334155',
  linkOpacity: 0.45,
};

/** The palette for a resolved theme; both tables are frozen literals. */
export function graphPalette(theme: GraphTheme): GraphPalette {
  return theme === 'light' ? LIGHT : DARK;
}

function currentGraphTheme(): GraphTheme {
  if (typeof document === 'undefined') return 'light';
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}

/**
 * The theme the document is currently painted with.
 *
 * Read from `<html data-theme>` rather than {@link useTheme}: ThemeProvider
 * throws outside its tree, and the graph is also rendered in Storybook, where
 * the theme decorator writes the attribute without mounting the provider.
 *
 * The first read happens during render so an open in dark mode does not build
 * the canvas once in light colours and rebuild it a frame later — that rebuild
 * would re-run the layout in front of the analyst. The palette never reaches
 * server-rendered markup, only the canvas effects, so reading the DOM here
 * cannot cause a hydration mismatch.
 */
export function useGraphTheme(): GraphTheme {
  const [theme, setTheme] = useState<GraphTheme>(currentGraphTheme);
  useEffect(() => {
    const root = document.documentElement;
    // Only the switch itself has to be watched; the first read already happened
    // during render, so there is nothing to correct on mount.
    const observer = new MutationObserver(() => setTheme(currentGraphTheme()));
    observer.observe(root, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);
  return theme;
}
