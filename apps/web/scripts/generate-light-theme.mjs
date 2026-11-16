#!/usr/bin/env node
/**
 * Generates `src/app/light-theme.css` — the light-mode remap layer.
 *
 * Why this exists: most console components were written dark-first with
 * hard-coded utilities (`text-gray-400`, `bg-slate-800/60`,
 * `border-[#374151]`, `text-white`, `text-red-300`, …) instead of the
 * semantic `surface-*` / `fg-*` tokens. Rewriting thousands of class names
 * is risky, so light mode instead remaps those utilities centrally:
 *
 *   1. Tailwind palette variables are redefined under `[data-theme="light"]`:
 *      gray/slate/zinc/neutral/stone ramps flip, white becomes navy ink,
 *      pastel chromatic shades (50–400, used as text on dark) darken and
 *      the 900/950 "dark tint" shades lighten. Every utility that reads them
 *      — including opacity variants, which compile to
 *      `color-mix(var(--color-…))` — follows automatically.
 *   2. Utilities that compile to literal colours (arbitrary hex values)
 *      get explicit per-class overrides.
 *   3. Islands that must keep their native colours restore the default
 *      palette: nested `[data-theme="dark"]` wrappers (marketing pages),
 *      explicitly light components (`bg-white` cards) and solid accent
 *      fills (white / pastel text on teal, red, cyan, … buttons and chips).
 *
 * Palette: light dashboard design — page #F6F8FB, cards #FFFFFF,
 * borders #E5E7EB, text #121724 / #1F2937 / #374151 / #6B7280 / #939DAD,
 * brand teal #4FD2C2.
 *
 * Usage:  node scripts/generate-light-theme.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const OUT = join(here, '..', 'src', 'app', 'light-theme.css');

// ── Tailwind defaults (needed to restore palette inside reset islands) ──
const themeCss = readFileSync(
  join(dirname(require.resolve('tailwindcss/package.json')), 'theme.css'),
  'utf8',
);
const tw = {};
for (const m of themeCss.matchAll(/--color-([a-z]+(?:-\d+)?):\s*([^;]+);/g)) {
  tw[m[1]] = m[2].trim();
}

const LIGHT = 'html[data-theme="light"]';
// Excludes elements inside a nested forced-dark wrapper.
const NOT_DARK = ':not([data-theme="dark"] *)';

// ── 1. Palette variable remaps ──────────────────────────────────────────
const NEUTRAL_FAMILIES = ['gray', 'slate', 'zinc', 'neutral', 'stone'];
// Dark-first usage → light equivalent (text shades darken, surface shades lighten).
const NEUTRAL_RAMP = {
  50: '#0b0f19',
  100: '#121724', // primary text
  200: '#1f2937',
  300: '#374151',
  400: '#4b5563',
  500: '#6b7280', // secondary text
  600: '#939dad', // tertiary text / strong borders
  700: '#e5e7eb', // borders, chips
  800: '#ebeef2',
  900: '#f3f4f6',
  950: '#f9fafb',
};

const CHROMATIC = [
  'red', 'orange', 'amber', 'yellow', 'lime', 'green', 'emerald', 'teal',
  'cyan', 'sky', 'blue', 'indigo', 'violet', 'purple', 'fuchsia', 'pink', 'rose',
];
// Low-luminance hues need one step darker to stay legible on white.
const PALE_HUES = new Set(['amber', 'yellow', 'lime']);

const paletteVars = {};
for (const fam of NEUTRAL_FAMILIES) {
  for (const [shade, value] of Object.entries(NEUTRAL_RAMP)) {
    paletteVars[`${fam}-${shade}`] = value;
  }
}
for (const hue of CHROMATIC) {
  // Pastel text shades (designed for dark backgrounds) → readable darks.
  const ink = PALE_HUES.has(hue)
    ? { 50: 800, 100: 800, 200: 800, 300: 700, 400: 700 }
    : { 50: 800, 100: 800, 200: 700, 300: 700, 400: 600 };
  for (const [from, to] of Object.entries(ink)) paletteVars[`${hue}-${from}`] = tw[`${hue}-${to}`];
  // Dark tinted panels (`bg-red-950/40`, `border-emerald-900`) → light tints.
  paletteVars[`${hue}-900`] = tw[`${hue}-200`];
  paletteVars[`${hue}-950`] = tw[`${hue}-100`];
}
// `text-white` / `bg-white/[0.03]` / `border-white/10` → navy ink.
paletteVars.white = '#121724';

// Project tokens (tailwind.config.ts reads these variables): [dark, light].
const AM_TOKENS = {
  'am-dark-10': ['#1F2533', '#e5e7eb'],
  'am-dark-20': ['#1F2638', '#f3f4f6'],
  'am-dark-30': ['#192130', '#f9fafb'],
  'am-dark-40': ['#1E2434', '#f3f4f6'],
  'am-dark-50': ['#151D2C', '#f9fafb'],
  'am-dark-60': ['#181E2D', '#ffffff'],
  'am-dark-70': ['#161B28', '#ffffff'],
  'am-dark-80': ['#121724', '#f6f8fb'],
  'am-gray-10': ['#FFFEFE', '#121724'],
  'am-gray-20': ['#9298A2', '#4b5563'],
  'am-gray-30': ['#909FAE', '#6b7280'],
  'am-gray-40': ['#728497', '#6b7280'],
  'am-gray-50': ['#596272', '#939dad'],
  'am-gray-60': ['#333A47', '#d1d5db'],
  'am-teal-10': ['#6AF8E7', '#1c9e8f'],
  'am-brand-200': ['#8af8ea', '#2a9e91'],
  'am-brand-300': ['#6AF8E7', '#2a9e91'],
  'am-brand-400': ['#5FEEDD', '#2a9e91'],
  'am-sev-critical': ['#ef4444', '#fd4e4e'],
  'am-sev-high': ['#f97316', '#f98b3e'],
  'am-sev-medium': ['#eab308', '#f2bd57'],
  'am-sev-low': ['#3163CF', '#4fd2c2'],
  'am-sev-info': ['#64FF99', '#4ade80'],
  'am-status-live': ['#64FF99', '#4ade80'],
  'am-status-warn': ['#F0BC56', '#f2bd57'],
  'am-status-dead': ['#ef4444', '#fd4e4e'],
  'am-status-idle': ['#596272', '#939dad'],
};

// ── 2. Per-class overrides for literal colours ─────────────────────────
const ALPHAS = ['', '/30', '/40', '/50', '/60', '/70', '/80'];
const VARIANTS = ['', 'hover', 'group-hover'];
const classRules = []; // [className, declaration, selectorSuffix?, variants?]

// Dark chrome borders → design border #E5E7EB (hover states one step stronger).
for (const hex of ['#333A47', '#374151', '#1D232F']) {
  for (const a of ALPHAS) {
    classRules.push([`border-[${hex}]${a}`, 'border-color: #e5e7eb', '', ['', 'group-hover']]);
    classRules.push([`border-[${hex}]${a}`, 'border-color: #d1d5db', '', ['hover']]);
    classRules.push([`divide-[${hex}]${a}`, 'border-color: #e5e7eb', ' > :not(:last-child)', ['']]);
    classRules.push([`ring-[${hex}]${a}`, '--tw-ring-color: #e5e7eb', '', ['']]);
  }
}
classRules.push(['bg-[#374151]', 'background-color: #e5e7eb']);
for (const hex of ['#0d1117', '#0a1120', '#111620', '#0d121b', '#121724', '#161b28', '#181e2d']) {
  for (const a of ALPHAS) classRules.push([`bg-[${hex}]${a}`, 'background-color: #ffffff']);
}
classRules.push(['bg-[#0b1c24]/75', 'background-color: rgb(79 210 194 / 0.08)']);
classRules.push(['text-[#64FF99]', 'color: #16a34a']);
classRules.push(['text-[#F0BC56]', 'color: #b7791f']);
classRules.push(['text-[#6ff3df]', 'color: #1c9e8f']);
classRules.push(['text-[#7BA3F0]', 'color: #3163cf']);
// `text-dark-80` sits on teal buttons — must stay dark ink.
classRules.push(['text-dark-80', 'color: #121724']);

// ── 3. Reset islands ───────────────────────────────────────────────────
// Solid accent fills keep white / pastel text (exact class tokens, so
// translucent tints such as `bg-red-500/10` are not matched).
const ACCENT_FILLS = [
  'bg-brand-500', 'bg-brand-600', 'bg-brand-600/80', 'bg-brand-700',
  'bg-teal-20', 'bg-teal-30',
  'bg-severity-critical', 'bg-severity-high', 'bg-severity-low',
];
for (const hue of CHROMATIC) {
  for (const shade of [500, 600, 700, 800]) {
    for (const a of ['', '/70', '/80', '/90']) ACCENT_FILLS.push(`bg-${hue}-${shade}${a}`);
  }
}

// ── Emit ───────────────────────────────────────────────────────────────
const esc = (cls) => cls.replace(/[^a-zA-Z0-9_-]/g, (c) => `\\${c}`);
function selector(cls, variant, suffix = '') {
  const base = variant ? `.${esc(`${variant}:${cls}`)}` : `.${esc(cls)}`;
  switch (variant) {
    case '':
      return `${LIGHT} ${base}${NOT_DARK}${suffix}`;
    case 'group-hover':
      return `${LIGHT} .group:hover ${base}${NOT_DARK}${suffix}`;
    default:
      return `${LIGHT} ${base}:${variant}${NOT_DARK}${suffix}`;
  }
}
const decls = (obj, indent = '  ') =>
  Object.entries(obj).map(([k, v]) => `${indent}--${k}: ${v};`).join('\n');

const paletteDefaults = {};
for (const key of Object.keys(paletteVars)) paletteDefaults[`color-${key}`] = tw[key];

const out = [];
out.push(`/*
 * GENERATED by scripts/generate-light-theme.mjs — do not edit by hand.
 * Re-run \`node scripts/generate-light-theme.mjs\` after changing the script.
 *
 * Light-mode remap layer: see the script header for the rationale.
 */
`);

out.push(`/* Project tokens: dark defaults (also restored inside forced-dark islands). */
:root,
[data-theme="dark"] {
${decls(Object.fromEntries(Object.entries(AM_TOKENS).map(([k, [d]]) => [k, d])))}
}
`);

out.push(`/* Light palette. */
${LIGHT} {
${decls(Object.fromEntries(Object.entries(AM_TOKENS).map(([k, [, l]]) => [k, l])))}
${decls(Object.fromEntries(Object.entries(paletteVars).map(([k, v]) => [`color-${k}`, v])))}
}
`);

out.push(`/* Forced-dark wrappers (marketing pages) restore Tailwind's palette. */
${LIGHT} [data-theme="dark"] {
${decls(paletteDefaults)}
}
`);

out.push(`/* Explicitly light components keep their native look. */
${LIGHT} .bg-white${NOT_DARK},
${LIGHT} .hover\\:bg-white:hover${NOT_DARK} {
  background-color: #ffffff;
${decls(paletteDefaults)}
}
`);

out.push(`/* Solid accent fills keep white / pastel text. */
${ACCENT_FILLS.map((c) => `${LIGHT} [class~="${c}"]${NOT_DARK}`).join(',\n')} {
${decls(paletteDefaults)}
}
`);

out.push('/* Literal-colour utilities. */');
for (const [cls, decl, suffix = '', variants = VARIANTS] of classRules) {
  const sels = variants.map((v) => selector(cls, v, suffix));
  out.push(`${sels.join(',\n')} {\n  ${decl};\n}`);
}

writeFileSync(OUT, `${out.join('\n')}\n`);
console.log(`wrote ${OUT} (${classRules.length} class rules)`);
