/**
 * Turn a case `description` into something readable in a case header.
 *
 * Two shapes have to be handled, and they are both in the database:
 *
 * * **Legacy** (engine before the summary change) — a provenance line, four
 *   `Key: value` metadata lines, then a bare `Observations:` heading followed by
 *   one bullet per observation. Case 567274f8… carries 59 such lines (~8000
 *   characters, duplicates and all), which the header used to render as one
 *   wall of text.
 * * **Current** — one summary sentence, the same four metadata lines, a bounded
 *   rule roll-up, and a provenance footer.
 *
 * Every number the engine wrote (`observations`, `alerts`, `rules`, `score`,
 * phases) is frozen at case creation. The correlation graph recomputes those
 * counts from live evidence, so none of them may be rendered as current — the
 * header once read "9 rules" next to "17 distinct rules", and an explicitly
 * labelled snapshot line still put "114 alerts" under a case that holds nine.
 * All of them are therefore dropped here: the caller measures alerts and rules
 * live from the case record, and `facts` keeps only the campaigns window, which
 * does not change. The rule bullets under `Rules (N distinct):` go with the
 * count, for the same reason.
 *
 * The observation bullets are never rendered here at all — the Observations tab
 * is their home — but they are counted so the header can say how many there are.
 *
 * Analyst-written descriptions (anything that is not engine-shaped) fall through
 * as a single clipped headline plus the rest behind the toggle.
 */

export interface CaseDescriptionSummary {
  /** One sentence: what the case is and when — never a mutable count. */
  headline: string;
  /** Stable context chips (campaign window); omitted when absent. */
  facts: string[];
  /** Rule roll-up + provenance, rendered only when the analyst asks for it. */
  details: string;
  /** Bullets the legacy format listed under `Observations:`; 0 when absent. */
  observationCount: number;
  /** True when the description was written by the correlation engine. */
  isEngine: boolean;
}

const EMPTY: CaseDescriptionSummary = {
  headline: '',
  facts: [],
  details: '',
  observationCount: 0,
  isEngine: false,
};

const OBSERVATIONS_HEADING = /^observations:\s*$/i;
const PROVENANCE = /^created by the graph correlation engine/i;
/** `Graph correlation grouped 73 observation(s) from 114 alert(s) …` */
const ENGINE_SUMMARY = /^graph correlation grouped\b/i;
/**
 * `Label: value` for the labels the engine actually writes, with an optional
 * parenthetical note before the colon (`Rules (7 distinct):`). Deliberately an
 * allow-list: an analyst's free-form note may well contain a colon, and it must
 * stay a headline rather than turn into a metadata chip.
 */
const LABELLED =
  /^(correlation score|observations merged|roles|primary entity|rules|phases)\s*(?:\(([^)]*)\))?\s*:\s*(.*)$/i;

const MAX_HEADLINE = 300;
const MAX_DETAILS = 4000;

function clip(text: string, limit: number): string {
  const trimmed = text.trim();
  if (trimmed.length <= limit) return trimmed;
  const cut = trimmed.slice(0, limit);
  const lastSpace = cut.lastIndexOf(' ');
  return `${(lastSpace > limit * 0.6 ? cut.slice(0, lastSpace) : cut).trimEnd()}…`;
}

export function summariseCaseDescription(raw?: string | null): CaseDescriptionSummary {
  const text = (raw ?? '').replace(/\r\n?/g, '\n').trim();
  if (!text) return EMPTY;

  const lines = text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const headingAt = lines.findIndex((line) => OBSERVATIONS_HEADING.test(line));
  const body = headingAt === -1 ? lines : lines.slice(0, headingAt);
  const observationCount =
    headingAt === -1 ? 0 : lines.slice(headingAt + 1).filter((line) => line.startsWith('-')).length;

  const provenance: string[] = [];
  const extra: string[] = [];
  const facts: string[] = [];
  let headline = '';
  let engineSummary = '';
  let merged = 0;
  let score = '';
  let primary = '';
  /** Inside the engine's `Rules (N distinct):` block, whose bullets are dropped. */
  let inRulesBlock = false;

  for (const line of body) {
    if (line.startsWith('- ')) {
      if (!inRulesBlock) extra.push(line);
      continue;
    }
    inRulesBlock = false;

    if (PROVENANCE.test(line)) {
      provenance.push(line);
      continue;
    }

    if (!engineSummary && ENGINE_SUMMARY.test(line)) {
      engineSummary = line;
      continue;
    }

    const labelled = LABELLED.exec(line);
    if (labelled && !line.startsWith('- ')) {
      const label = labelled[1].trim();
      const value = labelled[3].trim();
      switch (label.toLowerCase()) {
        case 'correlation score':
          // "5 (L1 entity overlap + L2 context + L3 graph path)" → "5"
          score = value.split(/\s*\(/)[0].trim();
          break;
        case 'observations merged':
          merged = Number.parseInt(value, 10) || 0;
          break;
        case 'primary entity':
          primary = value.toLowerCase() === 'n/a' ? '' : value;
          break;
        case 'rules':
          // Counted over observations, not alerts — a stale, misleading number.
          // The live roll-up comes from the case record, so the whole block goes.
          inRulesBlock = true;
          break;
        default:
          // `roles` / `phases` and any other engine label: frozen values that the
          // live rule/alert counts already cover, so they are not surfaced.
          break;
      }
      continue;
    }

    if (!headline) {
      headline = line;
      continue;
    }
    extra.push(line);
  }

  const isEngine =
    provenance.length > 0 || Boolean(engineSummary) || merged > 0 || Boolean(score && primary);

  if (isEngine) {
    // The engine sentence carries the campaign window ("… into one campaign,
    // 2026-09-21 22:57 → 2026-11-14 06:05."). Keep that one stable fact and drop
    // every count: the caller measures alerts and rules live.
    const windowMatch = /into one campaign,\s*(.+?)\s*\.?$/i.exec(engineSummary);
    const entityMatch = /\b(?:on|for)\s+(.+?)\s+into one campaign/i.exec(engineSummary);
    const anchor = entityMatch?.[1] ?? primary;
    const window = windowMatch?.[1] ?? '';

    headline = `Graph-correlated campaign${anchor ? ` on ${anchor}` : ''}${
      window ? `, ${window}` : ''
    }.`;
    if (window) facts.push(window);
  } else {
    // Analyst-written notes have no engine numbers at all.
    facts.length = 0;
  }

  return {
    headline: clip(headline, MAX_HEADLINE),
    facts,
    // Provenance footer only; the rule roll-up is measured live by the caller.
    details: clip([...extra, ...provenance].join('\n'), MAX_DETAILS),
    observationCount,
    isEngine,
  };
}
