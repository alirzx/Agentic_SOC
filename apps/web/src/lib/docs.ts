export const DOCS_BASE =
  process.env.NEXT_PUBLIC_DOCS_URL ??
  "https://github.com/SoorinSecurity/Agentic_SOC/blob/main/apps/docs/docs";

export const docs = (path: string) =>
  `${DOCS_BASE}/${path.replace(/^\//, "")}`;
