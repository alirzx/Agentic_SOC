/**
 * Brand asset paths — always use these instead of inventing ad-hoc marks.
 */
export const BRAND = {
  company: 'Soorin Security',
  product: 'Soorin Agentic SOC',
  shortName: 'Soorin',
  tagline: 'AI-powered Security Operations Center',
  githubOrg: 'SoorinSecurity',
  githubRepo: 'Agentic_SOC',
  githubUrl: 'https://github.com/SoorinSecurity/Agentic_SOC',
  githubIssues: 'https://github.com/SoorinSecurity/Agentic_SOC/issues',
  website: 'https://soorinsec.ir',
  email: 'info@soorinsec.ir',
  linkedin: 'https://www.linkedin.com/company/soorinsec',
  license: 'MIT',
  logoMark: '/logo/logo-mark.svg',
  logoLockup: '/logo/soorin-attack-detection.svg',
} as const;

export const BRAND_GITHUB_BLOB = `${BRAND.githubUrl}/blob/main`;
export const BRAND_GITHUB_TREE = `${BRAND.githubUrl}/tree/main`;
