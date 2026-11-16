import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

// Mock Next.js routing primitives. The Sidebar reads `usePathname` to decide
// which item is active and uses `<Link>` for navigation; for a smoke test we
// just need both to behave as plain functions/elements.
vi.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
}));

vi.mock('next/link', () => ({
  default: ({
    children,
    href,
    className,
  }: {
    children: React.ReactNode;
    href: string;
    className?: string;
  }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

import { Sidebar } from './Sidebar';

describe('Sidebar', () => {
  it('renders the Soorin mark and the major nav sections', () => {
    render(<Sidebar />);

    // Brand
    expect(screen.getByText('Soorin')).toBeInTheDocument();
    expect(screen.getByText(/Attack Detection/i)).toBeInTheDocument();

    // Section headings — Dashboard sits in an unlabelled lead section,
    // everything else is grouped under one of these four titles.
    expect(screen.getByText('Threat Operations')).toBeInTheDocument();
    expect(screen.getByText('Intelligence')).toBeInTheDocument();
    expect(screen.getByText('Automation')).toBeInTheDocument();
    expect(screen.getByText('Platform')).toBeInTheDocument();
  });

  it('exposes core workflow entry points and hides deferred surfaces', () => {
    render(<Sidebar />);

    const workflow = screen.getByRole('link', { name: /workflow soc/i });
    expect(workflow).toHaveAttribute('href', '/workflow-soc');

    const funnel = screen.getByRole('link', { name: /soc funnel/i });
    expect(funnel).toHaveAttribute('href', '/soc-funnel');

    const users = screen.getByRole('link', { name: /^users$/i });
    expect(users).toHaveAttribute('href', '/settings/users');

    expect(screen.queryByRole('link', { name: /investigation queue/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /^hunt$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /compliance/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /agentic shadow runs/i })).not.toBeInTheDocument();
  });

  it('renders the MIT license attribution in the footer', () => {
    render(<Sidebar />);

    const license = screen.getByRole('link', { name: /MIT License/i });
    expect(license).toHaveAttribute('href', 'https://github.com/SoorinSecurity/Agentic_SOC');
  });
});
