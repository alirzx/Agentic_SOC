import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

vi.mock('next/link', () => ({
  default: ({
    children,
    href,
    ...rest
  }: {
    children?: React.ReactNode;
    href: string;
    [key: string]: unknown;
  }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

vi.mock('next/image', () => ({
  default: (props: { alt: string }) => <img alt={props.alt} />,
}));

import { SoorinHero } from './SoorinHero';

describe('SoorinHero', () => {
  it('renders the splash headline and both CTAs to login', () => {
    render(<SoorinHero />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
      /soorin\s*agentic soc\.?/i,
    );
    expect(screen.getByRole('link', { name: /log in/i })).toHaveAttribute(
      'href',
      '/login',
    );
    expect(screen.getByRole('link', { name: /get started/i })).toHaveAttribute(
      'href',
      '/login',
    );
  });
});
