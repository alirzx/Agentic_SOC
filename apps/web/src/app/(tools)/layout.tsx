import Link from "next/link";
import type { ReactNode } from "react";
import { BrandLogo } from "@/components/brand/BrandLogo";
import { BRAND } from "@/lib/brand";

/**
 * Shell for the free standalone tools at /tools/*.
 * Visual language aligned with AssetManagement (navy + teal).
 */
export default function ToolsLayout({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        background: "#121724",
        minHeight: "100vh",
        color: "#FFFEFE",
        fontFamily: "Gilroy, Helvetica, system-ui, sans-serif",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "16px 24px",
          borderBottom: "1px solid #374151",
          background: "#161B28",
        }}
      >
        <Link
          href="/tools"
          style={{
            color: "#FFFEFE",
            textDecoration: "none",
            display: "inline-flex",
            alignItems: "center",
            gap: 10,
            fontWeight: 800,
            letterSpacing: 0.5,
          }}
        >
          <BrandLogo variant="mark" size={28} />
          <span>
            {BRAND.shortName}{" "}
            <span style={{ color: "#909FAE", fontWeight: 500 }}>· free tools</span>
          </span>
        </Link>
        <nav style={{ display: "flex", gap: 18, fontSize: 14 }}>
          <Link href="/tools/translate" style={{ color: "#9298A2", textDecoration: "none" }}>
            Translate
          </Link>
          <Link href="/tools/nl2sigma" style={{ color: "#9298A2", textDecoration: "none" }}>
            NL→Sigma
          </Link>
          <Link href="/tools/coverage" style={{ color: "#9298A2", textDecoration: "none" }}>
            Coverage
          </Link>
          <Link href="/tools/noise" style={{ color: "#9298A2", textDecoration: "none" }}>
            Noise
          </Link>
          <a
            href={BRAND.githubUrl}
            style={{ color: "#4FD2C2", textDecoration: "none", fontWeight: 700 }}
          >
            GitHub ★
          </a>
        </nav>
      </header>
      <div style={{ maxWidth: 980, margin: "0 auto", padding: "40px 24px 64px" }}>{children}</div>
      <footer
        style={{
          borderTop: "1px solid #374151",
          padding: "24px",
          textAlign: "center",
          color: "#596272",
          fontSize: 13,
        }}
      >
        Free & open source · part of{" "}
        <a href={BRAND.githubUrl} style={{ color: "#4FD2C2" }}>
          {BRAND.product}
        </a>
        . Everything on this page runs in your browser — your rules never touch our servers.
      </footer>
    </div>
  );
}
