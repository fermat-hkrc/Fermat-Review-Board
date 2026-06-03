import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Fermat Review Board",
  description:
    "Security vulnerability review board powered by Fermat Security Scanner",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="zh-CN"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col" style={{ background: "#0a0a0a", color: "#ededed" }}>
        <nav className="border-b border-[#262626] bg-[#0a0a0a]/80 backdrop-blur-sm sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-14">
              <div className="flex items-center gap-8">
                <Link
                  href="/"
                  className="text-lg font-bold tracking-tight text-white flex items-center gap-2"
                >
                  <span className="text-blue-500">&#x25C6;</span>
                  Fermat Review Board
                </Link>
                <div className="hidden sm:flex items-center gap-1">
                  <NavLink href="/">Dashboard</NavLink>
                  <NavLink href="/issues">Issues</NavLink>
                  <NavLink href="/poc">PoC</NavLink>
                  <NavLink href="/analysis">Analysis</NavLink>
                </div>
              </div>
              <a
                href="https://github.com/fermat-hkrc/Fermat-Review-Board"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-[#a3a3a3] hover:text-white transition-colors"
              >
                GitHub
              </a>
            </div>
          </div>
        </nav>
        <main className="flex-1">{children}</main>
        <footer className="border-t border-[#262626] py-6 text-center text-sm text-[#737373]">
          Fermat Security Scanner &mdash; Automated vulnerability detection for
          C/C++ codebases
        </footer>
      </body>
    </html>
  );
}

function NavLink({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      className="px-3 py-1.5 text-sm text-[#a3a3a3] hover:text-white hover:bg-[#1a1a1a] rounded-md transition-colors"
    >
      {children}
    </Link>
  );
}
