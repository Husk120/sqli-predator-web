"use client";

import Link from "next/link";
import { useState } from "react";

export function Header() {
    const [mobileOpen, setMobileOpen] = useState(false);

    return (
        <header className="border-b border-surface-border bg-surface/80 backdrop-blur-sm sticky top-0 z-50">
            <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between">
                <Link href="/" className="flex items-center gap-2">
                    <span className="text-2xl">🦅</span>
                    <span className="font-bold text-lg text-white">
                        SQLi-<span className="text-accent-blue">PREDATOR</span>
                    </span>
                    <span className="text-xs text-gray-500 ml-1 border border-surface-border px-1.5 py-0.5 rounded">
                        v4.0
                    </span>
                </Link>

                <nav className="hidden md:flex items-center gap-6">
                    <Link
                        href="/"
                        className="text-sm text-gray-400 hover:text-white transition-colors"
                    >
                        New Scan
                    </Link>
                    <Link
                        href="/scans"
                        className="text-sm text-gray-400 hover:text-white transition-colors"
                    >
                        Scan History
                    </Link>
                    <a
                        href="https://github.com/hackerai/sqli-predator"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-gray-400 hover:text-white transition-colors"
                    >
                        GitHub
                    </a>
                </nav>

                <button
                    className="md:hidden text-gray-400"
                    onClick={() => setMobileOpen(!mobileOpen)}
                >
                    {mobileOpen ? "✕" : "☰"}
                </button>
            </div>

            {mobileOpen && (
                <div className="md:hidden border-t border-surface-border px-4 py-3 flex flex-col gap-3">
                    <Link href="/" className="text-sm text-gray-400" onClick={() => setMobileOpen(false)}>
                        New Scan
                    </Link>
                    <Link href="/scans" className="text-sm text-gray-400" onClick={() => setMobileOpen(false)}>
                        Scan History
                    </Link>
                </div>
            )}
        </header>
    );
}
