"use client";

import Link from "next/link";
import { useState, useEffect } from "react";

export function Header() {
    const [mobileOpen, setMobileOpen] = useState(false);
    const [theme, setTheme] = useState<"light" | "dark">("light");

    useEffect(() => {
        const saved = localStorage.getItem("sqli_theme") as "light" | "dark" | null;
        const initialTheme = saved || "light";
        setTheme(initialTheme);
        document.documentElement.setAttribute("data-theme", initialTheme);
    }, []);

    const toggleTheme = () => {
        const nextTheme = theme === "light" ? "dark" : "light";
        setTheme(nextTheme);
        localStorage.setItem("sqli_theme", nextTheme);
        document.documentElement.setAttribute("data-theme", nextTheme);
    };

    return (
        <header className="bg-[var(--bg-card)] border-b border-[var(--border-subtle)] sticky top-0 z-50 transition-colors">
            <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between">
                <Link href="/" className="flex items-center gap-2 focus:outline-none border-0">
                    <span className="text-2xl">🦅</span>
                    <span className="font-bold text-lg text-[var(--text-primary)]">
                        SQLi-<span className="text-[var(--accent-primary)]">PREDATOR</span>
                    </span>
                    <span className="text-[10px] font-semibold text-[var(--text-accent)] bg-[var(--bg-pill-accent)] px-2 py-0.5 rounded-full border-0">
                        v4.0
                    </span>
                </Link>

                <nav className="hidden md:flex items-center gap-6">
                    <Link
                        href="/"
                        className="text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                    >
                        New Scan
                    </Link>
                    <Link
                        href="/scans"
                        className="text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                    >
                        Scan History
                    </Link>
                    <a
                        href="https://github.com/Husk120/sqli-predator-web"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                    >
                        GitHub
                    </a>
                    <button
                        onClick={toggleTheme}
                        aria-label="Toggle theme"
                        className="p-1.5 rounded-full bg-[var(--bg-pill-muted)] text-[var(--text-primary)] hover:opacity-80 transition-all text-sm flex items-center justify-center w-8 h-8 cursor-pointer"
                    >
                        {theme === "light" ? "🌙" : "☀️"}
                    </button>
                </nav>

                <div className="flex items-center gap-2 md:hidden">
                    <button
                        onClick={toggleTheme}
                        aria-label="Toggle theme"
                        className="p-1.5 rounded-full bg-[var(--bg-pill-muted)] text-[var(--text-primary)] text-sm flex items-center justify-center w-8 h-8"
                    >
                        {theme === "light" ? "🌙" : "☀️"}
                    </button>
                    <button
                        className="text-[var(--text-secondary)]"
                        onClick={() => setMobileOpen(!mobileOpen)}
                    >
                        {mobileOpen ? "✕" : "☰"}
                    </button>
                </div>
            </div>

            {mobileOpen && (
                <div className="md:hidden border-t border-[var(--border-subtle)] px-4 py-3 flex flex-col gap-3 bg-[var(--bg-card)]">
                    <Link href="/" className="text-sm text-[var(--text-secondary)]" onClick={() => setMobileOpen(false)}>
                        New Scan
                    </Link>
                    <Link href="/scans" className="text-sm text-[var(--text-secondary)]" onClick={() => setMobileOpen(false)}>
                        Scan History
                    </Link>
                </div>
            )}
        </header>
    );
}
