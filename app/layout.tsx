import type { Metadata } from "next";
import "./globals.css";
import { Header } from "@/components/Header";

export const metadata: Metadata = {
    title: "SQLi-PREDATOR | Advanced SQL Injection Detection",
    description: "Educational SQL injection vulnerability detection engine. Use only on authorized targets.",
    themeColor: "#0a0e14",
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en" className="dark">
            <body className="min-h-screen">
                <Header />
                <main className="max-w-7xl mx-auto px-4 py-6">
                    {children}
                </main>
            </body>
        </html>
    );
}