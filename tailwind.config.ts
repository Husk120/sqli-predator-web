import type { Config } from "tailwindcss";

const config: Config = {
    content: [
        "./app/**/*.{js,ts,jsx,tsx,mdx}",
        "./components/**/*.{js,ts,jsx,tsx,mdx}",
    ],
    theme: {
        extend: {
            colors: {
                surface: {
                    DEFAULT: '#0a0e14',
                    card: '#161b22',
                    border: '#21262d',
                    hover: '#1c2333',
                },
                accent: {
                    blue: '#58a6ff',
                    green: '#3fb950',
                    orange: '#d29922',
                    red: '#f85149',
                    purple: '#bc8cff',
                },
            },
        },
    },
    plugins: [],
};

export default config;
