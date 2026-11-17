import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SNAKE | Security Operations",
  description: "AI-assisted authorized security assessment platform"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
