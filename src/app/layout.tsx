import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "The Possessed Butler",
  description: "A tool-using AI agent that resists indirect prompt injection.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
