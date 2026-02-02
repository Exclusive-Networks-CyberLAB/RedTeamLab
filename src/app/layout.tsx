import type { Metadata } from 'next';
import './globals.css';
import GlobalHeader from '@/components/GlobalHeader';

export const metadata: Metadata = {
  title: 'Red Team Lab',
  description: 'Adversary Emulation & Breach Simulation',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <GlobalHeader />
        {children}
      </body>
    </html>
  );
}
