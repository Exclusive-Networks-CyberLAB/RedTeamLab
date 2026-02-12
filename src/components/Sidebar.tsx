'use client';

import { useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import styles from './Sidebar.module.css';

type SidebarView = 'adversaries' | 'scenarios' | 'campaigns';

interface SidebarProps {
    activeView: SidebarView;
    onViewChange: (view: SidebarView) => void;
}

const NAV_ITEMS: { id: SidebarView; label: string; icon: string }[] = [
    { id: 'adversaries', label: 'ADVERSARIES', icon: '☠' },
    { id: 'scenarios', label: 'SCENARIOS', icon: '⚡' },
    { id: 'campaigns', label: 'CAMPAIGNS', icon: '🎯' },
];

export default function Sidebar({ activeView, onViewChange }: SidebarProps) {
    const [collapsed, setCollapsed] = useState(false);

    return (
        <aside className={`${styles.sidebar} ${collapsed ? styles.collapsed : ''}`}>
            {/* Brand */}
            <div className={styles.brand}>
                <span className={styles.logo}>☠</span>
                <Link href="/" className={styles.logoFull}>RED TEAM LAB</Link>
                <button
                    className={styles.toggle}
                    onClick={() => setCollapsed(!collapsed)}
                    title={collapsed ? 'Expand' : 'Collapse'}
                >
                    {collapsed ? '»' : '«'}
                </button>
            </div>

            {/* Navigation */}
            <nav className={styles.nav}>
                {NAV_ITEMS.map((item) => (
                    <button
                        key={item.id}
                        className={`${styles.navItem} ${activeView === item.id ? styles.active : ''}`}
                        onClick={() => onViewChange(item.id)}
                        title={item.label}
                    >
                        <span className={styles.navIcon}>{item.icon}</span>
                        <span className={styles.navLabel}>{item.label}</span>
                    </button>
                ))}
            </nav>

            {/* Footer */}
            <div className={styles.footer}>
                <span className={styles.footerText}>ADVERSARY EMULATION v2.0</span>
            </div>
        </aside>
    );
}

export type { SidebarView };
