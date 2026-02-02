'use client';

import Link from 'next/link';
import { CAMPAIGNS } from '@/lib/types';
import styles from '../page.module.css'; // Reusing dashboard styles

export default function CampaignsPage() {
    return (
        <main className="container">
            <header className={styles.header}>
                <div>
                    <h1 className="mono glow-text" style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>
                        ADVERSARY CAMPAIGNS
                    </h1>
                    <p className="text-dim mono">
                        End-to-End Attack Simulations // Multi-Stage TTPs
                    </p>
                </div>
            </header>

            <div className={styles.scenariosGrid}>
                {CAMPAIGNS.map((campaign) => (
                    <div key={campaign.id} className="card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '1rem' }}>
                            <span className={`mono ${styles.badge}`} style={{ color: 'var(--warning)', borderColor: 'var(--warning)' }}>{campaign.adversary}</span>
                            <span className="text-dim mono" style={{ fontSize: '0.8rem' }}>{campaign.steps.length} STEPS</span>
                        </div>

                        <h2 className="mono text-primary" style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>
                            {campaign.name}
                        </h2>
                        <p className="text-dim" style={{ fontSize: '0.9rem', marginBottom: '1.5rem', lineHeight: '1.6', minHeight: '3em' }}>
                            {campaign.description}
                        </p>

                        <div style={{ marginBottom: '1.5rem' }}>
                            <p className="mono text-dim" style={{ fontSize: '0.75rem', marginBottom: '0.5rem' }}>ATTACK CHAIN:</p>
                            <div className="mono text-dim" style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                                {campaign.steps.map((step, i) => (
                                    <span key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ color: 'var(--primary)' }}>↓</span> {step}
                                    </span>
                                ))}
                            </div>
                        </div>

                        <Link href={`/campaigns/${campaign.id}`} className="btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none' }}>
                            INITIATE CAMPAIGN
                        </Link>
                    </div>
                ))}
            </div>
        </main>
    );
}
