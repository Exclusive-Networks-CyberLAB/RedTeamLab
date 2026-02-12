'use client';

import { useState, Suspense } from 'react';
import Link from 'next/link';
import { SCENARIOS, CAMPAIGNS } from '@/lib/types';
import styles from './page.module.css';
import ThreatLibrary from '@/components/ThreatLibrary';
import Sidebar, { SidebarView } from '@/components/Sidebar';
import GlobalHeader from '@/components/GlobalHeader';

function ScenariosView() {
  return (
    <section style={{ animation: 'fadeIn 0.3s ease' }}>
      <header style={{ marginBottom: '2rem', borderBottom: '1px solid #333', paddingBottom: '1rem' }}>
        <h1 className="mono text-primary glow-text" style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>
          GUIDED SCENARIOS
        </h1>
        <p className="text-dim mono">
          Atomic Attack Simulations // Individual TTPs
        </p>
      </header>
      <div className={styles.scenariosGrid}>
        {SCENARIOS.map((scenario) => (
          <div key={scenario.id} className="card" style={{ border: '1px solid #333' }}
            onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--primary)')}
            onMouseLeave={(e) => (e.currentTarget.style.borderColor = '#333')}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <span className="badge" style={{ color: 'var(--secondary)', borderColor: 'var(--secondary)' }}>{scenario.adversary}</span>
              <span className="mono text-dim" style={{ fontSize: '0.8rem' }}>{scenario.difficulty}</span>
            </div>

            <h2 className="mono text-primary" style={{ fontSize: '1.2rem', marginBottom: '0.5rem' }}>
              {scenario.name}
            </h2>
            <p className="text-dim" style={{ fontSize: '0.9rem', marginBottom: '1.5rem', lineHeight: '1.5' }}>
              {scenario.description.substring(0, 120)}...
            </p>

            <div style={{ marginBottom: '1.5rem' }}>
              <p className="mono text-dim" style={{ fontSize: '0.75rem', marginBottom: '0.5rem' }}>MITRE ATT&CK:</p>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {scenario.mitreTechniques.map((tech) => (
                  <span key={tech.id} className="tag" title={tech.name}>
                    {tech.id}
                  </span>
                ))}
              </div>
            </div>

            <Link href={`/scenario/${scenario.id}`} className="btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none' }}>
              INITIALIZE
            </Link>
          </div>
        ))}
      </div>
    </section>
  );
}

function CampaignsView() {
  return (
    <section style={{ animation: 'fadeIn 0.3s ease' }}>
      <header style={{ marginBottom: '2rem', borderBottom: '1px solid #333', paddingBottom: '1rem' }}>
        <h1 className="mono text-primary glow-text" style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>
          ADVERSARY CAMPAIGNS
        </h1>
        <p className="text-dim mono">
          End-to-End Attack Simulations // Multi-Stage TTPs
        </p>
      </header>
      <div className={styles.scenariosGrid}>
        {CAMPAIGNS.map((campaign) => (
          <div key={campaign.id} className="card" style={{ border: '1px solid #333' }}
            onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--primary)')}
            onMouseLeave={(e) => (e.currentTarget.style.borderColor = '#333')}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <span className="badge" style={{ color: 'var(--warning)', borderColor: 'var(--warning)' }}>{campaign.adversary}</span>
              <span className="mono text-dim" style={{ fontSize: '0.8rem' }}>{campaign.steps.length} STEPS</span>
            </div>

            <h2 className="mono text-primary" style={{ fontSize: '1.2rem', marginBottom: '0.5rem' }}>
              {campaign.name}
            </h2>
            <p className="text-dim" style={{ fontSize: '0.9rem', marginBottom: '1.5rem', lineHeight: '1.5', minHeight: '3em' }}>
              {campaign.description.substring(0, 100)}...
            </p>

            <div style={{ marginBottom: '1.5rem' }}>
              <p className="mono text-dim" style={{ fontSize: '0.75rem', marginBottom: '0.5rem' }}>ATTACK CHAIN:</p>
              <div style={{ display: 'grid', gap: '0.25rem' }}>
                {campaign.steps.slice(0, 4).map((step, i) => (
                  <div key={i} className="accent-item" style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}>
                    <span className="text-primary mono" style={{ marginRight: '0.5rem' }}>↓</span>
                    <span className="mono text-dim">{step}</span>
                  </div>
                ))}
                {campaign.steps.length > 4 && (
                  <span className="mono text-dim" style={{ fontSize: '0.75rem', paddingLeft: '0.75rem' }}>
                    +{campaign.steps.length - 4} more steps...
                  </span>
                )}
              </div>
            </div>

            <Link href={`/campaigns/${campaign.id}`} className="btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none' }}>
              INITIATE CAMPAIGN
            </Link>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function Home() {
  const [activeView, setActiveView] = useState<SidebarView>('adversaries');

  return (
    <>
      <Sidebar activeView={activeView} onViewChange={setActiveView} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <GlobalHeader />
        <main className="container" style={{ flex: 1, overflowY: 'auto' }}>
          {activeView === 'adversaries' && <ThreatLibrary />}
          {activeView === 'scenarios' && <ScenariosView />}
          {activeView === 'campaigns' && <CampaignsView />}
        </main>
      </div>
    </>
  );
}
