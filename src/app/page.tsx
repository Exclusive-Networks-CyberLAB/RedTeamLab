'use client';

import { useState } from 'react';
import Link from 'next/link';
import { SCENARIOS } from '@/lib/types';
import styles from './page.module.css';
import ThreatLibrary from '@/components/ThreatLibrary';

export default function Home() {
  const [activeTab, setActiveTab] = useState<'threats' | 'scenarios'>('threats');

  return (
    <main className="container">
      <div style={{
        display: 'flex',
        gap: '2rem',
        marginBottom: '2rem',
        borderBottom: '1px solid #333',
        paddingBottom: '1rem'
      }}>
        <button
          onClick={() => setActiveTab('threats')}
          className="mono"
          style={{
            background: 'none',
            border: 'none',
            color: activeTab === 'threats' ? 'var(--primary)' : '#666',
            fontSize: '1.2rem',
            cursor: 'pointer',
            padding: '0.5rem 0',
            borderBottom: activeTab === 'threats' ? '2px solid var(--primary)' : '2px solid transparent',
            transition: 'all 0.2s'
          }}
        >
          THREAT LIBRARY
        </button>
        <button
          onClick={() => setActiveTab('scenarios')}
          className="mono"
          style={{
            background: 'none',
            border: 'none',
            color: activeTab === 'scenarios' ? 'var(--primary)' : '#666',
            fontSize: '1.2rem',
            cursor: 'pointer',
            padding: '0.5rem 0',
            borderBottom: activeTab === 'scenarios' ? '2px solid var(--primary)' : '2px solid transparent',
            transition: 'all 0.2s'
          }}
        >
          GUIDED SCENARIOS
        </button>
      </div>

      {activeTab === 'threats' ? (
        <ThreatLibrary />
      ) : (
        <section style={{ animation: 'fadeIn 0.3s ease' }}>
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
      )}
    </main>
  );
}
