'use client';

import { useState, use } from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { SCENARIOS } from '@/lib/types';
import Console from '@/components/Console';
import styles from './Scenario.module.css';

export default function ScenarioPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const scenario = SCENARIOS.find((s) => s.id === id);

    const [isRunning, setIsRunning] = useState(false);
    const [logs, setLogs] = useState<string[]>([]);

    if (!scenario) {
        notFound();
    }

    const handleExecute = async () => {
        setIsRunning(true);
        const c2Host = localStorage.getItem('c2_host');

        if (!c2Host) {
            setLogs(prev => [...prev, '[!] WARNING: No C2 Server set. Please configure in header.']);
        }

        setLogs((prev) => [...prev, `[INFO] Initializing ${scenario.name}...`, `[INFO] Adversary Infrastructure: ${c2Host || 'Unknown'}`]);

        try {
            const response = await fetch('/api/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scriptPath: scenario.scriptPath,
                    c2Host: c2Host
                }),
            });

            const data = await response.json();

            if (data.success) {
                const logsToAdd: string[] = [];
                if (data.scriptContent) {
                    logsToAdd.push('[*] SCRIPT CONTENT EXECUTION PLAN:', '----------------------------------------');
                    logsToAdd.push(...data.scriptContent.split('\n'));
                    logsToAdd.push('----------------------------------------');
                }
                const lines = data.output.split('\n').filter((l: string) => l);
                logsToAdd.push(...lines, '[+] Execution Completed Successfully.');

                setLogs(prev => [...prev, ...logsToAdd]);
            } else {
                setLogs(prev => [...prev, `[ERROR] ${data.error}`]);
            }

        } catch (error) {
            setLogs(prev => [...prev, `[ERROR] Execution failed: ${error}`]);
        } finally {
            setIsRunning(false);
        }
    };

    return (
        <main className={styles.container} style={{ animation: 'fadeIn 0.3s ease' }}>
            <Link href="/" className={styles.backLink}>← Back to Dashboard</Link>

            <header className={styles.header}>
                <div className={styles.meta}>
                    <span className="badge" style={{ color: 'var(--secondary)', borderColor: 'var(--secondary)' }}>[{scenario.adversary}]</span>
                    <span className="mono text-dim">{scenario.difficulty}</span>
                    <span className="mono text-dim">{scenario.estimatedDuration}</span>
                </div>
                <h1 className="mono text-primary glow-text" style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>{scenario.name}</h1>
                <p className="text-dim">{scenario.description}</p>
            </header>

            <section className="section-card" style={{ marginBottom: '2rem' }}>
                <h3>MITRE ATT&CK MAPPING</h3>
                <div style={{ display: 'grid', gap: '0.5rem' }}>
                    {scenario.mitreTechniques.map(t => (
                        <div key={t.id} className="accent-item">
                            <a href={t.url} target="_blank" rel="noopener noreferrer"
                                className="mono" style={{ color: 'var(--text-main)', textDecoration: 'none' }}>
                                <span className="text-primary" style={{ marginRight: '0.5rem' }}>{t.id}</span>
                                {t.name}
                            </a>
                        </div>
                    ))}
                </div>
            </section>

            <div className={styles.controls}>
                <button
                    className="btn"
                    onClick={handleExecute}
                    disabled={isRunning}
                    style={{ opacity: isRunning ? 0.5 : 1 }}
                >
                    {isRunning ? 'EXECUTING...' : 'EXECUTE SCENARIO'}
                </button>
            </div>

            <Console logs={logs} isRunning={isRunning} />
        </main>
    );
}
