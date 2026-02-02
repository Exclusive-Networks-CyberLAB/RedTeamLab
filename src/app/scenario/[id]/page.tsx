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
        <main className={styles.container}>
            <Link href="/" className={styles.backLink}>← Back to Dashboard</Link>

            <header className={styles.header}>
                <div className={styles.meta}>
                    <span className="mono text-secondary">[{scenario.adversary}]</span>
                    <span className="mono text-dim">{scenario.difficulty}</span>
                    <span className="mono text-dim">{scenario.estimatedDuration}</span>
                </div>
                <h1 className={`mono ${styles.title}`}>{scenario.name}</h1>
                <p className="text-dim">{scenario.description}</p>
            </header>

            <section className={styles.mitreSection}>
                <h3 className="mono text-primary" style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>MITRE ATT&CK MAPPING</h3>
                <ul>
                    {scenario.mitreTechniques.map(t => (
                        <li key={t.id} className="mono text-dim" style={{ fontSize: '0.9rem', marginBottom: '0.25rem' }}>
                            <a href={t.url} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'underline' }}>
                                {t.id}: {t.name}
                            </a>
                        </li>
                    ))}
                </ul>
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
