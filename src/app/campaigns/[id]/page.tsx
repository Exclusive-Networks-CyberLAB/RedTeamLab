'use client';

import { useState, use, useEffect } from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { CAMPAIGNS, SCENARIOS, Scenario } from '@/lib/types';
import Console from '@/components/Console';
import styles from '@/app/scenario/[id]/Scenario.module.css'; // Reusing scenario styles

export default function CampaignDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const campaign = CAMPAIGNS.find((c) => c.id === id);

    const [isRunning, setIsRunning] = useState(false);
    const [currentStepIndex, setCurrentStepIndex] = useState(-1);
    const [logs, setLogs] = useState<string[]>([]);

    if (!campaign) notFound();

    const handleExecute = async () => {
        setIsRunning(true);
        setCurrentStepIndex(0);
        setLogs([]);

        // Get Config
        const c2Host = localStorage.getItem('c2_host');
        const targetIp = localStorage.getItem('target_ip');

        setLogs(p => [...p, `[INFO] Initializing Campaign: ${campaign.name}`, `[INFO] Target: ${targetIp}`, `[INFO] C2: ${c2Host}`]);

        // Sequential Execution
        for (let i = 0; i < campaign.steps.length; i++) {
            const stepId = campaign.steps[i];
            const scenario = SCENARIOS.find(s => s.id === stepId);

            if (!scenario) {
                setLogs(p => [...p, `[ERROR] Scenario ID ${stepId} not found. Skipping.`]);
                continue;
            }

            setCurrentStepIndex(i);
            setLogs(p => [...p, `\n[*] STEP ${i + 1}/${campaign.steps.length}: ${scenario.name} (${scenario.mitreTechniques[0].id})...`]);

            try {
                const response = await fetch('/api/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        scriptPath: scenario.scriptPath,
                        c2Host: c2Host,
                        targetIp: targetIp
                    }),
                });

                const data = await response.json();

                if (data.success) {
                    const lines = data.output.split('\n').filter((l: string) => l);
                    setLogs(prev => [...prev, ...lines]);
                } else {
                    setLogs(prev => [...prev, `[ERROR] ${data.error}`]);
                }
            } catch (e) {
                setLogs(prev => [...prev, `[ERROR] API Failure: ${e}`]);
            }

            // Small delay between steps for realism
            await new Promise(r => setTimeout(r, 2000));
        }

        setLogs(p => [...p, `\n[+] Campaign Execution Completed.`]);
        setIsRunning(false);
        setCurrentStepIndex(-1);
    };

    return (
        <main className={styles.container} style={{ animation: 'fadeIn 0.3s ease' }}>
            <Link href="/campaigns" className={styles.backLink}>← Back to Campaigns</Link>

            <header className={styles.header}>
                <div className={styles.meta}>
                    <span className="badge" style={{ color: 'var(--warning)', borderColor: 'var(--warning)' }}>[{campaign.adversary}]</span>
                    <span className="mono text-dim">{campaign.steps.length} PHASES</span>
                </div>
                <h1 className="mono text-primary glow-text" style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>{campaign.name}</h1>
                <p className="text-dim">{campaign.description}</p>
            </header>

            <section className="section-card" style={{ marginBottom: '2rem' }}>
                <h3>CAMPAIGN OPERATIONS CHAIN</h3>
                <div style={{ display: 'grid', gap: '0.5rem' }}>
                    {campaign.steps.map((stepId, index) => {
                        const s = SCENARIOS.find(x => x.id === stepId);
                        const isActive = index === currentStepIndex;
                        const isDone = index < currentStepIndex || (currentStepIndex === -1 && logs.length > 0 && isRunning === false);

                        return (
                            <div key={index} className={`accent-item ${isActive ? 'active' : ''}`}
                                style={{
                                    borderLeftColor: isDone ? '#ff6b35' : isActive ? 'var(--primary)' : 'var(--border)',
                                    opacity: (isRunning && !isActive && !isDone) ? 0.5 : 1
                                }}>
                                <span className="mono text-dim" style={{ marginRight: '1rem' }}>{index + 1}.</span>
                                <span className="mono" style={{ color: isActive ? 'var(--primary)' : 'var(--text-main)' }}>
                                    {s?.name || stepId}
                                </span>
                                {isDone && <span className="tag" style={{ float: 'right', background: 'rgba(255, 107, 53, 0.2)', color: '#ff6b35', borderColor: '#ff6b35' }}>COMPLETED</span>}
                                {isActive && <span className="tag" style={{ float: 'right' }}>EXECUTING</span>}
                            </div>
                        );
                    })}
                </div>
            </section>

            <div className={styles.controls}>
                <button
                    className="btn"
                    onClick={handleExecute}
                    disabled={isRunning}
                    style={{ opacity: isRunning ? 0.5 : 1 }}
                >
                    {isRunning ? 'CAMPAIGN IN PROGRESS...' : 'EXECUTE CAMPAIGN'}
                </button>
            </div>

            <Console logs={logs} isRunning={isRunning} />
        </main>
    );
}

