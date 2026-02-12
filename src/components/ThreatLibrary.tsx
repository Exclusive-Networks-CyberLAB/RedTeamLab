'use client';

import { useState } from 'react';
import { THREAT_ACTORS, AttributedTTP, TTPInputParam } from '@/lib/types';

// Input validation functions
const validators: Record<TTPInputParam['type'], (value: string) => boolean> = {
    ip: (v) => /^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every(n => parseInt(n) <= 255),
    hostname: (v) => /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})*$/.test(v),
    url: (v) => /^https?:\/\/.+/.test(v),
    domain: (v) => /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(v),
    subnet: (v) => /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v),
    text: () => true
};

export default function ThreatLibrary() {
    const [selectedActorId, setSelectedActorId] = useState<string | null>(null);
    const [runningTTP, setRunningTTP] = useState<string | null>(null);
    const [revertingTTP, setRevertingTTP] = useState<string | null>(null);
    const [output, setOutput] = useState<Record<string, string>>({});
    const [executedTTPs, setExecutedTTPs] = useState<Set<string>>(new Set());
    const [inputValues, setInputValues] = useState<Record<string, Record<string, string>>>({});
    const [inputErrors, setInputErrors] = useState<Record<string, Record<string, boolean>>>({});

    const selectedActor = THREAT_ACTORS.find(a => a.id === selectedActorId);

    const validateInputs = (ttp: AttributedTTP): boolean => {
        if (!ttp.inputParams) return true;

        const errors: Record<string, boolean> = {};
        let valid = true;

        for (const param of ttp.inputParams) {
            const value = inputValues[ttp.id]?.[param.name] || '';
            if (param.required && !value) {
                errors[param.name] = true;
                valid = false;
            } else if (value && !validators[param.type](value)) {
                errors[param.name] = true;
                valid = false;
            }
        }

        setInputErrors(prev => ({ ...prev, [ttp.id]: errors }));
        return valid;
    };

    const executeTTP = async (ttp: AttributedTTP) => {
        if (!ttp.scriptPath) return;
        if (!validateInputs(ttp)) return;

        setRunningTTP(ttp.id);

        try {
            const params: Record<string, string> = {};
            if (ttp.inputParams) {
                for (const param of ttp.inputParams) {
                    params[param.name] = inputValues[ttp.id]?.[param.name] || '';
                }
            }

            const res = await fetch('/api/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scriptPath: ttp.scriptPath,
                    params
                })
            });
            const data = await res.json();
            setOutput(prev => ({ ...prev, [ttp.id]: data.output || data.error }));
            setExecutedTTPs(prev => new Set(prev).add(ttp.id));
        } catch (e) {
            setOutput(prev => ({ ...prev, [ttp.id]: 'Failed to execute TTP.' }));
        } finally {
            setRunningTTP(null);
        }
    };

    const revertTTP = async (ttp: AttributedTTP) => {
        if (!ttp.revertScriptPath) return;

        setRevertingTTP(ttp.id);

        try {
            const res = await fetch('/api/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scriptPath: ttp.revertScriptPath,
                    params: {}
                })
            });
            const data = await res.json();
            setOutput(prev => ({
                ...prev,
                [ttp.id]: `[REVERT OUTPUT]\n${data.output || data.error}`
            }));
            setExecutedTTPs(prev => {
                const next = new Set(prev);
                next.delete(ttp.id);
                return next;
            });
        } catch (e) {
            setOutput(prev => ({ ...prev, [ttp.id]: 'Failed to revert TTP.' }));
        } finally {
            setRevertingTTP(null);
        }
    };

    const handleInputChange = (ttpId: string, paramName: string, value: string) => {
        setInputValues(prev => ({
            ...prev,
            [ttpId]: { ...(prev[ttpId] || {}), [paramName]: value }
        }));
        // Clear error when user types
        if (inputErrors[ttpId]?.[paramName]) {
            setInputErrors(prev => ({
                ...prev,
                [ttpId]: { ...(prev[ttpId] || {}), [paramName]: false }
            }));
        }
    };

    if (selectedActor) {
        return (
            <div style={{ animation: 'fadeIn 0.3s ease' }}>
                <button
                    onClick={() => setSelectedActorId(null)}
                    className="btn"
                    style={{ marginBottom: '1rem', padding: '0.5rem 1rem' }}
                >
                    ← BACK TO LIBRARY
                </button>

                <div className="card" style={{ border: '1px solid var(--primary)', boxShadow: '0 0 15px rgba(255, 26, 26, 0.1)' }}>
                    <h1 className="mono text-primary" style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>
                        {selectedActor.name}
                    </h1>
                    {selectedActor.aliases.length > 0 && (
                        <p className="mono text-dim" style={{ marginBottom: '1rem' }}>
                            ALIASES: {selectedActor.aliases.join(', ')}
                        </p>
                    )}
                    <p style={{ lineHeight: '1.6', marginBottom: '2rem', fontSize: '1.1rem' }}>
                        {selectedActor.description}
                    </p>

                    <h3 className="mono" style={{ borderBottom: '1px solid #333', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
                        ATTRIBUTED TTPs
                    </h3>

                    <div style={{ display: 'grid', gap: '1rem' }}>
                        {selectedActor.ttps.map((ttp) => (
                            <div key={ttp.id} style={{
                                background: 'rgba(255,255,255,0.03)',
                                padding: '1rem',
                                borderLeft: `2px solid ${executedTTPs.has(ttp.id) ? '#ff6b35' : 'var(--primary)'}`
                            }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                                    <span className="mono text-primary" style={{ fontWeight: 'bold' }}>{ttp.id}</span>
                                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                                        <span className="mono text-dim" style={{ fontSize: '0.8rem' }}>{ttp.tactic.toUpperCase()}</span>
                                        {executedTTPs.has(ttp.id) && (
                                            <span style={{
                                                background: '#ff6b35',
                                                color: '#000',
                                                padding: '0.1rem 0.4rem',
                                                fontSize: '0.7rem',
                                                fontWeight: 'bold'
                                            }}>EXECUTED</span>
                                        )}
                                    </div>
                                </div>
                                <h4 style={{ marginBottom: '0.5rem' }}>{ttp.technique}</h4>
                                <p className="text-dim" style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>{ttp.description}</p>

                                <div className="code-block" style={{
                                    background: '#000',
                                    padding: '0.5rem',
                                    fontFamily: 'monospace',
                                    fontSize: '0.8rem',
                                    color: '#0f0',
                                    marginBottom: '1rem',
                                    overflowX: 'auto'
                                }}>
                                    {ttp.commandSnippet}
                                </div>

                                {/* Input Parameters */}
                                {ttp.inputParams && ttp.inputParams.length > 0 && (
                                    <div style={{ marginBottom: '1rem', display: 'grid', gap: '0.5rem' }}>
                                        {ttp.inputParams.map((param) => (
                                            <div key={param.name}>
                                                <label className="mono text-dim" style={{ fontSize: '0.8rem', display: 'block', marginBottom: '0.25rem' }}>
                                                    {param.label} {param.required && <span style={{ color: '#ff3333' }}>*</span>}
                                                </label>
                                                <input
                                                    type="text"
                                                    placeholder={param.placeholder}
                                                    value={inputValues[ttp.id]?.[param.name] || ''}
                                                    onChange={(e) => handleInputChange(ttp.id, param.name, e.target.value)}
                                                    style={{
                                                        width: '100%',
                                                        padding: '0.5rem',
                                                        background: '#111',
                                                        border: `1px solid ${inputErrors[ttp.id]?.[param.name] ? '#ff3333' : '#333'}`,
                                                        color: '#fff',
                                                        fontFamily: 'monospace',
                                                        fontSize: '0.85rem'
                                                    }}
                                                />
                                                {inputErrors[ttp.id]?.[param.name] && (
                                                    <span style={{ color: '#ff3333', fontSize: '0.75rem' }}>
                                                        Invalid {param.type} format
                                                    </span>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {/* Execute / Revert Buttons */}
                                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                                    {ttp.scriptPath && (
                                        <button
                                            onClick={() => executeTTP(ttp)}
                                            className="btn"
                                            disabled={runningTTP === ttp.id}
                                            style={{ fontSize: '0.8rem', padding: '0.3rem 0.8rem' }}
                                        >
                                            {runningTTP === ttp.id ? 'EXECUTING...' : 'EXECUTE'}
                                        </button>
                                    )}

                                    {ttp.revertScriptPath && executedTTPs.has(ttp.id) && (
                                        <button
                                            onClick={() => revertTTP(ttp)}
                                            disabled={revertingTTP === ttp.id}
                                            style={{
                                                fontSize: '0.8rem',
                                                padding: '0.3rem 0.8rem',
                                                background: '#ff6b35',
                                                color: '#000',
                                                border: 'none',
                                                cursor: 'pointer',
                                                fontWeight: 'bold'
                                            }}
                                        >
                                            {revertingTTP === ttp.id ? 'REVERTING...' : 'REVERT'}
                                        </button>
                                    )}

                                    {!ttp.scriptPath && (
                                        <span className="text-dim mono" style={{ fontSize: '0.8rem' }}>PENDING IMPLEMENTATION</span>
                                    )}
                                </div>

                                {output[ttp.id] && (
                                    <div style={{ marginTop: '1rem', background: '#111', padding: '0.5rem', border: '1px solid #333' }}>
                                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: '0.8rem', color: '#ccc' }}>
                                            {output[ttp.id]}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1.5rem' }}>
                {THREAT_ACTORS.map((actor) => (
                    <div
                        key={actor.id}
                        className="card"
                        style={{
                            cursor: 'pointer',
                            transition: 'transform 0.2s',
                            border: '1px solid #333'
                        }}
                        onClick={() => setSelectedActorId(actor.id)}
                        onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--primary)')}
                        onMouseLeave={(e) => (e.currentTarget.style.borderColor = '#333')}
                    >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                            <span className="mono text-primary" style={{ fontSize: '1.2rem' }}>{actor.name}</span>
                        </div>
                        <p className="text-dim" style={{ fontSize: '0.9rem', lineHeight: '1.5' }}>
                            {actor.description.substring(0, 100)}...
                        </p>
                        <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem' }}>
                            <span className="tag">{actor.ttps.length} TTPs</span>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
