'use client';

import { useState, useEffect } from 'react';

export default function GlobalHeader() {
    const [c2, setC2] = useState('');
    const [targetIp, setTargetIp] = useState('');
    const [ipError, setIpError] = useState(false);

    useEffect(() => {
        const savedC2 = localStorage.getItem('c2_host');
        if (savedC2) setC2(savedC2);

        const savedIp = localStorage.getItem('target_ip');
        if (savedIp) setTargetIp(savedIp);
        else setTargetIp('127.0.0.1');
    }, []);

    const handleC2Change = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newVal = e.target.value;
        setC2(newVal);
        localStorage.setItem('c2_host', newVal);
    };

    const handleIpChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newVal = e.target.value;
        setTargetIp(newVal);

        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

        if (newVal === 'localhost' || ipRegex.test(newVal)) {
            setIpError(false);
            localStorage.setItem('target_ip', newVal);
        } else {
            setIpError(true);
        }
    };

    return (
        <header style={{
            display: 'flex',
            justifyContent: 'flex-end',
            alignItems: 'center',
            padding: '0.75rem 2rem',
            borderBottom: '1px solid var(--border)',
            background: 'var(--background)',
            position: 'sticky',
            top: 0,
            zIndex: 100
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                {/* Target IP Input */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <label className="mono text-secondary" style={{ fontSize: '0.8rem' }}>TARGET IP:</label>
                        <input
                            type="text"
                            value={targetIp}
                            onChange={handleIpChange}
                            placeholder="127.0.0.1"
                            className="mono"
                            style={{
                                background: 'var(--surface)',
                                border: `1px solid ${ipError ? 'var(--danger)' : 'var(--border)'}`,
                                color: ipError ? 'var(--danger)' : 'var(--primary)',
                                padding: '0.25rem 0.5rem',
                                borderRadius: '4px',
                                outline: 'none',
                                fontSize: '0.9rem',
                                width: '140px',
                                textAlign: 'right'
                            }}
                        />
                    </div>
                    {ipError && <span className="mono text-danger" style={{ fontSize: '0.7rem' }}>Invalid IP Syntax</span>}
                </div>

                {/* C2 Server Input */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <label className="mono text-secondary" style={{ fontSize: '0.8rem' }}>C2 HOST:</label>
                    <input
                        type="text"
                        value={c2}
                        onChange={handleC2Change}
                        placeholder="evil.corp"
                        className="mono"
                        style={{
                            background: 'var(--surface)',
                            border: '1px solid var(--border)',
                            color: 'var(--primary)',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '4px',
                            outline: 'none',
                            fontSize: '0.9rem',
                            width: '180px'
                        }}
                    />
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: c2 ? 'var(--primary)' : 'var(--danger)', boxShadow: c2 ? '0 0 5px var(--primary)' : 'none' }}></div>
                </div>
            </div>
        </header>
    );
}
