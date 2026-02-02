'use client';

import { useEffect, useRef } from 'react';
import styles from './Console.module.css';

interface ConsoleProps {
    logs: string[];
    isRunning: boolean;
}

export default function Console({ logs, isRunning }: ConsoleProps) {
    const bottomRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    return (
        <div className={styles.terminal}>
            <div className={styles.header}>
                <span className={styles.dot} style={{ background: '#ff5f56' }}></span>
                <span className={styles.dot} style={{ background: '#ffbd2e' }}></span>
                <span className={styles.dot} style={{ background: '#27c93f' }}></span>
                <span className={styles.title}>root@kali:~/scenarios</span>
            </div>
            <div className={styles.content}>
                {logs.map((log, i) => (
                    <div key={i} className={styles.line}>
                        <span className={styles.prompt}>$ </span>
                        {log}
                    </div>
                ))}
                {isRunning && (
                    <div className={styles.line}>
                        <span className={`${styles.cursor} mono`}>_</span>
                    </div>
                )}
                <div ref={bottomRef} />
            </div>
        </div>
    );
}
