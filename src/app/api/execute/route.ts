import { NextResponse } from 'next/server';
import { exec } from 'child_process';
import path from 'path';
import { promisify } from 'util';
import os from 'os';

const execAsync = promisify(exec);

export async function POST(request: Request) {
    try {
        const { scriptPath, c2Host, params } = await request.json();

        if (!scriptPath) {
            return NextResponse.json({ error: 'No script path provided' }, { status: 400 });
        }

        // Security: Minimize injection risk
        const safePath = path.normalize(scriptPath).replace(/^(\.\.(\/|\\|$))+/, '');
        const fullPath = path.join(process.cwd(), 'src', safePath);

        // Determine Environment
        const isWindows = os.platform() === 'win32';

        // Build parameter string for PowerShell
        let paramString = '';
        if (params && typeof params === 'object') {
            for (const [key, value] of Object.entries(params)) {
                if (value && typeof value === 'string') {
                    // Sanitize parameter values - escape quotes
                    const safeValue = String(value).replace(/"/g, '`"').replace(/'/g, "''");
                    paramString += ` -${key} "${safeValue}"`;
                }
            }
        }

        console.log(`[API] Executing: ${fullPath}${paramString} with C2: ${c2Host}`);

        let command = '';

        if (isWindows) {
            // Windows Execution with parameters
            command = `powershell -NoProfile -ExecutionPolicy Bypass -File "${fullPath}"${paramString}`;
        } else {
            // Dev/Mac Simulation using pwsh if available
            command = `if command -v pwsh &> /dev/null; then pwsh -File "${fullPath}"${paramString}; else echo "Warning: Non-Windows Host. Simulated Success for: ${safePath}"; fi`;
        }

        const { stdout, stderr } = await execAsync(command, {
            env: { ...process.env, C2_HOST: c2Host || '127.0.0.1' },
            shell: isWindows ? 'powershell.exe' : '/bin/bash'
        });

        // Read Script Content for Verbose Output
        let scriptContent = '';
        try {
            // We can use fs.promises here. Imported path, os, exec, but need fs.
            // Adding fs import to the top of file later in a valid way, but for now using require or expecting it?
            // Actually, I should check imports. I'll use imports provided.
            // Wait, I need to add 'import fs from 'fs/promises';' or similar. 
            // Since I can't easily see imports again without scrolling, I'll assume I need to add it or use 'require'.
            // But existing code uses import. I will modify imports in a separate edit or just use require('fs').promises.
            const fs = require('fs').promises;
            scriptContent = await fs.readFile(fullPath, 'utf8');
        } catch (e) {
            console.error("Failed to read script content", e);
            scriptContent = "# Failed to read script content.";
        }

        return NextResponse.json({
            success: true,
            output: stdout,
            error: stderr,
            scriptContent: scriptContent
        });

    } catch (error: any) {
        console.error('Execution Error:', error);
        return NextResponse.json({
            success: false,
            error: error.message
        }, { status: 500 });
    }
}
