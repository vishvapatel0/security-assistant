import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { promisify } from 'util';

const execFile = promisify(cp.execFile);

export class SemgrepRunner {
    private semgrepPath: string | null = null;
    
    constructor(private extensionPath: string) {}

    private async findSemgrepPath(): Promise<string> {
        if (this.semgrepPath) {
            return this.semgrepPath;
        }

        const config = vscode.workspace.getConfiguration('securityAssistant');
        const configuredPath = config.get<string>('semgrepPath', 'semgrep');
        
        // First try the configured path
        if (await this.testSemgrepPath(configuredPath)) {
            this.semgrepPath = configuredPath;
            return configuredPath;
        }

        // Try common installation paths on Windows
        const commonPaths = [
            'semgrep',
            'semgrep.exe',
            path.join(process.env.USERPROFILE || '', 'AppData', 'Local', 'Programs', 'Python', 'Python312', 'Scripts', 'semgrep.exe'),
            path.join(process.env.USERPROFILE || '', 'AppData', 'Local', 'Programs', 'Python', 'Python311', 'Scripts', 'semgrep.exe'),
            path.join(process.env.USERPROFILE || '', 'AppData', 'Local', 'Programs', 'Python', 'Python310', 'Scripts', 'semgrep.exe'),
            path.join(process.env.USERPROFILE || '', 'AppData', 'Roaming', 'Python', 'Scripts', 'semgrep.exe'),
            'C:\\Python312\\Scripts\\semgrep.exe',
            'C:\\Python311\\Scripts\\semgrep.exe',
            'C:\\Python310\\Scripts\\semgrep.exe'
        ];

        for (const testPath of commonPaths) {
            if (await this.testSemgrepPath(testPath)) {
                this.semgrepPath = testPath;
                return testPath;
            }
        }

        throw new Error('Semgrep not found. Please install it with "pip install semgrep" or configure the path in settings.');
    }

    private async testSemgrepPath(semgrepPath: string): Promise<boolean> {
        try {
            await execFile(semgrepPath, ['--version']);
            return true;
        } catch (error) {
            return false;
        }
    }

    private getSemgrepPath(): Promise<string> {
        return this.findSemgrepPath();
    }

    private getRulesPath(): string {
        // Get the path to the extension's semgrep rules directory
        return path.join(this.extensionPath, 'rules');
    }

    public async checkSemgrepInstallation(): Promise<boolean> {
        try {
            const semgrepPath = await this.getSemgrepPath();
            const { stdout } = await execFile(semgrepPath, ['--version']);
            console.log(`Semgrep installed: ${stdout.trim()}`);
            return true;
        } catch (error) {
            console.error('Semgrep not installed or not in PATH:', error);
            return false;
        }
    }

    public async runSemgrepOnFile(filePath: string): Promise<any[]> {
        try {
            // Try to find and validate Semgrep installation
            await this.getSemgrepPath();
        } catch (error) {
            vscode.window.showErrorMessage(
                `Semgrep is not installed or not accessible. Please install it with "pip install semgrep" and ensure it's in your PATH. Error: ${error}`
            );
            return [];
        }

        try {
            const semgrepPath = await this.getSemgrepPath();
            const rulesPath = this.getRulesPath();
            
            // Run semgrep with our custom rules and output as JSON
            const { stdout } = await execFile(semgrepPath, [
                '--config', rulesPath,
                '--json',
                filePath
            ]);
            
            // Parse the JSON output
            const results = JSON.parse(stdout);
            return results.results || [];
        } catch (error) {
            console.error('Error running Semgrep:', error);
            throw new Error(`Semgrep scan failed: ${error}`);
        }
    }

    public async createTemporaryFileAndScan(content: string, fileExtension: string): Promise<any[]> {
        const tempDir = path.join(this.extensionPath, 'temp');
        
        // Ensure temp directory exists
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        // Create temporary file
        const tempFile = path.join(tempDir, `temp-${Date.now()}${fileExtension}`);
        fs.writeFileSync(tempFile, content);
        
        try {
            // Scan the temporary file
            const results = await this.runSemgrepOnFile(tempFile);
            return results;
        } finally {
            // Clean up temporary file
            try {
                fs.unlinkSync(tempFile);
            } catch (error) {
                console.error('Error cleaning up temporary file:', error);
            }
        }
    }
}