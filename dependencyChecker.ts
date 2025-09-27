import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as semver from 'semver';
import { DiagnosticsManager } from './diagnosticsManager';
import { SecurityIssueType } from './securityScanner';

interface Dependency {
    name: string;
    currentVersion: string;
    latestVersion?: string;
    hasVulnerabilities?: boolean;
}

export class DependencyChecker {
    constructor(private diagnosticsManager: DiagnosticsManager) {}
    
    public async checkDependencies(): Promise<void> {
        if (!vscode.workspace.workspaceFolders) {
            return;
        }
        
        for (const folder of vscode.workspace.workspaceFolders) {
            // Check for package.json (Node.js)
            const packageJsonPath = path.join(folder.uri.fsPath, 'package.json');
            if (fs.existsSync(packageJsonPath)) {
                await this.checkNodeDependencies(packageJsonPath);
            }
            
            // Check for requirements.txt (Python)
            const requirementsPath = path.join(folder.uri.fsPath, 'requirements.txt');
            if (fs.existsSync(requirementsPath)) {
                await this.checkPythonDependencies(requirementsPath);
            }
        }
    }
    
    private async checkNodeDependencies(packageJsonPath: string): Promise<void> {
        try {
            const packageJsonContent = fs.readFileSync(packageJsonPath, 'utf8');
            const packageJson = JSON.parse(packageJsonContent);
            
            const dependencies: Dependency[] = [];
            
            // Process dependencies
            if (packageJson.dependencies) {
                for (const [name, version] of Object.entries(packageJson.dependencies)) {
                    dependencies.push({
                        name,
                        currentVersion: String(version).replace(/[\^~]/g, '')
                    });
                }
            }
            
            // Process devDependencies
            if (packageJson.devDependencies) {
                for (const [name, version] of Object.entries(packageJson.devDependencies)) {
                    dependencies.push({
                        name,
                        currentVersion: String(version).replace(/[\^~]/g, '')
                    });
                }
            }
            
            // For demonstration, let's mark some common packages as outdated
            // In a real implementation, you would check against an API or database
            const knownVulnerableDependencies = [
                { name: 'lodash', safeVersion: '4.17.21' },
                { name: 'axios', safeVersion: '0.21.2' },
                { name: 'express', safeVersion: '4.17.3' },
                { name: 'minimist', safeVersion: '1.2.6' }
            ];
            
            const diagnostics: vscode.Diagnostic[] = [];
            
            // Check dependencies against known vulnerable versions
            for (const dep of dependencies) {
                const knownVulnerable = knownVulnerableDependencies.find(v => v.name === dep.name);
                if (knownVulnerable) {
                    if (semver.lt(dep.currentVersion, knownVulnerable.safeVersion)) {
                        dep.hasVulnerabilities = true;
                        dep.latestVersion = knownVulnerable.safeVersion;
                        
                        // Find the position of this dependency in the package.json file
                        const regex = new RegExp(`["']${dep.name}["']\\s*:\\s*["']([^"']*)["']`, 'g');
                        const match = regex.exec(packageJsonContent);
                        
                        if (match) {
                            const startPos = match.index;
                            const endPos = startPos + match[0].length;
                            const lineStart = packageJsonContent.lastIndexOf('\n', startPos) + 1;
                            
                            let lineNum = 0;
                            let pos = 0;
                            while (pos < startPos) {
                                pos = packageJsonContent.indexOf('\n', pos) + 1;
                                if (pos === 0) break;
                                lineNum++;
                            }
                            
                            const diagnostic = new vscode.Diagnostic(
                                new vscode.Range(
                                    new vscode.Position(lineNum, startPos - lineStart),
                                    new vscode.Position(lineNum, endPos - lineStart)
                                ),
                                `Outdated dependency: ${dep.name}@${dep.currentVersion} has known vulnerabilities. Update to ${dep.latestVersion}`,
                                vscode.DiagnosticSeverity.Warning
                            );
                            
                            diagnostic.code = 'outdated-dependency';
                            diagnostic.source = 'Security Assistant';
                            (diagnostic as any).securityIssue = {
                                type: SecurityIssueType.OutdatedDependency,
                                message: `Update ${dep.name} to version ${dep.latestVersion} or later`
                            };
                            
                            diagnostics.push(diagnostic);
                        }
                    }
                }
            }
            
            // Set diagnostics for package.json
            if (diagnostics.length > 0) {
                this.diagnosticsManager.setDiagnostics(vscode.Uri.file(packageJsonPath), diagnostics);
            }
        } catch (error) {
            console.error('Error checking Node.js dependencies:', error);
        }
    }
    
    private async checkPythonDependencies(requirementsPath: string): Promise<void> {
        try {
            const requirementsContent = fs.readFileSync(requirementsPath, 'utf8');
            const lines = requirementsContent.split('\n');
            
            const dependencies: Dependency[] = [];
            
            // Parse requirements.txt
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                if (line && !line.startsWith('#')) {
                    // Parse dependency specification (e.g., package==1.0.0)
                    const match = line.match(/^([a-zA-Z0-9_.-]+)([=<>]+)([a-zA-Z0-9_.-]+)/);
                    if (match) {
                        dependencies.push({
                            name: match[1],
                            currentVersion: match[3]
                        });
                    }
                }
            }
            
            // Known vulnerable Python packages (for demonstration)
            const knownVulnerableDependencies = [
                { name: 'django', safeVersion: '3.2.13' },
                { name: 'flask', safeVersion: '2.0.1' },
                { name: 'requests', safeVersion: '2.27.1' },
                { name: 'pyyaml', safeVersion: '6.0' }
            ];
            
            const diagnostics: vscode.Diagnostic[] = [];
            
            // Check dependencies against known vulnerable versions
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                if (line && !line.startsWith('#')) {
                    const match = line.match(/^([a-zA-Z0-9_.-]+)([=<>]+)([a-zA-Z0-9_.-]+)/);
                    if (match) {
                        const name = match[1];
                        const version = match[3];
                        const knownVulnerable = knownVulnerableDependencies.find(v => v.name === name);
                        
                        if (knownVulnerable && semver.lt(version, knownVulnerable.safeVersion)) {
                            const diagnostic = new vscode.Diagnostic(
                                new vscode.Range(i, 0, i, line.length),
                                `Outdated dependency: ${name}@${version} has known vulnerabilities. Update to ${knownVulnerable.safeVersion}`,
                                vscode.DiagnosticSeverity.Warning
                            );
                            
                            diagnostic.code = 'outdated-dependency';
                            diagnostic.source = 'Security Assistant';
                            (diagnostic as any).securityIssue = {
                                type: SecurityIssueType.OutdatedDependency,
                                message: `Update ${name} to version ${knownVulnerable.safeVersion} or later`
                            };
                            
                            diagnostics.push(diagnostic);
                        }
                    }
                }
            }
            
            // Set diagnostics for requirements.txt
            if (diagnostics.length > 0) {
                this.diagnosticsManager.setDiagnostics(vscode.Uri.file(requirementsPath), diagnostics);
            }
        } catch (error) {
            console.error('Error checking Python dependencies:', error);
        }
    }
}