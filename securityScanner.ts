import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import { DiagnosticsManager } from './diagnosticsManager';

export enum SecurityIssueType {
  HardcodedSecret = 'hardcoded-secret',
  SqlInjection = 'sql-injection',
  CommandInjection = 'command-injection',
  MissingAuth = 'missing-auth',
  WeakCrypto = 'weak-crypto',
  InsecureRandom = 'insecure-random',
  OutdatedDependency = 'outdated-dependency'
}

export interface SecurityIssue {
  message: string;
  severity: vscode.DiagnosticSeverity;
  range: vscode.Range;
  code: string;
  source: string;
  fix?: {
    title: string;
    edits: vscode.TextEdit[];
  };
}

export class SecurityScanner {
  constructor(private diagnosticsManager: DiagnosticsManager) {}

  async scanFile(document: vscode.TextDocument): Promise<void> {
    try {
      // Skip scanning for unsupported file types
      const supportedLanguages = ['javascript', 'typescript', 'python', 'json'];
      if (!supportedLanguages.includes(document.languageId)) {
        return;
      }

      vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Scanning for security issues...",
        cancellable: false
      }, async () => {
        // First clear previous diagnostics for this file
        this.diagnosticsManager.clearDiagnostics(document.uri);
        
        // Get the semgrep executable path from settings
        const config = vscode.workspace.getConfiguration('securityAssistant');
        const semgrepPath = config.get<string>('semgrepPath') || 'semgrep';
        
        let issues: SecurityIssue[] = [];
        
        // Force pattern-based scanning for reliability (Semgrep might not be available)
        console.log('Using pattern-based security scanning');
        issues = await this.runPatternBasedScan(document);
        
        // Also try Semgrep if available (optional)
        try {
          await this.checkSemgrepInstallation(semgrepPath);
          console.log('Semgrep also available, running additional scan');
          const semgrepIssues = await this.runSemgrepScan(document, semgrepPath);
          issues = [...issues, ...semgrepIssues];
        } catch (error) {
          console.log('Semgrep not available, pattern-based scan only');
        }
        
        // Update diagnostics
        this.diagnosticsManager.updateDiagnostics(document.uri, issues.map(issue => this.convertToVscodeDiagnostic(issue)));
        
        // Show status message
        if (issues.length > 0) {
          vscode.window.showWarningMessage(`Found ${issues.length} security issues in ${path.basename(document.uri.fsPath)}`);
        } else {
          vscode.window.showInformationMessage(`No security issues found in ${path.basename(document.uri.fsPath)}`);
        }
      });
    } catch (error) {
      console.error('Error scanning file:', error);
      vscode.window.showErrorMessage(`Error scanning for security issues: ${error}`);
    }
  }
  
  async scanWorkspace(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
      vscode.window.showErrorMessage('No workspace folder open');
      return;
    }
    
    vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Scanning workspace for security issues...",
      cancellable: true
    }, async (progress, token) => {
      // Clear all previous diagnostics
      this.diagnosticsManager.clearAllDiagnostics();
      
      // Get the semgrep executable path from settings
      const config = vscode.workspace.getConfiguration('securityAssistant');
      const semgrepPath = config.get<string>('semgrepPath') || 'semgrep';
      
      try {
        // Check if semgrep is installed
        await this.checkSemgrepInstallation(semgrepPath);
        
        // Run semgrep on the workspace
        for (const folder of workspaceFolders) {
          if (token.isCancellationRequested) {
            return;
          }
          
          progress.report({ message: `Scanning ${folder.name}...` });
          
          const issues = await this.runSemgrepWorkspaceScan(folder.uri.fsPath, semgrepPath);
          let totalIssues = 0;
          
          // Group issues by file and update diagnostics
          for (const [filePath, fileIssues] of Object.entries(issues)) {
            const fileUri = vscode.Uri.file(filePath);
            this.diagnosticsManager.updateDiagnostics(
              fileUri,
              fileIssues.map(issue => this.convertToVscodeDiagnostic(issue))
            );
            totalIssues += fileIssues.length;
          }
          
          vscode.window.showInformationMessage(`Found ${totalIssues} security issues in workspace ${folder.name}`);
        }
      } catch (error) {
        console.error('Error scanning workspace:', error);
        vscode.window.showErrorMessage(`Error scanning workspace: ${error}`);
      }
    });
  }
  
  async fixIssue(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): Promise<void> {
    if (!diagnostic.code || typeof diagnostic.code !== 'string') {
      return;
    }
    
    const edit = new vscode.WorkspaceEdit();
    
    switch (diagnostic.code) {
      case 'hardcoded-secret': {
        // Replace hardcoded secret with environment variable reference
        const secretMatch = document.getText(diagnostic.range).match(/(["'])([^"']+)(["'])/);
        if (secretMatch) {
          const secretValue = secretMatch[2];
          const secretName = `API_KEY_${Math.floor(Math.random() * 1000)}`;
          const replacement = document.languageId === 'python' 
            ? `os.environ.get("${secretName}")` 
            : `process.env.${secretName}`;
          
          edit.replace(document.uri, diagnostic.range, replacement);
          
          vscode.workspace.applyEdit(edit).then(() => {
            vscode.window.showInformationMessage(
              `Replaced hardcoded secret with environment variable. ` +
              `Make sure to set ${secretName}="${secretValue}" in your environment.`
            );
            
            // After fixing, scan again to confirm fix
            this.scanFile(document);
          });
        }
        break;
      }
      
      case 'missing-auth': {
        // Insert authorization check snippet
        if (document.languageId === 'javascript' || document.languageId === 'typescript') {
          const indentation = this.getLineIndentation(document, diagnostic.range.start.line);
          const authCheck = `${indentation}// Add authorization check\n${indentation}if (!req.user || !req.user.isAuthorized) {\n${indentation}  return res.status(403).json({ error: 'Unauthorized' });\n${indentation}}\n\n${indentation}`;
          
          edit.insert(document.uri, new vscode.Position(diagnostic.range.start.line, 0), authCheck);
          
          vscode.workspace.applyEdit(edit).then(() => {
            vscode.window.showInformationMessage(
              'Added authorization check. Please modify as needed for your authentication system.'
            );
            
            // After fixing, scan again to confirm fix
            this.scanFile(document);
          });
        } else if (document.languageId === 'python') {
          const indentation = this.getLineIndentation(document, diagnostic.range.start.line);
          const authCheck = `${indentation}# Add authorization check\n${indentation}if not request.user or not request.user.is_authorized:\n${indentation}    return jsonify({'error': 'Unauthorized'}), 403\n\n${indentation}`;
          
          edit.insert(document.uri, new vscode.Position(diagnostic.range.start.line, 0), authCheck);
          
          vscode.workspace.applyEdit(edit).then(() => {
            vscode.window.showInformationMessage(
              'Added authorization check. Please modify as needed for your authentication system.'
            );
            
            // After fixing, scan again to confirm fix
            this.scanFile(document);
          });
        }
        break;
      }
      
      case 'outdated-dependency': {
        // For now, just show a message as updating dependencies requires more context
        vscode.window.showInformationMessage(
          'Please update the outdated dependency manually. Consider using a dependency management tool.'
        );
        break;
      }
    }
  }
  
  private async checkSemgrepInstallation(semgrepPath: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      cp.exec(`${semgrepPath} --version`, (error) => {
        if (error) {
          reject(new Error('Semgrep not found. Please install it with "pip install semgrep"'));
        } else {
          resolve();
        }
      });
    });
  }
  
  private async runSemgrepScan(document: vscode.TextDocument, semgrepPath: string): Promise<SecurityIssue[]> {
    // Save document to a temporary file to ensure Semgrep scans the latest content
    const tmpFilePath = document.uri.fsPath;
    
    return new Promise<SecurityIssue[]>((resolve, reject) => {
      // Set up rules - use our custom rules directory
      const rulesDir = path.join(__dirname, '..', 'rules');
      
      // Use specific rule files based on file type
      let configArg = '';
      if (document.fileName.endsWith('package.json')) {
        configArg = `--config ${path.join(rulesDir, 'outdated-deps.yaml')}`;
      } else {
        // Use all security rules for code files
        const ruleFiles = [
          'hardcoded-secrets.yaml',
          'missing-auth.yaml', 
          'sql-injection.yaml'
        ].map(file => path.join(rulesDir, file));
        configArg = ruleFiles.map(file => `--config ${file}`).join(' ');
      }
      
      const command = `${semgrepPath} --json ${configArg} --no-git-ignore ${tmpFilePath}`;
      
      cp.exec(command, (error, stdout) => {
        if (error && error.code !== 1) { // Semgrep returns 1 when it finds issues
          console.error('Semgrep error:', error);
          return reject(new Error(`Semgrep error: ${error.message}`));
        }
        
        try {
          // Parse the JSON output from Semgrep
          const results = JSON.parse(stdout);
          const issues: SecurityIssue[] = [];
          
          // Convert Semgrep results to our SecurityIssue format
          if (results.results) {
            for (const result of results.results) {
              const startLine = result.start.line - 1;
              const startCol = result.start.col - 1;
              const endLine = result.end.line - 1;
              const endCol = result.end.col;
              
              const range = new vscode.Range(
                new vscode.Position(startLine, startCol),
                new vscode.Position(endLine, endCol)
              );
              
              let code = 'security-issue';
              if (result.check_id.includes('hardcoded-secret')) {
                code = 'hardcoded-secret';
              } else if (result.check_id.includes('missing-auth')) {
                code = 'missing-auth';
              } else if (result.check_id.includes('outdated')) {
                code = 'outdated-dependency';
              }
              
              issues.push({
                message: result.extra.message,
                severity: vscode.DiagnosticSeverity.Warning,
                range,
                code,
                source: 'Security Assistant'
              });
            }
          }
          
          resolve(issues);
        } catch (parseError) {
          console.error('Error parsing Semgrep output:', parseError);
          reject(new Error(`Error parsing Semgrep output: ${parseError}`));
        }
      });
    });
  }
  
  private async runSemgrepWorkspaceScan(workspacePath: string, semgrepPath: string): Promise<Record<string, SecurityIssue[]>> {
    return new Promise<Record<string, SecurityIssue[]>>((resolve, reject) => {
      const rules = path.join(__dirname, '..', 'semgrep-rules');
      const command = `${semgrepPath} --json --config ${rules} ${workspacePath}`;
      
      cp.exec(command, (error, stdout) => {
        if (error && error.code !== 1) { // Semgrep returns 1 when it finds issues
          console.error('Semgrep error:', error);
          return reject(new Error(`Semgrep error: ${error.message}`));
        }
        
        try {
          // Parse the JSON output from Semgrep
          const results = JSON.parse(stdout);
          const issuesByFile: Record<string, SecurityIssue[]> = {};
          
          // Convert Semgrep results to our SecurityIssue format
          if (results.results) {
            for (const result of results.results) {
              const filePath = result.path;
              const startLine = result.start.line - 1;
              const startCol = result.start.col - 1;
              const endLine = result.end.line - 1;
              const endCol = result.end.col;
              
              const range = new vscode.Range(
                new vscode.Position(startLine, startCol),
                new vscode.Position(endLine, endCol)
              );
              
              let code = 'security-issue';
              if (result.check_id.includes('hardcoded-secret')) {
                code = 'hardcoded-secret';
              } else if (result.check_id.includes('missing-auth')) {
                code = 'missing-auth';
              } else if (result.check_id.includes('outdated')) {
                code = 'outdated-dependency';
              }
              
              if (!issuesByFile[filePath]) {
                issuesByFile[filePath] = [];
              }
              
              issuesByFile[filePath].push({
                message: result.extra.message,
                severity: vscode.DiagnosticSeverity.Warning,
                range,
                code,
                source: 'Security Assistant'
              });
            }
          }
          
          resolve(issuesByFile);
        } catch (parseError) {
          console.error('Error parsing Semgrep output:', parseError);
          reject(new Error(`Error parsing Semgrep output: ${parseError}`));
        }
      });
    });
  }
  
  private convertToVscodeDiagnostic(issue: SecurityIssue): vscode.Diagnostic {
    const diagnostic = new vscode.Diagnostic(
      issue.range,
      issue.message,
      issue.severity
    );
    
    diagnostic.source = issue.source;
    diagnostic.code = issue.code;
    
    return diagnostic;
  }
  
  private getLineIndentation(document: vscode.TextDocument, line: number): string {
    const lineText = document.lineAt(line).text;
    const match = lineText.match(/^(\s*)/);
    return match ? match[1] : '';
  }
  
  private async runPatternBasedScan(document: vscode.TextDocument): Promise<SecurityIssue[]> {
    const issues: SecurityIssue[] = [];
    const text = document.getText();
    const lines = text.split('\n');
    
    // Enhanced OWASP Top 10 Security patterns
    const patterns = [
      // A01: Broken Access Control - Hardcoded secrets
      {
        pattern: /(?:password|pwd|pass|secret|key|token)\s*[:=]\s*["']([^"']{4,})["']/gi,
        type: SecurityIssueType.HardcodedSecret,
        message: 'A01: Hardcoded credential detected. Use environment variables or secure key management.',
        severity: vscode.DiagnosticSeverity.Error
      },
      {
        pattern: /(?:api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["']([^"']{8,})["']/gi,
        type: SecurityIssueType.HardcodedSecret,
        message: 'A01: Hardcoded API key detected. Use environment variables.',
        severity: vscode.DiagnosticSeverity.Error
      },
      {
        pattern: /(?:jwt[_-]?secret|auth[_-]?secret)\s*[:=]\s*["']([^"']{6,})["']/gi,
        type: SecurityIssueType.HardcodedSecret,
        message: 'A01: Hardcoded JWT/Auth secret detected. Use secure key storage.',
        severity: vscode.DiagnosticSeverity.Error
      },
      
      // A03: Injection - SQL Injection patterns
      {
        pattern: /["']\s*\+\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/gi,
        type: SecurityIssueType.SqlInjection,
        message: 'A03: SQL injection vulnerability - string concatenation. Use parameterized queries.',
        severity: vscode.DiagnosticSeverity.Error
      },
      {
        pattern: /`[^`]*\$\{[^}]+\}[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/gi,
        type: SecurityIssueType.SqlInjection,
        message: 'A03: SQL injection vulnerability - template literal. Use parameterized queries.',
        severity: vscode.DiagnosticSeverity.Error
      },
      {
        pattern: /query\s*=\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+/gi,
        type: SecurityIssueType.SqlInjection,
        message: 'A03: SQL injection vulnerability - dynamic query building. Use ORM or parameterized queries.',
        severity: vscode.DiagnosticSeverity.Error
      },
      
      // A03: Injection - Command injection
      {
        pattern: /exec\s*\(\s*["'][^"']*["']\s*\+\s*[^)]+\)/gi,
        type: SecurityIssueType.CommandInjection,
        message: 'A03: Command injection vulnerability. Validate input and use safe alternatives.',
        severity: vscode.DiagnosticSeverity.Error
      },
      {
        pattern: /system\s*\(\s*["'][^"']*["']\s*\+\s*[^)]+\)/gi,
        type: SecurityIssueType.CommandInjection,
        message: 'A03: Command injection vulnerability via system(). Validate input.',
        severity: vscode.DiagnosticSeverity.Error
      },
      {
        pattern: /spawn\s*\(\s*["'][^"']*["']\s*,\s*\[[^\]]*\+[^\]]*\]\)/gi,
        type: SecurityIssueType.CommandInjection,
        message: 'A03: Command injection vulnerability via spawn(). Validate input.',
        severity: vscode.DiagnosticSeverity.Error
      },
      
      // A01: Broken Access Control - Missing authentication
      {
        pattern: /app\.(get|post|put|delete|patch)\s*\(\s*["'][^"']*(?:admin|api|secure|private)[^"']*["']\s*,\s*(?!.*auth)(?:function|\([^)]*\)\s*=>)/gi,
        type: SecurityIssueType.MissingAuth,
        message: 'A01: Missing authentication on sensitive endpoint. Add authentication middleware.',
        severity: vscode.DiagnosticSeverity.Warning
      },
      {
        pattern: /router\.(get|post|put|delete|patch)\s*\(\s*["'][^"']*["']\s*,\s*(?!.*auth)(?:function|\([^)]*\)\s*=>)/gi,
        type: SecurityIssueType.MissingAuth,
        message: 'A01: Route without authentication middleware. Consider adding authentication.',
        severity: vscode.DiagnosticSeverity.Information
      },
      {
        pattern: /app\.(get|post|put|delete|patch)\s*\(\s*["'][^"']*\/(?:delete|remove|admin|manage)[^"']*["']\s*,\s*(?!.*auth)(?:function|\([^)]*\)\s*=>)/gi,
        type: SecurityIssueType.MissingAuth,
        message: 'A01: Destructive operation without authentication. Add strong authentication.',
        severity: vscode.DiagnosticSeverity.Error
      },
      
      // A05: Security Misconfiguration
      {
        pattern: /cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']/gi,
        type: SecurityIssueType.WeakCrypto,
        message: 'A05: Insecure CORS configuration. Avoid wildcard origins in production.',
        severity: vscode.DiagnosticSeverity.Warning
      },
      {
        pattern: /app\.use\s*\(\s*cors\s*\(\s*\)\s*\)/gi,
        type: SecurityIssueType.WeakCrypto,
        message: 'A05: Default CORS configuration. Specify allowed origins explicitly.',
        severity: vscode.DiagnosticSeverity.Information
      },
      
      // A02: Cryptographic Failures
      {
        pattern: /(?:md5|sha1)\s*\(/gi,
        type: SecurityIssueType.WeakCrypto,
        message: 'A02: Weak cryptographic hash (MD5/SHA1). Use SHA-256 or better.',
        severity: vscode.DiagnosticSeverity.Warning
      },
      {
        pattern: /Math\.random\s*\(\s*\)/gi,
        type: SecurityIssueType.InsecureRandom,
        message: 'A02: Insecure random number generation. Use crypto.randomBytes() for security.',
        severity: vscode.DiagnosticSeverity.Warning
      }
    ];
    
    // Scan each line for patterns
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      
      for (const patternDef of patterns) {
        patternDef.pattern.lastIndex = 0; // Reset regex state
        let match;
        
        while ((match = patternDef.pattern.exec(line)) !== null) {
          const startPos = match.index;
          const endPos = startPos + match[0].length;
          
          const range = new vscode.Range(
            lineIndex, startPos,
            lineIndex, endPos
          );
          
          const issue: SecurityIssue = {
            message: patternDef.message,
            range: range,
            severity: patternDef.severity,
            code: patternDef.type,
            source: 'Security Assistant'
          };
          
          issues.push(issue);
        }
      }
    }
    
    return issues;
  }
}