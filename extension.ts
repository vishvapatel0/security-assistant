import * as vscode from 'vscode';
import { SecurityScanner } from './securityScanner';
import { DiagnosticsManager } from './diagnosticsManager';
import { PromptEnricher } from './promptEnricher';

export function activate(context: vscode.ExtensionContext) {
  console.log('Simple Security Assistant with Copilot integration is now active');

  // Initialize services
  const diagnosticsManager = new DiagnosticsManager();
  const securityScanner = new SecurityScanner(diagnosticsManager);
  const promptEnricher = new PromptEnricher();
  
  // Scan currently active file when extension activates
  const activeEditor = vscode.window.activeTextEditor;
  if (activeEditor && activeEditor.document) {
    securityScanner.scanFile(activeEditor.document);
  }
  
  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('security-assistant.scanCurrentFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        securityScanner.scanFile(editor.document);
      }
    }),

    vscode.commands.registerCommand('security-assistant.fixWithCopilot', async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      await fixSecurityIssueWithCopilot(document, diagnostic, promptEnricher);
    }),
    
    // Auto-scan on file save
    vscode.workspace.onDidSaveTextDocument((document) => {
      securityScanner.scanFile(document);
    }),
    
    // Auto-scan when opening files
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document) {
        securityScanner.scanFile(editor.document);
      }
    }),

    // Register simple code action provider
    vscode.languages.registerCodeActionsProvider(
      ['javascript', 'typescript', 'python', 'json'],
      {
        provideCodeActions(document: vscode.TextDocument, _range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
          const actions: vscode.CodeAction[] = [];
          
          for (const diagnostic of context.diagnostics) {
            if (diagnostic.source?.includes('Security Assistant')) {
              const fixAction = new vscode.CodeAction(
                '🤖 Fix with GitHub Copilot',
                vscode.CodeActionKind.QuickFix
              );
              fixAction.command = {
                title: 'Fix with GitHub Copilot',
                command: 'security-assistant.fixWithCopilot',
                arguments: [document, diagnostic]
              };
              fixAction.diagnostics = [diagnostic];
              fixAction.isPreferred = true;
              actions.push(fixAction);
            }
          }
          
          return actions;
        }
      },
      {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
      }
    )
  );
}

async function fixSecurityIssueWithCopilot(
  document: vscode.TextDocument, 
  diagnostic: vscode.Diagnostic, 
  promptEnricher: PromptEnricher
) {
  try {
    // Get the vulnerable code and context
    const vulnerableCode = document.getText(diagnostic.range);
    const issueType = getIssueTypeFromDiagnostic(diagnostic);
    
    // Get secure replacement based on issue type
    const secureReplacement = getSecureReplacement(vulnerableCode, issueType);
    
    if (secureReplacement) {
      // Show the editor and directly replace the vulnerable code
      const editor = await vscode.window.showTextDocument(document);
      
      await editor.edit(editBuilder => {
        editBuilder.replace(diagnostic.range, secureReplacement);
      });
      
      // Show success message
      vscode.window.showInformationMessage(
        `✅ Security issue fixed: ${issueType} replaced with secure code.`
      );
      
      // Position cursor at the fixed code
      editor.selection = new vscode.Selection(diagnostic.range.start, diagnostic.range.start);
      
    } else {
      // Fallback: use GitHub Copilot with invisible prompt
      await triggerCopilotForSecurity(document, diagnostic, issueType, promptEnricher);
    }
    
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to fix security issue: ${error}`);
  }
}

function getSecureReplacement(vulnerableCode: string, issueType: string): string | null {
  switch (issueType) {
    case 'hardcoded-secret':
      // Replace hardcoded secrets with environment variables
      if (vulnerableCode.match(/apikey|api[_-]?key/i)) {
        return vulnerableCode.replace(/:\s*["'][^"']+["']/, ': process.env.API_KEY');
      }
      if (vulnerableCode.match(/password|pwd/i)) {
        return vulnerableCode.replace(/:\s*["'][^"']+["']/, ': process.env.DB_PASSWORD');
      }
      if (vulnerableCode.match(/jwt[_-]?secret|auth[_-]?secret/i)) {
        return vulnerableCode.replace(/:\s*["'][^"']+["']/, ': process.env.JWT_SECRET');
      }
      if (vulnerableCode.match(/secret|token/i)) {
        return vulnerableCode.replace(/:\s*["'][^"']+["']/, ': process.env.AUTH_TOKEN');
      }
      break;
      
    case 'sql-injection':
      // Replace string concatenation with parameterized queries
      if (vulnerableCode.includes('+ id +') || vulnerableCode.includes("' + id + '")) {
        return vulnerableCode.replace(
          /["'][^"']*["']\s*\+\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*["'][^"']*["']/,
          '"SELECT * FROM users WHERE id = ?", [id]'
        );
      }
      if (vulnerableCode.includes('${') && vulnerableCode.includes('SELECT')) {
        return vulnerableCode.replace(
          /`[^`]*\$\{[^}]+\}[^`]*`/,
          '"SELECT * FROM users WHERE name LIKE ?", [`%${name}%`]'
        );
      }
      // Generic SQL injection fix
      if (vulnerableCode.match(/["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+/)) {
        return 'db.query("SELECT * FROM table WHERE column = ?", [userInput])';
      }
      break;
      
    case 'missing-auth':
      // Add authentication middleware for Express routes
      if (vulnerableCode.match(/app\.(get|post|put|delete|patch)\s*\(/)) {
        // Find the route pattern and add middleware
        const routeMatch = vulnerableCode.match(/(app\.\w+\s*\(\s*["'][^"']*["']\s*,\s*)(.+)/);
        if (routeMatch) {
          return `${routeMatch[1]}authenticateUser, ${routeMatch[2]}`;
        }
      }
      if (vulnerableCode.match(/router\.(get|post|put|delete|patch)\s*\(/)) {
        const routeMatch = vulnerableCode.match(/(router\.\w+\s*\(\s*["'][^"']*["']\s*,\s*)(.+)/);
        if (routeMatch) {
          return `${routeMatch[1]}authenticateUser, ${routeMatch[2]}`;
        }
      }
      break;
      
    case 'command-injection':
      // Secure command execution
      if (vulnerableCode.includes('exec(') && vulnerableCode.includes('+')) {
        return 'child_process.execFile("command", [sanitizedArg1, sanitizedArg2])';
      }
      if (vulnerableCode.includes('system(') && vulnerableCode.includes('+')) {
        return 'subprocess.run(["command", sanitized_input], check=True)';
      }
      break;
      
    case 'weak-crypto':
      // Replace weak crypto
      if (vulnerableCode.includes('md5(') || vulnerableCode.includes('sha1(')) {
        return vulnerableCode.replace(/(md5|sha1)\s*\(/g, 'crypto.createHash("sha256")(');
      }
      if (vulnerableCode.includes('Math.random()')) {
        return vulnerableCode.replace(/Math\.random\s*\(\s*\)/, 'crypto.randomBytes(4).readUInt32BE() / 0x100000000');
      }
      if (vulnerableCode.includes('origin: "*"')) {
        return vulnerableCode.replace(/origin\s*:\s*["']\*["']/, 'origin: ["https://yourdomain.com"]');
      }
      break;
      
    case 'insecure-random':
      if (vulnerableCode.includes('Math.random()')) {
        return vulnerableCode.replace(/Math\.random\s*\(\s*\)/, 'crypto.randomInt(0, 1000000) / 1000000');
      }
      break;
  }
  
  return null;
}

async function triggerCopilotForSecurity(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic,
  issueType: string,
  _promptEnricher: PromptEnricher
) {
  try {
    const vulnerableCode = document.getText(diagnostic.range);
    
    // Create context-aware comment above the vulnerable code
    const securityPrompt = createSecurityPromptComment(vulnerableCode, issueType);
    
    const editor = await vscode.window.showTextDocument(document);
    
    // Insert security guidance comment above the vulnerable line
    const insertPosition = new vscode.Position(diagnostic.range.start.line, 0);
    
    await editor.edit(editBuilder => {
      editBuilder.insert(insertPosition, securityPrompt + '\n');
    });
    
    // Position cursor at the vulnerable code for Copilot to suggest fixes
    const newVulnerableRange = new vscode.Range(
      new vscode.Position(diagnostic.range.start.line + securityPrompt.split('\n').length, diagnostic.range.start.character),
      new vscode.Position(diagnostic.range.end.line + securityPrompt.split('\n').length, diagnostic.range.end.character)
    );
    
    editor.selection = new vscode.Selection(newVulnerableRange.start, newVulnerableRange.end);
    
    // Show options to user
    const choice = await vscode.window.showInformationMessage(
      `🤖 Security guidance added for ${issueType}. Select an option:`,
      'Get Copilot Suggestions',
      'Remove Comments',
      'Keep Comments'
    );
    
    if (choice === 'Get Copilot Suggestions') {
      await vscode.commands.executeCommand('editor.action.triggerSuggest');
    } else if (choice === 'Remove Comments') {
      // Remove the added comments
      const endPosition = new vscode.Position(
        diagnostic.range.start.line + securityPrompt.split('\n').length,
        0
      );
      await editor.edit(editBuilder => {
        editBuilder.delete(new vscode.Range(insertPosition, endPosition));
      });
    }
    
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to trigger Copilot: ${error}`);
  }
}

function createSecurityPromptComment(_vulnerableCode: string, issueType: string): string {
  const prompts = {
    'hardcoded-secret': '// SECURITY: Replace hardcoded secret with environment variable\n// Use process.env.SECRET_NAME or secure key management',
    'sql-injection': '// SECURITY: SQL injection vulnerability detected\n// Use parameterized queries: db.query("SELECT * FROM table WHERE id = ?", [id])',
    'missing-auth': '// SECURITY: Missing authentication on this endpoint\n// Add authentication middleware: app.get("/route", authenticateUser, handler)',
    'command-injection': '// SECURITY: Command injection vulnerability\n// Use execFile() with array of arguments instead of string concatenation',
    'weak-crypto': '// SECURITY: Weak cryptographic function detected\n// Use strong algorithms: crypto.createHash("sha256") or crypto.randomBytes()',
    'insecure-random': '// SECURITY: Insecure random number generation\n// Use crypto.randomBytes() for cryptographic purposes'
  };
  
  return prompts[issueType as keyof typeof prompts] || '// SECURITY: Security vulnerability detected - please fix';
}

function getIssueTypeFromDiagnostic(diagnostic: vscode.Diagnostic): string {
  if (diagnostic.code && typeof diagnostic.code === 'string') {
    return diagnostic.code;
  }
  
  const message = diagnostic.message.toLowerCase();
  if (message.includes('hardcoded') || message.includes('secret') || message.includes('password')) {
    return 'hardcoded-secret';
  }
  if (message.includes('sql injection')) {
    return 'sql-injection';
  }
  if (message.includes('authentication')) {
    return 'missing-auth';
  }
  if (message.includes('command injection')) {
    return 'command-injection';
  }
  
  return 'security-vulnerability';
}

export function deactivate() {
  console.log('Simple Security Assistant deactivated');
}