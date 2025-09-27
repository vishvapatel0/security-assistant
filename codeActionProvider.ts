import * as vscode from 'vscode';
import { DiagnosticsManager } from './diagnosticsManager';
import { SecurityScanner } from './securityScanner';

export class CodeActionProvider implements vscode.CodeActionProvider {
  constructor(
    private securityScanner: SecurityScanner,
    private diagnosticsManager: DiagnosticsManager
  ) {}
  
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    
    // Debug logging
    console.log('CodeActionProvider.provideCodeActions called');
    console.log('Number of diagnostics:', context.diagnostics.length);
    context.diagnostics.forEach((diag, index) => {
      console.log(`Diagnostic ${index}:`, {
        source: diag.source,
        message: diag.message,
        code: diag.code,
        severity: diag.severity
      });
    });
    
    // For each diagnostic, create a quick fix action
    for (const diagnostic of context.diagnostics) {
      console.log('Checking diagnostic source:', diagnostic.source);
      if (diagnostic.source?.includes('Security Assistant')) {
        console.log('Security Assistant diagnostic found, creating actions');
        // Handle different types of security issues
        const issueType = this.getIssueTypeFromDiagnostic(diagnostic);
        console.log('Issue type detected:', issueType);
        
        switch (issueType) {
          case 'hardcoded-secret': {
            const fixAction = new vscode.CodeAction(
              '🤖 Copilot-Enhanced Fix: Replace with environment variable',
              vscode.CodeActionKind.QuickFix
            );
            fixAction.command = {
              title: 'Copilot-Enhanced Fix: Replace with environment variable',
              command: 'security-assistant.fixHardcodedSecret',
              arguments: [document, diagnostic]
            };
            fixAction.diagnostics = [diagnostic];
            fixAction.isPreferred = true;
            actions.push(fixAction);

            // Add additional action to create .env file
            const envAction = new vscode.CodeAction(
              '📁 Create .env file template',
              vscode.CodeActionKind.QuickFix
            );
            envAction.command = {
              title: 'Create .env file template',
              command: 'security-assistant.createEnvTemplate',
              arguments: [document, diagnostic]
            };
            envAction.diagnostics = [diagnostic];
            actions.push(envAction);
            break;
          }
          
          case 'missing-auth': {
            const fixAction = new vscode.CodeAction(
              '🤖 Copilot-Enhanced Fix: Add authentication check',
              vscode.CodeActionKind.QuickFix
            );
            fixAction.command = {
              title: 'Copilot-Enhanced Fix: Add authentication check',
              command: 'security-assistant.fixMissingAuth',
              arguments: [document, diagnostic]
            };
            fixAction.diagnostics = [diagnostic];
            fixAction.isPreferred = true;
            actions.push(fixAction);
            break;
          }

          case 'sql-injection': {
            const fixAction = new vscode.CodeAction(
              '🤖 Copilot-Enhanced Fix: SQL injection vulnerability',
              vscode.CodeActionKind.QuickFix
            );
            fixAction.command = {
              title: 'Copilot-Enhanced Fix: Convert to parameterized query',
              command: 'security-assistant.fixSqlInjection',
              arguments: [document, diagnostic]
            };
            fixAction.diagnostics = [diagnostic];
            fixAction.isPreferred = true;
            actions.push(fixAction);
            break;
          }

          case 'command-injection': {
            const fixAction = new vscode.CodeAction(
              '⚡ Fix command injection vulnerability',
              vscode.CodeActionKind.QuickFix
            );
            fixAction.command = {
              title: 'Add input validation',
              command: 'security-assistant.fixCommandInjection',
              arguments: [document, diagnostic]
            };
            fixAction.diagnostics = [diagnostic];
            actions.push(fixAction);
            break;
          }
          
          case 'outdated-dependency': {
            const fixAction = new vscode.CodeAction(
              '📦 Show update instructions',
              vscode.CodeActionKind.QuickFix
            );
            fixAction.command = {
              title: 'Show update instructions',
              command: 'security-assistant.showDependencyInstructions',
              arguments: [document, diagnostic]
            };
            fixAction.diagnostics = [diagnostic];
            actions.push(fixAction);
            break;
          }

          default: {
            // Generic Copilot-Enhanced Fix
            const fixAction = new vscode.CodeAction(
              '🤖 Copilot-Enhanced Fix: Security Issue',
              vscode.CodeActionKind.QuickFix
            );
            fixAction.command = {
              title: 'Copilot-Enhanced Fix: Security Issue',
              command: 'security-assistant.fixHardcodedSecret', // Use hardcoded secret command as fallback
              arguments: [document, diagnostic]
            };
            fixAction.diagnostics = [diagnostic];
            fixAction.isPreferred = true;
            actions.push(fixAction);
            break;
          }
        }
      }
    }
    
    // Debug: Always add a test action to see if code action provider is working
    if (context.diagnostics.length > 0) {
      const testAction = new vscode.CodeAction(
        '🧪 DEBUG: Copilot Test Action',
        vscode.CodeActionKind.QuickFix
      );
      testAction.command = {
        title: 'Debug Test Action',
        command: 'security-assistant.scanCurrentFile',
        arguments: []
      };
      actions.push(testAction);
      console.log('Added debug test action');
    }
    
    console.log('Total actions created:', actions.length);
    return actions;
  }

  private getIssueTypeFromDiagnostic(diagnostic: vscode.Diagnostic): string {
    if (diagnostic.code && typeof diagnostic.code === 'string') {
      return diagnostic.code;
    }
    
    // Fall back to analyzing the message
    const message = diagnostic.message.toLowerCase();
    if (message.includes('hardcoded') || message.includes('secret') || message.includes('password')) {
      return 'hardcoded-secret';
    }
    if (message.includes('authentication') || message.includes('missing auth')) {
      return 'missing-auth';
    }
    if (message.includes('sql injection')) {
      return 'sql-injection';
    }
    if (message.includes('command injection')) {
      return 'command-injection';
    }
    if (message.includes('outdated') || message.includes('dependency')) {
      return 'outdated-dependency';
    }
    
    return 'generic';
  }
}