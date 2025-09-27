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
    const lineNumber = diagnostic.range.start.line;
    const contextRange = new vscode.Range(
      Math.max(0, lineNumber - 3),
      0,
      Math.min(document.lineCount - 1, lineNumber + 3),
      document.lineAt(Math.min(document.lineCount - 1, lineNumber + 3)).text.length
    );
    const context = document.getText(contextRange);
    
    // Determine issue type
    const issueType = getIssueTypeFromDiagnostic(diagnostic);
    
    // Create enhanced prompt
    const basePrompt = `Fix this ${issueType} security issue in the following code:
    
VULNERABLE CODE:
${vulnerableCode}

CONTEXT:
${context}

Provide a secure replacement that follows security best practices.`;

    const enhancedPrompt = promptEnricher.enrichPromptForFix(basePrompt, issueType);
    
    // Show the editor and position cursor
    const editor = await vscode.window.showTextDocument(document);
    
    // Insert enhanced prompt as comment above the vulnerable code
    const insertPosition = new vscode.Position(diagnostic.range.start.line, 0);
    const commentedPrompt = enhancedPrompt.split('\n').map(line => `// ${line}`).join('\n') + '\n';
    
    await editor.edit(editBuilder => {
      editBuilder.insert(insertPosition, commentedPrompt);
    });
    
    // Position cursor after the comments for Copilot to suggest fixes
    const newCursorPosition = new vscode.Position(
      diagnostic.range.start.line + enhancedPrompt.split('\n').length,
      0
    );
    editor.selection = new vscode.Selection(newCursorPosition, newCursorPosition);
    
    // Show instructions
    const choice = await vscode.window.showInformationMessage(
      `🤖 Enhanced security prompt added. GitHub Copilot will suggest a secure fix.`,
      'Trigger Copilot Suggestions',
      'Clean Up Comments',
      'Got It'
    );
    
    if (choice === 'Trigger Copilot Suggestions') {
      // Trigger Copilot completions
      await vscode.commands.executeCommand('editor.action.triggerSuggest');
    } else if (choice === 'Clean Up Comments') {
      // Remove the comment prompt
      const endPosition = new vscode.Position(
        diagnostic.range.start.line + enhancedPrompt.split('\n').length,
        0
      );
      await editor.edit(editBuilder => {
        editBuilder.delete(new vscode.Range(insertPosition, endPosition));
      });
    }
    
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to prepare Copilot fix: ${error}`);
  }
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