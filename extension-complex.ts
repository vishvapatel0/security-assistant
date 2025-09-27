import * as vscode from 'vscode';
import { SecurityScanner } from './securityScanner';
import { DiagnosticsManager } from './diagnosticsManager';
import { CodeActionProvider } from './codeActionProvider';
import { PromptEnricher } from './promptEnricher';
import { DependencyChecker } from './dependencyChecker';
import { CopilotFixProvider } from './llmFixProvider';

export function activate(context: vscode.ExtensionContext) {
  console.log('Security Assistant extension is now active');

  // Initialize services
  const diagnosticsManager = new DiagnosticsManager();
  const securityScanner = new SecurityScanner(diagnosticsManager);
  const promptEnricher = new PromptEnricher();
  const dependencyChecker = new DependencyChecker(diagnosticsManager);
  const copilotFixProvider = new CopilotFixProvider();
  
  // Register code action provider
  const codeActionProvider = new CodeActionProvider(securityScanner, diagnosticsManager);
  
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
    
    vscode.commands.registerCommand('security-assistant.scanWorkspace', () => {
      securityScanner.scanWorkspace();
    }),
    
    vscode.commands.registerCommand('security-assistant.togglePromptEnrichment', () => {
      const config = vscode.workspace.getConfiguration('securityAssistant');
      const currentValue = config.get('enablePromptEnrichment') as boolean;
      config.update('enablePromptEnrichment', !currentValue, true).then(() => {
        vscode.window.showInformationMessage(
          `Security prompt enrichment ${!currentValue ? 'enabled' : 'disabled'}`
        );
      });
    }),

    // LLM-Enhanced Auto-fix commands
    vscode.commands.registerCommand('security-assistant.fixHardcodedSecret', async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "🤖 Generating LLM-enhanced security fix...",
        cancellable: true
      }, async (progress, token) => {
        try {
          progress.report({ increment: 20, message: "Analyzing vulnerable code..." });
          
          // Get context around the vulnerable line
          const context = getContextAroundLine(document, diagnostic.range.start.line, 5);
          const vulnerableCode = document.lineAt(diagnostic.range.start.line).text;
          
          progress.report({ increment: 40, message: "Creating security-enhanced prompt..." });
          
          const fixRequest = {
            issueType: 'hardcoded-secret',
            vulnerableCode,
            context,
            fileName: document.fileName,
            language: document.languageId
          };
          
          progress.report({ increment: 60, message: "Requesting Copilot fix..." });
          
          if (token.isCancellationRequested) return;
          
          const copilotResponse = await copilotFixProvider.generateLegacyFix(fixRequest);
          
          progress.report({ increment: 80, message: "Applying Copilot-guided fix..." });
          
          // Apply the LLM-generated fix
          const edit = new vscode.WorkspaceEdit();
          const fullRange = new vscode.Range(
            diagnostic.range.start.line, 0,
            diagnostic.range.end.line, document.lineAt(diagnostic.range.end.line).text.length
          );
          
          // Note: Copilot workflow doesn't directly replace code
          // The fix is applied through Copilot suggestions
          
          progress.report({ increment: 100, message: "Copilot workflow ready!" });
          
          // Show detailed explanation
          vscode.window.showInformationMessage(
            `🤖 Copilot Fix Ready (${copilotResponse.confidence}% confidence): ${copilotResponse.explanation}`,
            'Show Details', 'Got it'
          ).then(selection => {
            if (selection === 'Show Details') {
              showCopilotFixDetails(copilotResponse);
            }
          });
          
        } catch (error) {
          vscode.window.showErrorMessage(`Failed to generate LLM fix: ${error}`);
        }
      });
    }),

    vscode.commands.registerCommand('security-assistant.fixMissingAuth', async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "🤖 Generating LLM-enhanced authentication fix...",
        cancellable: true
      }, async (progress, token) => {
        try {
          progress.report({ increment: 20, message: "Analyzing route handler..." });
          
          const context = getContextAroundLine(document, diagnostic.range.start.line, 8);
          const vulnerableCode = document.getText(new vscode.Range(
            diagnostic.range.start.line, 0,
            Math.min(diagnostic.range.start.line + 5, document.lineCount - 1),
            document.lineAt(Math.min(diagnostic.range.start.line + 5, document.lineCount - 1)).text.length
          ));
          
          progress.report({ increment: 40, message: "Creating security-enhanced prompt..." });
          
          const fixRequest = {
            issueType: 'missing-auth',
            vulnerableCode,
            context,
            fileName: document.fileName,
            language: document.languageId
          };
          
          progress.report({ increment: 60, message: "Requesting Copilot authentication fix..." });
          
          if (token.isCancellationRequested) return;
          
          const copilotResponse = await copilotFixProvider.generateLegacyFix(fixRequest);
          
          progress.report({ increment: 80, message: "Applying Copilot authentication fix..." });
          
          // Apply the LLM-generated fix
          const edit = new vscode.WorkspaceEdit();
          const fullRange = new vscode.Range(
            diagnostic.range.start.line, 0,
            Math.min(diagnostic.range.start.line + 5, document.lineCount - 1),
            document.lineAt(Math.min(diagnostic.range.start.line + 5, document.lineCount - 1)).text.length
          );
          
          // Note: Copilot workflow guides the fix rather than replacing directly
          
          progress.report({ increment: 100, message: "Copilot authentication fix ready!" });
          
          vscode.window.showInformationMessage(
            `🤖 Copilot Authentication Fix Ready (${copilotResponse.confidence}% confidence)`,
            'Show Details', 'Got it'
          ).then(selection => {
            if (selection === 'Show Details') {
              showCopilotFixDetails(copilotResponse);
            }
          });
          
        } catch (error) {
          vscode.window.showErrorMessage(`Failed to generate LLM authentication fix: ${error}`);
        }
      });
    }),

    vscode.commands.registerCommand('security-assistant.createEnvFile', async (varName: string, value: string) => {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (workspaceFolders && workspaceFolders.length > 0) {
        const envPath = vscode.Uri.joinPath(workspaceFolders[0].uri, '.env');
        const envContent = `# Environment variables
${varName}=${value}
`;
        
        try {
          await vscode.workspace.fs.writeFile(envPath, new Uint8Array(Buffer.from(envContent)));
          vscode.window.showInformationMessage('✅ Created .env file with your environment variable.');
          // Open the .env file
          const doc = await vscode.workspace.openTextDocument(envPath);
          vscode.window.showTextDocument(doc);
        } catch (error) {
          vscode.window.showErrorMessage('Failed to create .env file: ' + error);
        }
      }
    }),

    vscode.commands.registerCommand('security-assistant.showDependencyInstructions', (_document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      const channel = vscode.window.createOutputChannel('Security Assistant - Dependency Updates');
      channel.clear();
      channel.appendLine('🔒 DEPENDENCY UPDATE INSTRUCTIONS');
      channel.appendLine('='.repeat(50));
      channel.appendLine('');
      channel.appendLine('⚠️  Outdated dependency detected:');
      channel.appendLine(diagnostic.message);
      channel.appendLine('');
      channel.appendLine('📋 Update instructions:');
      channel.appendLine('1. Run: npm audit');
      channel.appendLine('2. Run: npm audit fix');
      channel.appendLine('3. Or manually update in package.json');
      channel.appendLine('');
      channel.appendLine('🔍 Check for vulnerabilities:');
      channel.appendLine('- Visit: https://npmjs.com/advisories');
      channel.appendLine('- Use: npm audit --audit-level moderate');
      channel.show();
    }),

    vscode.commands.registerCommand('security-assistant.fixSqlInjection', async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,  
        title: "🤖 Generating LLM-enhanced SQL injection fix...",
        cancellable: true
      }, async (progress, token) => {
        try {
          progress.report({ increment: 20, message: "Analyzing SQL injection vulnerability..." });
          
          const context = getContextAroundLine(document, diagnostic.range.start.line, 6);
          const vulnerableCode = document.lineAt(diagnostic.range.start.line).text;
          
          progress.report({ increment: 40, message: "Creating security-enhanced SQL prompt..." });
          
          const fixRequest = {
            issueType: 'sql-injection',
            vulnerableCode,
            context,
            fileName: document.fileName,
            language: document.languageId
          };
          
          progress.report({ increment: 60, message: "Requesting LLM SQL injection fix..." });
          
          if (token.isCancellationRequested) return;
          
          const copilotResponse = await copilotFixProvider.generateLegacyFix(fixRequest);
          
          progress.report({ increment: 80, message: "Applying Copilot SQL injection fix..." });
          
          // Note: Copilot workflow guides the fix rather than replacing directly
          
          progress.report({ increment: 100, message: "Copilot SQL injection fix ready!" });
          
          vscode.window.showInformationMessage(
            `🤖 Copilot SQL Injection Fix Ready (${copilotResponse.confidence}% confidence)`,
            'Show Details', 'Got it'  
          ).then(selection => {
            if (selection === 'Show Details') {
              showCopilotFixDetails(copilotResponse);
            }
          });
          
        } catch (error) {
          vscode.window.showErrorMessage(`Failed to generate Copilot SQL injection fix: ${error}`);
        }
      });
    }),

    vscode.commands.registerCommand('security-assistant.fixCommandInjection', async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      const edit = new vscode.WorkspaceEdit();
      const line = document.lineAt(diagnostic.range.start.line);
      
      // Add input validation before the vulnerable line
      const validation = `    // Input validation to prevent command injection
    if (!/^[a-zA-Z0-9._-]+$/.test(userInput)) {
        throw new Error('Invalid input: only alphanumeric characters, dots, underscores, and hyphens allowed');
    }
    
`;
      
      const insertPosition = new vscode.Position(diagnostic.range.start.line, 0);
      edit.insert(document.uri, insertPosition, validation);
      
      await vscode.workspace.applyEdit(edit);
      vscode.window.showInformationMessage('✅ Added input validation. Please adjust the regex pattern as needed for your use case.');
    }),

    vscode.commands.registerCommand('security-assistant.createEnvTemplate', async (_document: vscode.TextDocument, _diagnostic: vscode.Diagnostic) => {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (workspaceFolders && workspaceFolders.length > 0) {
        const envPath = vscode.Uri.joinPath(workspaceFolders[0].uri, '.env.template');
        const envContent = `# Environment Variables Template
# Copy this file to .env and fill in your actual values

# API Keys and Secrets
API_KEY=your_api_key_here
JWT_SECRET=your_jwt_secret_here
DB_PASSWORD=your_database_password_here

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=your_database_name

# External Service URLs
EXTERNAL_API_URL=https://api.example.com

# Security Settings
SESSION_SECRET=your_session_secret_here
ENCRYPTION_KEY=your_encryption_key_here
`;
        
        try {
          await vscode.workspace.fs.writeFile(envPath, new Uint8Array(Buffer.from(envContent)));
          vscode.window.showInformationMessage('✅ Created .env.template file. Copy to .env and add your actual values.');
          // Open the template file
          const doc = await vscode.workspace.openTextDocument(envPath);
          vscode.window.showTextDocument(doc);
        } catch (error) {
          vscode.window.showErrorMessage('Failed to create .env.template file: ' + error);
        }
      }
    }),

    vscode.commands.registerCommand('security-assistant.showSecurityGuidance', (_document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      const channel = vscode.window.createOutputChannel('Security Assistant - Security Guidance');
      channel.clear();
      channel.appendLine('🔒 SECURITY GUIDANCE');
      channel.appendLine('='.repeat(50));
      channel.appendLine('');
      channel.appendLine('⚠️  Security Issue Detected:');
      channel.appendLine(diagnostic.message);
      channel.appendLine('');
      channel.appendLine('📋 General Security Best Practices:');
      channel.appendLine('• Always validate and sanitize user input');
      channel.appendLine('• Use parameterized queries for database operations');
      channel.appendLine('• Store secrets in environment variables');
      channel.appendLine('• Implement proper authentication and authorization');
      channel.appendLine('• Keep dependencies up to date');
      channel.appendLine('• Use HTTPS for all communications');
      channel.appendLine('• Implement proper error handling');
      channel.appendLine('• Follow the principle of least privilege');
      channel.appendLine('');
      channel.appendLine('🔍 Additional Resources:');
      channel.appendLine('• OWASP Top 10: https://owasp.org/www-project-top-ten/');
      channel.appendLine('• NIST Cybersecurity Framework: https://www.nist.gov/cyberframework');
      channel.appendLine('• CWE Database: https://cwe.mitre.org/');
      channel.show();
    }),
    
    // Register code action provider for security issues
    vscode.languages.registerCodeActionsProvider(
      ['javascript', 'typescript', 'python', 'json'],
      codeActionProvider,
      {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
      }
    ),
    
    // Setup file save listener
    vscode.workspace.onDidSaveTextDocument((document) => {
      securityScanner.scanFile(document);
      // Also check for dependency vulnerabilities in package files
      if (document.fileName.endsWith('package.json') || document.fileName.endsWith('requirements.txt')) {
        dependencyChecker.checkDependencies();
      }
    }),
    
    // Setup file open listener - scan when files are opened
    vscode.workspace.onDidOpenTextDocument((document) => {
      securityScanner.scanFile(document);
      // Also check dependencies when opening package files
      if (document.fileName.endsWith('package.json') || document.fileName.endsWith('requirements.txt')) {
        dependencyChecker.checkDependencies();
      }
    }),
    
    // Setup active editor change listener - scan when switching between files
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document) {
        securityScanner.scanFile(editor.document);
        // Check dependencies when switching to package files
        if (editor.document.fileName.endsWith('package.json') || editor.document.fileName.endsWith('requirements.txt')) {
          dependencyChecker.checkDependencies();
        }
      }
    }),
    
    // Setup editor change listener for prompt enrichment
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration('securityAssistant');
      if (config.get('enablePromptEnrichment')) {
        promptEnricher.processDocumentChanges(event);
      }
    })
  );
}

// Helper functions for LLM fixes
function getContextAroundLine(document: vscode.TextDocument, lineNumber: number, contextLines: number): string {
  const startLine = Math.max(0, lineNumber - contextLines);
  const endLine = Math.min(document.lineCount - 1, lineNumber + contextLines);
  
  let context = '';
  for (let i = startLine; i <= endLine; i++) {
    const lineText = document.lineAt(i).text;
    const marker = i === lineNumber ? '>>> ' : '    ';
    context += `${marker}${i + 1}: ${lineText}\n`;
  }
  
  return context;
}

function showCopilotFixDetails(response: any): void {
  const channel = vscode.window.createOutputChannel('Security Assistant - Copilot Fix Details');
  channel.clear();
  channel.appendLine('🤖 GITHUB COPILOT SECURITY FIX DETAILS');
  channel.appendLine('='.repeat(60));
  channel.appendLine('');
  channel.appendLine(`📊 Confidence Level: ${response.confidence}%`);
  channel.appendLine('');
  channel.appendLine('🔧 EXPLANATION:');
  channel.appendLine('-'.repeat(30));
  channel.appendLine(response.explanation);
  channel.appendLine('');
  
  if (response.additionalSteps && response.additionalSteps.length > 0) {
    channel.appendLine('📋 WORKFLOW STEPS:');
    channel.appendLine('-'.repeat(30));
    response.additionalSteps.forEach((step: string, index: number) => {
      channel.appendLine(`${index + 1}. ${step}`);
    });
    channel.appendLine('');
  }
  
  channel.appendLine('💡 COPILOT WORKFLOW TIPS:');
  channel.appendLine('- Enhanced prompt added as comments above vulnerable code');
  channel.appendLine('- Use Ctrl+Space to trigger Copilot suggestions');
  channel.appendLine('- Review and accept Copilot suggestions carefully');
  channel.appendLine('- Test the fix thoroughly');
  channel.appendLine('- Clean up comment prompts after fixing');
  channel.appendLine('- Consider additional security measures');
  
  channel.show();
}

export function deactivate() {
  console.log('Security Assistant extension deactivated');
}