import * as vscode from 'vscode';
import { SecurityScanner } from './securityScanner';
import { DiagnosticsManager } from './diagnosticsManager';

/**
 * Register commands related to code actions
 */
export function registerCodeActions(
    context: vscode.ExtensionContext,
    securityScanner: SecurityScanner,
    diagnosticsManager: DiagnosticsManager
): void {
    // Register command to fix security issues
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'security-assistant.fixIssue',
            async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
                try {
                    await securityScanner.fixIssue(document, diagnostic);
                    vscode.window.showInformationMessage('Security issue fixed');
                    
                    // Clear and refresh diagnostics after fix
                    diagnosticsManager.clearDiagnostics(document.uri);
                } catch (error) {
                    vscode.window.showErrorMessage(`Failed to fix security issue: ${error}`);
                }
            }
        )
    );
}