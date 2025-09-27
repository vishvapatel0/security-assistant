import * as vscode from 'vscode';
import { PromptEnricher } from './promptEnricher';

export interface CopilotFixRequest {
  issueType: string;
  vulnerableCode: string;
  context: string;
  fileName: string;
  language: string;
  range: vscode.Range;
}

export interface CopilotFixResult {
  success: boolean;
  explanation: string;
  appliedFix?: string;
}

export class CopilotFixProvider {
  private promptEnricher: PromptEnricher;
  private outputChannel: vscode.OutputChannel;

  constructor() {
    this.promptEnricher = new PromptEnricher();
    this.outputChannel = vscode.window.createOutputChannel('Security Assistant - Copilot Fixes');
  }

  async generateFix(request: CopilotFixRequest): Promise<CopilotFixResult> {
    try {
      // Create security-enhanced prompt for Copilot
      const basePrompt = this.createCopilotPrompt(request);
      const enhancedPrompt = this.promptEnricher.enrichPromptForFix(basePrompt, request.issueType);
      
      // Apply the Copilot workflow
      const result = await this.applyCopilotFix(request, enhancedPrompt);
      
      return result;
    } catch (error) {
      console.error('Copilot fix generation failed:', error);
      return {
        success: false,
        explanation: `Failed to apply Copilot fix: ${error}`
      };
    }
  }

  private createCopilotPrompt(request: CopilotFixRequest): string {
    return `Fix this ${request.issueType} security vulnerability in ${request.fileName}:

SECURITY ISSUE: ${request.issueType}
LANGUAGE: ${request.language}

VULNERABLE CODE:
${request.vulnerableCode}

CONTEXT:
${request.context}

Please provide a secure implementation that follows security best practices.`;
  }

  private async applyCopilotFix(request: CopilotFixRequest, enhancedPrompt: string): Promise<CopilotFixResult> {
    try {
      // Open the file with the vulnerable code
      const document = await vscode.workspace.openTextDocument(request.fileName);
      const editor = await vscode.window.showTextDocument(document);
      
      // Position cursor at the problematic code
      editor.selection = new vscode.Selection(request.range.start, request.range.end);
      
      // Convert enhanced prompt to code comments
      const promptComments = this.convertToCodeComments(enhancedPrompt, request.language);
      
      // Insert the enhanced prompt as comments above the vulnerable code
      const insertPosition = new vscode.Position(request.range.start.line, 0);
      
      await editor.edit(editBuilder => {
        editBuilder.insert(insertPosition, promptComments + '\n');
      });
      
      // Update selection to include the new comments and vulnerable code
      const newEndLine = request.range.end.line + promptComments.split('\n').length;
      const newSelection = new vscode.Selection(
        insertPosition,
        new vscode.Position(newEndLine, request.range.end.character)
      );
      editor.selection = newSelection;
      
      // Show options to user
      const choice = await vscode.window.showInformationMessage(
        `🤖 Enhanced security prompt added for ${request.issueType}. Use GitHub Copilot to fix the vulnerable code.`,
        { modal: false },
        'Trigger Copilot',
        'Show Instructions',
        'Clean Up Comments'
      );
      
      if (choice === 'Trigger Copilot') {
        // Position cursor at the end of comments to trigger Copilot
        const triggerPosition = new vscode.Position(
          request.range.start.line + promptComments.split('\n').length - 1,
          0
        );
        editor.selection = new vscode.Selection(triggerPosition, triggerPosition);
        
        // Trigger Copilot suggestions
        await vscode.commands.executeCommand('editor.action.triggerSuggest');
        
        // Show additional instructions
        vscode.window.showInformationMessage(
          '💡 Copilot suggestions triggered! Accept the secure fix and then clean up the comments.',
          'Got it'
        );
        
      } else if (choice === 'Show Instructions') {
        this.showCopilotInstructions(request.issueType);
        
      } else if (choice === 'Clean Up Comments') {
        // Remove the added comments
        const endPosition = new vscode.Position(
          request.range.start.line + promptComments.split('\n').length,
          0
        );
        await editor.edit(editBuilder => {
          editBuilder.delete(new vscode.Range(insertPosition, endPosition));
        });
        
        vscode.window.showInformationMessage('🧹 Comments cleaned up!');
      }
      
      return {
        success: true,
        explanation: `Enhanced security prompt added for ${request.issueType}. Use GitHub Copilot to apply the fix.`,
        appliedFix: 'Copilot-guided fix ready'
      };
      
    } catch (error) {
      return {
        success: false,
        explanation: `Failed to apply Copilot workflow: ${error}`
      };
    }
  }

  private convertToCodeComments(prompt: string, language: string): string {
    const commentPrefix = this.getCommentPrefix(language);
    
    return prompt.split('\n').map(line => {
      if (line.trim()) {
        return `${commentPrefix} ${line}`;
      }
      return commentPrefix;
    }).join('\n');
  }

  private getCommentPrefix(language: string): string {
    switch (language.toLowerCase()) {
      case 'javascript':
      case 'typescript':
      case 'java':
      case 'c':
      case 'cpp':
      case 'csharp':
        return '//';
      case 'python':
      case 'ruby':
      case 'shell':
        return '#';
      case 'html':
      case 'xml':
        return '<!--';
      case 'css':
        return '/*';
      default:
        return '//';
    }
  }

  private showCopilotInstructions(issueType: string): void {
    this.outputChannel.clear();
    this.outputChannel.appendLine('🤖 GITHUB COPILOT FIX INSTRUCTIONS');
    this.outputChannel.appendLine('='.repeat(50));
    this.outputChannel.appendLine('');
    this.outputChannel.appendLine(`Issue Type: ${issueType}`);
    this.outputChannel.appendLine('');
    this.outputChannel.appendLine('WORKFLOW:');
    this.outputChannel.appendLine('1. Enhanced security prompt added as comments above vulnerable code');
    this.outputChannel.appendLine('2. Position your cursor after the comments');
    this.outputChannel.appendLine('3. Start typing or press Ctrl+Space to trigger Copilot');
    this.outputChannel.appendLine('4. Review and accept the secure fix suggestion');
    this.outputChannel.appendLine('5. Clean up the comment prompts when done');
    this.outputChannel.appendLine('');
    this.outputChannel.appendLine('TIPS:');
    this.outputChannel.appendLine('• Copilot will use the enhanced prompt context for better fixes');
    this.outputChannel.appendLine('• Review the suggestion before accepting');
    this.outputChannel.appendLine('• Test the fix thoroughly');
    this.outputChannel.appendLine('• Remove comment prompts after fixing');
    this.outputChannel.appendLine('');
    this.outputChannel.appendLine('KEYBOARD SHORTCUTS:');
    this.outputChannel.appendLine('• Ctrl+Space: Trigger Copilot suggestions');
    this.outputChannel.appendLine('• Tab: Accept suggestion');
    this.outputChannel.appendLine('• Esc: Dismiss suggestions');
    this.outputChannel.appendLine('• Alt+]: Next suggestion');
    this.outputChannel.appendLine('• Alt+[: Previous suggestion');
    this.outputChannel.show();
  }

  // Helper method for integration with existing code
  async generateLegacyFix(request: any): Promise<any> {
    // Convert legacy request to new format
    const copilotRequest: CopilotFixRequest = {
      issueType: request.issueType,
      vulnerableCode: request.vulnerableCode || request.codeContext,
      context: request.context || '',
      fileName: request.fileName || request.filePath,
      language: request.language || 'javascript',
      range: request.range || new vscode.Range(0, 0, 0, 0)
    };

    const result = await this.generateFix(copilotRequest);
    
    // Convert back to legacy format
    return {
      fixedCode: result.appliedFix || 'Copilot-guided fix',
      explanation: result.explanation,
      confidence: result.success ? 90 : 30,
      additionalSteps: ['Use GitHub Copilot to apply the suggested fix']
    };
  }
}