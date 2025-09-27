import * as vscode from 'vscode';

export class DiagnosticsManager {
  private diagnosticCollection: vscode.DiagnosticCollection;
  
  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('security-assistant');
  }
  
  updateDiagnostics(uri: vscode.Uri, diagnostics: vscode.Diagnostic[]): void {
    this.diagnosticCollection.set(uri, diagnostics);
  }
  
  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }
  
  clearAllDiagnostics(): void {
    this.diagnosticCollection.clear();
  }
  
  getDiagnostics(uri: vscode.Uri): vscode.Diagnostic[] {
    return [...(this.diagnosticCollection.get(uri) ?? [])];
  }
  
  setDiagnostics(uri: vscode.Uri, diagnostics: vscode.Diagnostic[]): void {
    this.diagnosticCollection.set(uri, diagnostics);
  }
}