import * as vscode from 'vscode';

export function getWorkspaceFolder(document: vscode.TextDocument): string | undefined {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    return undefined;
  }
  
  const documentUri = document.uri;
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(documentUri);
  return workspaceFolder?.uri.fsPath;
}

export function isPackageJson(document: vscode.TextDocument): boolean {
  return document.fileName.endsWith('package.json');
}

export function isRequirementsFile(document: vscode.TextDocument): boolean {
  return document.fileName.endsWith('requirements.txt');
}