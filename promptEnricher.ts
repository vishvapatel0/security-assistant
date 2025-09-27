import * as vscode from 'vscode';

// This class enhances prompts to LLMs with comprehensive security best practices
export class PromptEnricher {
  private static readonly DETAILED_SECURITY_GUIDELINES = {
    authentication: [
      "🔐 AUTHENTICATION SECURITY - COMPREHENSIVE REQUIREMENTS:",
      "",
      "PASSWORD SECURITY:",
      "- Use bcrypt (cost 12+), scrypt, or Argon2id for password hashing - NEVER use MD5, SHA1, SHA256, or plain text",
      "- Implement password complexity: minimum 12 characters, uppercase, lowercase, numbers, special symbols",
      "- Enforce password history: prevent reuse of last 12 passwords",
      "- Implement password expiration policies for high-privilege accounts (90 days)",
      "- Use password strength meters with real-time feedback during registration",
      "- Store password hashes with unique salts (never reuse salts across users)",
      "",
      "RATE LIMITING & BRUTE FORCE PROTECTION:",
      "- Implement progressive delays: 1st fail=0s, 2nd=2s, 3rd=4s, 4th=8s, 5th=16s",
      "- Lock accounts after 5 failed attempts for 15 minutes (exponential backoff)",
      "- Implement IP-based rate limiting: max 10 login attempts per IP per minute",
      "- Use CAPTCHA after 3 failed attempts to prevent automated attacks",
      "- Log all failed authentication attempts with IP, timestamp, user agent",
      "- Implement account lockout notifications to legitimate users via email",
      "",
      "SESSION MANAGEMENT:",
      "- Generate cryptographically secure session tokens (32+ bytes entropy)",
      "- Set session cookies with HTTPOnly, Secure, SameSite=Strict flags",
      "- Implement session timeout: 30 minutes idle, 8 hours absolute maximum",
      "- Regenerate session IDs after successful authentication",
      "- Implement proper logout: invalidate session server-side, clear client cookies",
      "- Store sessions server-side (database/Redis) never client-side only",
      "- Implement concurrent session limits (max 3 active sessions per user)",
      "",
      "MULTI-FACTOR AUTHENTICATION:",
      "- Implement TOTP (Time-based One-Time Password) using RFC 6238 standard",
      "- Support backup codes (single-use, store hashed)",
      "- Implement SMS fallback with rate limiting (max 3 SMS per hour)",
      "- Support hardware security keys (FIDO2/WebAuthn)",
      "- Require MFA for privileged operations (password change, data export)",
      "- Implement MFA bypass for emergency access with additional verification",
      "",
      "THIRD-PARTY AUTHENTICATION:",
      "- Use OAuth 2.0 with PKCE (Proof Key for Code Exchange)",
      "- Implement OpenID Connect for identity verification",
      "- Validate JWT tokens: signature, expiration, issuer, audience claims",
      "- Store only necessary user data from third-party providers",
      "- Implement account linking security for multiple auth methods",
      "",
      "SECURITY MONITORING:",
      "- Log authentication events: success, failure, account lockout, password changes",
      "- Monitor for suspicious patterns: unusual locations, devices, time patterns",
      "- Implement real-time alerts for security events",
      "- Use geolocation checking for login anomaly detection",
      "- Implement device fingerprinting for known device recognition"
    ],
    
    authorization: [
      "🛡️ AUTHORIZATION & ACCESS CONTROL - DETAILED IMPLEMENTATION:",
      "",
      "ACCESS CONTROL MODELS:",
      "- Implement Role-Based Access Control (RBAC) with hierarchical roles",
      "- Use Attribute-Based Access Control (ABAC) for complex permission logic",
      "- Follow principle of least privilege: grant minimum necessary permissions",
      "- Implement defense in depth: multiple authorization layers",
      "- Use mandatory access control for highly sensitive operations",
      "",
      "PERMISSION VERIFICATION:",
      "- Verify permissions on EVERY protected resource access (no exceptions)",
      "- Implement object-level authorization: check access to specific data records",
      "- Use resource-based permissions: different actions on same resource",
      "- Implement context-aware authorization: time, location, device factors",
      "- Validate permissions server-side NEVER rely on client-side checks alone",
      "",
      "TOKEN & SESSION SECURITY:",
      "- Use JWT tokens with proper claims: iss, aud, exp, iat, sub, jti",
      "- Implement token refresh mechanism with short-lived access tokens (15 min)",
      "- Use secure token storage: HTTPOnly cookies or secure local storage",
      "- Implement token revocation lists for immediate access revocation",
      "- Validate token signature, expiration, and issuer on every request",
      "",
      "AUTHORIZATION PATTERNS:",
      "- Implement centralized authorization service/middleware",
      "- Use policy-based authorization: define permissions as policies",
      "- Implement permission inheritance: roles inherit from parent roles",
      "- Use permission caching with cache invalidation on permission changes",
      "- Implement conditional access: require additional verification for sensitive operations",
      "",
      "PRIVILEGE ESCALATION CONTROLS:",
      "- Implement step-up authentication for privilege escalation",
      "- Use time-limited elevated permissions (30 minutes maximum)",
      "- Require additional verification for administrative actions",
      "- Implement approval workflows for high-privilege operations",
      "- Log all privilege escalation attempts and approvals",
      "",
      "MONITORING & AUDITING:",
      "- Log all authorization decisions: granted, denied, errors",
      "- Implement real-time monitoring for authorization anomalies",
      "- Track permission usage patterns for access reviews",
      "- Generate regular access reports for compliance",
      "- Monitor for privilege creep and unused permissions",
      "",
      "ORGANIZATIONAL CONTROLS:",
      "- Implement regular access reviews (quarterly for high-privilege accounts)",
      "- Use separation of duties: require multiple approvals for critical operations",
      "- Implement emergency access procedures with full audit trails",
      "- Use just-in-time access: temporary permissions for specific tasks",
      "- Implement automated deprovisioning for terminated users"
    ],
    
    input_validation: [
      "✅ INPUT VALIDATION & SANITIZATION - COMPREHENSIVE DEFENSE:",
      "",
      "SERVER-SIDE VALIDATION (CRITICAL):",
      "- Validate ALL inputs on server-side - NEVER trust client-side validation alone",
      "- Use whitelist validation: define allowed characters, patterns, values",
      "- Implement strict data type validation: integers, emails, URLs, dates",
      "- Check input length limits: prevent buffer overflow and DoS attacks",
      "- Validate input ranges: numeric ranges, date ranges, array sizes",
      "- Use regular expressions carefully: prevent ReDoS (Regular Expression DoS)",
      "",
      "SQL INJECTION PREVENTION:",
      "- Use parameterized queries/prepared statements for ALL database operations",
      "- Never concatenate user input directly into SQL queries",
      "- Use stored procedures with parameter validation",
      "- Implement database user permissions: principle of least privilege",
      "- Use ORM frameworks with built-in injection protection",
      "- Validate and sanitize database schema/table names if dynamic",
      "",
      "XSS (Cross-Site Scripting) PREVENTION:",
      "- Escape output for HTML context: &lt; &gt; &amp; &quot; &#x27; &#x2F;",
      "- Use context-aware output encoding: HTML, JavaScript, CSS, URL contexts",
      "- Implement Content Security Policy (CSP) headers with strict policies",
      "- Use HTTPOnly flags on cookies to prevent JavaScript access",
      "- Validate and sanitize rich text input (HTML editors)",
      "- Use template engines with automatic escaping enabled",
      "",
      "FILE UPLOAD SECURITY:",
      "- Validate file types using magic bytes, not just extensions",
      "- Implement file size limits: prevent disk space exhaustion",
      "- Scan uploaded files for malware using antivirus APIs",
      "- Store uploaded files outside web root directory",
      "- Use unique, non-guessable filenames for uploaded files",
      "- Implement virus scanning and quarantine procedures",
      "- Validate image files: prevent malicious image exploits",
      "",
      "CSRF (Cross-Site Request Forgery) PREVENTION:",
      "- Implement CSRF tokens for ALL state-changing operations",
      "- Use SameSite cookie attribute: Strict or Lax",
      "- Validate HTTP Referer header for additional protection",
      "- Implement double-submit cookie pattern for AJAX requests",
      "- Use custom headers for AJAX requests (X-Requested-With)",
      "",
      "COMMAND INJECTION PREVENTION:",
      "- Never execute user input directly as system commands",
      "- Use parameterized system calls when possible",
      "- Implement strict input validation for system command parameters",
      "- Use application allow-lists for permitted commands",
      "- Run applications with minimal system privileges",
      "",
      "LDAP & XML INJECTION PREVENTION:",
      "- Escape special characters in LDAP queries: ( ) \\ * / NUL",
      "- Use parameterized LDAP queries when available",
      "- Validate XML input against strict schemas (XSD)",
      "- Disable XML external entity (XXE) processing",
      "- Use safe XML parsing libraries with security features enabled",
      "",
      "LOG INJECTION PREVENTION:",
      "- Sanitize data before writing to log files",
      "- Use structured logging formats (JSON) to prevent manipulation",
      "- Validate log data doesn't contain ANSI escape sequences",
      "- Implement log rotation and integrity checking",
      "- Use centralized logging with input validation"
    ],
    
    data_protection: [
      "🔒 DATA PROTECTION & ENCRYPTION - ENTERPRISE-GRADE SECURITY:",
      "",
      "ENCRYPTION AT REST:",
      "- Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption",
      "- Implement full database encryption: transparent data encryption (TDE)",
      "- Encrypt individual sensitive fields with field-level encryption",
      "- Use authenticated encryption: prevents tampering and provides integrity",
      "- Implement key wrapping: encrypt data keys with master keys",
      "- Use hardware security modules (HSMs) for key protection in production",
      "",
      "ENCRYPTION IN TRANSIT:",
      "- Use TLS 1.3 exclusively: disable TLS 1.0, 1.1, 1.2 where possible",
      "- Implement certificate pinning for mobile applications",
      "- Use perfect forward secrecy (PFS) cipher suites only",
      "- Implement HTTP Strict Transport Security (HSTS) with long max-age",
      "- Use certificate transparency monitoring",
      "- Implement mutual TLS (mTLS) for service-to-service communication",
      "",
      "KEY MANAGEMENT LIFECYCLE:",
      "- Generate keys using cryptographically secure random number generators",
      "- Implement key rotation: quarterly for data keys, annually for master keys",
      "- Use key derivation functions (PBKDF2, Argon2) for password-based keys",
      "- Store keys in dedicated key management services (AWS KMS, Azure Key Vault)",
      "- Implement key escrow procedures for regulatory compliance",
      "- Use split knowledge: require multiple parties for key operations",
      "",
      "SECRETS MANAGEMENT:",
      "- Never hardcode API keys, passwords, or encryption keys in source code",
      "- Use environment variables with restricted access permissions",
      "- Implement secrets rotation with zero-downtime deployment",
      "- Use dedicated secrets management tools (HashiCorp Vault, AWS Secrets Manager)",
      "- Implement just-in-time secrets: generate temporary credentials as needed",
      "- Monitor secrets usage and detect unauthorized access attempts",
      "",
      "DATA CLASSIFICATION & HANDLING:",
      "- Classify data by sensitivity: public, internal, confidential, restricted",
      "- Implement data loss prevention (DLP) controls",
      "- Use data masking in non-production environments",
      "- Implement tokenization for credit card and PII data",
      "- Follow data minimization: collect and retain only necessary data",
      "- Implement data anonymization and pseudonymization techniques",
      "",
      "PRIVACY & COMPLIANCE:",
      "- Implement GDPR Article 25: Privacy by Design and by Default",
      "- Support data subject rights: access, rectification, erasure, portability",
      "- Implement consent management with granular permissions",
      "- Use privacy-preserving analytics techniques",
      "- Implement data retention policies with automated deletion",
      "- Conduct privacy impact assessments (PIAs) for new features",
      "",
      "SECURE DATA DELETION:",
      "- Implement cryptographic erasure: delete encryption keys",
      "- Use secure deletion methods for magnetic storage (multiple overwrites)",
      "- Implement SSD secure erase commands for solid-state drives",
      "- Verify data deletion with forensic tools",
      "- Document data deletion procedures for compliance audits",
      "",
      "BACKUP & RECOVERY SECURITY:",
      "- Encrypt all backups with separate encryption keys",
      "- Implement backup integrity checking with cryptographic hashes",
      "- Test backup restoration procedures regularly",
      "- Store backups in geographically separate locations",
      "- Implement backup access controls: need-to-know basis",
      "- Use air-gapped backups for critical data protection"
    ],
    
    error_handling: [
      "⚠️ SECURE ERROR HANDLING - COMPREHENSIVE APPROACH:",
      "",
      "ERROR MESSAGE SECURITY:",
      "- Never expose sensitive information: database schemas, file paths, system details",
      "- Use generic error messages for users: 'Invalid credentials' instead of 'User not found'",
      "- Implement error code mapping: internal detailed codes to generic user messages",
      "- Avoid exposing technology stack in error messages",
      "- Never include SQL query details or database error messages in responses",
      "- Use consistent error response format across all endpoints",
      "",
      "LOGGING & MONITORING:",
      "- Log detailed errors securely for debugging with correlation IDs",
      "- Use structured logging (JSON format) with consistent field names",
      "- Implement centralized logging with security event correlation",
      "- Log security events: authentication failures, authorization denials, input validation failures",
      "- Use log levels appropriately: ERROR for security events, DEBUG for troubleshooting",
      "- Implement log integrity protection: digital signatures or tamper-evident logging",
      "",
      "EXCEPTION HANDLING:",
      "- Implement proper try-catch blocks around all risky operations",
      "- Never expose stack traces to end users in production",
      "- Use custom exception classes with appropriate error codes",
      "- Implement global exception handlers for unhandled exceptions",
      "- Fail securely: default to deny access when errors occur",
      "- Implement circuit breakers to prevent cascading failures",
      "",
      "TIMING ATTACK PREVENTION:",
      "- Use constant-time comparison functions for sensitive operations",
      "- Implement consistent response times for authentication operations",
      "- Add artificial delays to prevent timing-based enumeration",
      "- Use rate limiting to prevent timing attack exploitation",
      "- Implement cache timing attack protections",
      "",
      "SECURITY MONITORING:",
      "- Monitor error rates and patterns for anomaly detection",
      "- Implement real-time alerting for security-related errors",
      "- Track error trends to identify potential attacks",
      "- Use error correlation to detect distributed attacks",
      "- Implement automated incident response for critical errors",
      "",
      "AUDIT TRAILS:",
      "- Log all security-relevant events with timestamps and user context",
      "- Implement non-repudiation: cryptographic signatures for critical logs",
      "- Use write-only logging: prevent log tampering",
      "- Implement log retention policies compliant with regulations",
      "- Regular audit trail reviews and analysis"
    ],
    
    api_security: [
      "🌐 API SECURITY - ENTERPRISE-GRADE PROTECTION:",
      "",
      "AUTHENTICATION & AUTHORIZATION:",
      "- Use OAuth 2.0 with PKCE for public clients",
      "- Implement JWT tokens with short expiration (15 minutes)",
      "- Use API keys with scope limitations and rotation policies",
      "- Implement client certificate authentication for high-security APIs",
      "- Use mutual TLS (mTLS) for service-to-service communication",
      "- Implement token introspection for distributed systems",
      "",
      "RATE LIMITING & THROTTLING:",
      "- Implement multiple rate limiting layers: per-user, per-IP, per-endpoint",
      "- Use sliding window rate limiting for better accuracy",
      "- Implement burst limiting: allow short bursts but control sustained rates",
      "- Use different limits for authenticated vs anonymous users",
      "- Implement rate limiting with exponential backoff suggestions",
      "- Monitor and alert on rate limit violations",
      "",
      "INPUT VALIDATION & SANITIZATION:",
      "- Validate Content-Type headers and enforce strict parsing",
      "- Implement request size limits: headers (8KB), body (based on endpoint)",
      "- Use schema validation for all API inputs (JSON Schema, OpenAPI)",
      "- Validate HTTP methods: only allow intended methods per endpoint",
      "- Implement parameter pollution prevention",
      "- Use strict JSON parsing: reject malformed JSON",
      "",
      "CORS & CROSS-ORIGIN SECURITY:",
      "- Implement restrictive CORS policies: avoid wildcard (*) origins",
      "- Use specific allowed origins, methods, and headers",
      "- Implement preflight request validation",
      "- Use CORS credentials carefully: only when necessary",
      "- Implement JSONP security if supporting legacy clients",
      "",
      "TRANSPORT SECURITY:",
      "- Use HTTPS exclusively: redirect HTTP to HTTPS",
      "- Implement HTTP Strict Transport Security (HSTS)",
      "- Use perfect forward secrecy cipher suites",
      "- Implement certificate pinning for critical APIs",
      "- Use TLS 1.3 with strong cipher suites only",
      "",
      "API VERSIONING & LIFECYCLE:",
      "- Use semantic versioning with backward compatibility guarantees",
      "- Implement graceful deprecation with advance notice",
      "- Use version-specific rate limits and security policies",
      "- Implement sunset headers for deprecated APIs",
      "- Maintain security patches for supported API versions",
      "",
      "MONITORING & LOGGING:",
      "- Log all API requests with correlation IDs",
      "- Monitor API usage patterns for anomaly detection",
      "- Implement real-time threat detection and blocking",
      "- Track API performance and security metrics",
      "- Use API analytics for security insights",
      "",
      "API GATEWAY SECURITY:",
      "- Use API gateways for centralized security policy enforcement",
      "- Implement request/response transformation and validation",
      "- Use gateway-level authentication and authorization",
      "- Implement circuit breakers and failover mechanisms",
      "- Use gateway analytics for security monitoring"
    ],
    
    general_security: [
      "🔧 GENERAL SECURITY PRACTICES - COMPREHENSIVE SECURITY FRAMEWORK:",
      "",
      "DEPENDENCY & SUPPLY CHAIN SECURITY:",
      "- Keep all dependencies updated: use automated dependency scanning",
      "- Implement Software Bill of Materials (SBOM) tracking",
      "- Use dependency pinning with hash verification",
      "- Scan for known vulnerabilities (CVE database integration)",
      "- Implement license compliance checking",
      "- Use private package repositories for internal dependencies",
      "- Implement dependency approval workflows for new packages",
      "",
      "SECURITY HEADERS:",
      "- Content-Security-Policy: strict policy preventing XSS",
      "- HTTP Strict Transport Security (HSTS): max-age=31536000; includeSubDomains",
      "- X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
      "- X-Content-Type-Options: nosniff to prevent MIME sniffing",
      "- X-XSS-Protection: 1; mode=block (for legacy browser support)",
      "- Referrer-Policy: strict-origin-when-cross-origin",
      "- Permissions-Policy: restrict dangerous features",
      "",
      "SECURE CONFIGURATION:",
      "- Use secure defaults: deny by default, fail securely",
      "- Disable unnecessary services and features",
      "- Use principle of least privilege for all system accounts",
      "- Implement configuration management with version control",
      "- Use infrastructure as code for consistent deployments",
      "- Implement configuration validation and testing",
      "",
      "MONITORING & LOGGING:",
      "- Implement centralized logging with structured data formats",
      "- Use security information and event management (SIEM) systems",
      "- Implement real-time threat detection and alerting",
      "- Monitor for indicators of compromise (IoCs)",
      "- Implement user behavior analytics (UBA)",
      "- Use log correlation for attack pattern detection",
      "",
      "STATIC & DYNAMIC ANALYSIS:",
      "- Use static application security testing (SAST) tools",
      "- Implement dynamic application security testing (DAST)",
      "- Use interactive application security testing (IAST)",
      "- Implement software composition analysis (SCA)",
      "- Use container security scanning",
      "- Implement infrastructure as code (IaC) security scanning",
      "",
      "CI/CD SECURITY:",
      "- Implement security gates in deployment pipeline",
      "- Use signed container images with vulnerability scanning",
      "- Implement infrastructure security testing",
      "- Use secrets scanning in code repositories",
      "- Implement compliance checking in CI/CD",
      "- Use deployment approval workflows for production",
      "",
      "COMPLIANCE & STANDARDS:",
      "- Follow OWASP Top 10 and OWASP API Security Top 10",
      "- Implement NIST Cybersecurity Framework controls",
      "- Use CIS Security Controls as baseline",
      "- Implement SOC 2 Type II controls if applicable",
      "- Follow PCI DSS requirements for payment data",
      "- Implement GDPR privacy by design principles",
      "",
      "INCIDENT RESPONSE:",
      "- Develop and test incident response procedures",
      "- Implement security playbooks for common scenarios",
      "- Use threat intelligence feeds for proactive defense",
      "- Implement business continuity and disaster recovery plans",
      "- Conduct regular security drills and tabletop exercises",
      "- Maintain updated contact lists and escalation procedures"
    ]
  };
  
  // This method would be called when text is changed in the editor
  // In a real implementation, this would need to integrate with the specific
  // LLM extension API (e.g., GitHub Copilot) to modify prompts
  processDocumentChanges(event: vscode.TextDocumentChangeEvent): void {
    // This is a placeholder implementation
    // In a real extension, we would need to hook into the LLM extension's API
    
    // Look for text that might be a prompt to an LLM
    const changedText = event.contentChanges[0]?.text;
    if (changedText && this.looksLikePrompt(changedText)) {
      // If we identify a prompt, we would enrich it with security guidance
      const enrichedPrompt = this.enrichPrompt(changedText);
      
      // In a real implementation, we would pass this to the LLM extension
      console.log('Enriched prompt:', enrichedPrompt);
      
      // For demonstration, show a notification to the user
      this.showPromptEnrichmentNotification(enrichedPrompt);
    }
  }
  
  private looksLikePrompt(text: string): boolean {
    // Simple heuristic to detect if text might be a prompt to an LLM
    // This is a very basic implementation - a real one would be more sophisticated
    const promptIndicators = [
      'generate', 'create', 'write', 'implement', 'code', 'function', 
      'class', 'script', 'program', 'api'
    ];
    
    return text.length > 20 && 
           promptIndicators.some(indicator => 
             text.toLowerCase().includes(indicator)
           );
  }
  
  private enrichPrompt(originalPrompt: string): string {
    // Analyze the prompt to determine relevant security categories
    const relevantCategories = this.determineSecurityCategories(originalPrompt);
    
    // Build comprehensive security guidance
    let securityGuidance = "\n🔒 SECURITY REQUIREMENTS:\n\n";
    
    relevantCategories.forEach(category => {
      const guidelines = PromptEnricher.DETAILED_SECURITY_GUIDELINES[category];
      securityGuidance += guidelines.join('\n') + '\n\n';
    });
    
    // Add comprehensive security context and reminders
    securityGuidance += "🚨 CRITICAL SECURITY REQUIREMENTS:\n";
    securityGuidance += "- Follow secure coding practices and OWASP guidelines throughout development\n";
    securityGuidance += "- Validate ALL inputs server-side using whitelist validation\n";
    securityGuidance += "- Use latest security libraries with automated vulnerability scanning\n";
    securityGuidance += "- Implement comprehensive security testing before deployment\n";
    securityGuidance += "- Use threat modeling to identify potential security risks\n";
    securityGuidance += "- Implement defense in depth with multiple security layers\n";
    securityGuidance += "- Follow principle of least privilege for all access controls\n";
    securityGuidance += "- Use secure defaults and fail-safe mechanisms\n";
    securityGuidance += "- Implement comprehensive logging and monitoring\n";
    securityGuidance += "- Regular security code reviews and penetration testing\n\n";
    
    securityGuidance += "💡 SECURITY IMPLEMENTATION TIPS:\n";
    securityGuidance += "- Use parameterized queries to prevent SQL injection\n";
    securityGuidance += "- Implement proper session management with secure cookies\n";
    securityGuidance += "- Use HTTPS everywhere with proper certificate validation\n"; 
    securityGuidance += "- Implement rate limiting and input validation on all endpoints\n";
    securityGuidance += "- Use Content Security Policy (CSP) headers to prevent XSS\n";
    securityGuidance += "- Encrypt sensitive data at rest and in transit\n";
    securityGuidance += "- Implement proper error handling without information disclosure\n";
    securityGuidance += "- Use secure random number generation for tokens and keys\n";
    securityGuidance += "- Implement audit logging for all security-relevant events\n";
    securityGuidance += "- Keep all dependencies updated and scan for vulnerabilities\n\n";
    
    securityGuidance += "🔍 SECURITY TESTING CHECKLIST:\n";
    securityGuidance += "- [ ] Static code analysis (SAST) with security rule sets\n";
    securityGuidance += "- [ ] Dynamic security testing (DAST) against running application\n";
    securityGuidance += "- [ ] Dependency vulnerability scanning (SCA)\n";
    securityGuidance += "- [ ] Penetration testing by security professionals\n";
    securityGuidance += "- [ ] Code review focusing on security aspects\n";
    securityGuidance += "- [ ] Security unit tests for authentication and authorization\n";
    securityGuidance += "- [ ] Input validation testing with malicious payloads\n";
    securityGuidance += "- [ ] Session management and token security testing\n";
    securityGuidance += "- [ ] Infrastructure security configuration review\n";
    securityGuidance += "- [ ] Compliance validation against relevant standards\n\n";
    
    return `${originalPrompt}\n${securityGuidance}`;
  }
  
  private determineSecurityCategories(prompt: string): (keyof typeof PromptEnricher.DETAILED_SECURITY_GUIDELINES)[] {
    const lowerPrompt = prompt.toLowerCase();
    const categories: (keyof typeof PromptEnricher.DETAILED_SECURITY_GUIDELINES)[] = [];
    
    // Authentication-related keywords
    if (lowerPrompt.includes('auth') || lowerPrompt.includes('login') || 
        lowerPrompt.includes('password') || lowerPrompt.includes('signin') ||
        lowerPrompt.includes('register') || lowerPrompt.includes('user')) {
      categories.push('authentication');
    }
    
    // Authorization-related keywords  
    if (lowerPrompt.includes('permission') || lowerPrompt.includes('role') ||
        lowerPrompt.includes('access') || lowerPrompt.includes('authorize') ||
        lowerPrompt.includes('token') || lowerPrompt.includes('session')) {
      categories.push('authorization');
    }
    
    // Input validation keywords
    if (lowerPrompt.includes('input') || lowerPrompt.includes('form') ||
        lowerPrompt.includes('validation') || lowerPrompt.includes('sanitiz') ||
        lowerPrompt.includes('upload') || lowerPrompt.includes('submit')) {
      categories.push('input_validation');
    }
    
    // Data protection keywords
    if (lowerPrompt.includes('encrypt') || lowerPrompt.includes('data') ||
        lowerPrompt.includes('database') || lowerPrompt.includes('sensitive') ||
        lowerPrompt.includes('personal') || lowerPrompt.includes('private')) {
      categories.push('data_protection');
    }
    
    // API security keywords
    if (lowerPrompt.includes('api') || lowerPrompt.includes('endpoint') ||
        lowerPrompt.includes('rest') || lowerPrompt.includes('graphql') ||
        lowerPrompt.includes('service') || lowerPrompt.includes('request')) {
      categories.push('api_security');
    }
    
    // Error handling keywords
    if (lowerPrompt.includes('error') || lowerPrompt.includes('exception') ||
        lowerPrompt.includes('handle') || lowerPrompt.includes('try') ||
        lowerPrompt.includes('catch') || lowerPrompt.includes('log')) {
      categories.push('error_handling');
    }
    
    // If no specific categories found, include general security
    if (categories.length === 0) {
      categories.push('general_security');
    }
    
    return categories;
  }
  
  // Method specifically for enhancing fix prompts sent to LLMs
  enrichPromptForFix(basePrompt: string, issueType: string): string {
    const relevantCategories = this.determineSecurityCategoriesFromIssueType(issueType);
    
    let enhancedPrompt = basePrompt + '\n\n';
    enhancedPrompt += '🔒 SECURITY CONTEXT AND REQUIREMENTS:\n';
    enhancedPrompt += '='.repeat(50) + '\n\n';
    
    // Add specific security guidelines for the issue type
    relevantCategories.forEach(category => {
      const guidelines = PromptEnricher.DETAILED_SECURITY_GUIDELINES[category];
      if (guidelines) {
        enhancedPrompt += guidelines.slice(0, 20).join('\n') + '\n\n'; // First 20 lines for focus
      }
    });
    
    // Add fix-specific instructions
    enhancedPrompt += '🎯 FIX REQUIREMENTS:\n';
    enhancedPrompt += '- Provide ONLY secure, production-ready code\n';
    enhancedPrompt += '- Follow security best practices for ' + issueType + '\n';
    enhancedPrompt += '- Include proper input validation and error handling\n';
    enhancedPrompt += '- Use established security libraries when possible\n';
    enhancedPrompt += '- Explain WHY each change improves security\n';
    enhancedPrompt += '- Consider performance and maintainability\n\n';
    
    // Add compliance context
    enhancedPrompt += '📋 COMPLIANCE CONSIDERATIONS:\n';
    enhancedPrompt += '- Follow OWASP guidelines\n';
    enhancedPrompt += '- Consider GDPR/privacy implications\n';
    enhancedPrompt += '- Ensure audit trail compatibility\n';
    enhancedPrompt += '- Use industry standard security patterns\n\n';
    
    return enhancedPrompt;
  }

  private determineSecurityCategoriesFromIssueType(issueType: string): (keyof typeof PromptEnricher.DETAILED_SECURITY_GUIDELINES)[] {
    const categories: (keyof typeof PromptEnricher.DETAILED_SECURITY_GUIDELINES)[] = [];
    
    switch (issueType.toLowerCase()) {
      case 'hardcoded-secret':
      case 'hardcoded-password':
      case 'hardcoded-api-key':
        categories.push('data_protection', 'general_security');
        break;
        
      case 'sql-injection':
      case 'command-injection':
      case 'code-injection':
        categories.push('input_validation', 'general_security');
        break;
        
      case 'missing-auth':
      case 'missing-authentication':
        categories.push('authentication', 'authorization');
        break;
        
      case 'xss':
      case 'cross-site-scripting':
        categories.push('input_validation', 'general_security');
        break;
        
      case 'api-security':
        categories.push('api_security', 'authentication', 'input_validation');
        break;
        
      default:
        categories.push('general_security');
    }
    
    return categories;
  }

  private showPromptEnrichmentNotification(enrichedPrompt: string): void {
    // In a real implementation, this would be replaced by actual integration
    // with the LLM extension API
    vscode.window.showInformationMessage(
      '🔒 Security Assistant enriched your prompt with comprehensive security guidelines',
      'View Detailed Security Requirements', 'Copy Enhanced Prompt'
    ).then(selection => {
      if (selection === 'View Detailed Security Requirements') {
        // Show the enriched prompt in an output channel
        const channel = vscode.window.createOutputChannel('Security Assistant - Prompt Enhancement');
        channel.clear();
        channel.appendLine('='.repeat(80));
        channel.appendLine('🔒 SECURITY-ENHANCED PROMPT');
        channel.appendLine('='.repeat(80));
        channel.appendLine('');
        channel.appendLine('📝 ORIGINAL PROMPT:');
        channel.appendLine('-'.repeat(40));
        
        // Extract original prompt (before security guidelines)
        const parts = enrichedPrompt.split('\n🔒 SECURITY REQUIREMENTS:\n');
        channel.appendLine(parts[0]);
        channel.appendLine('');
        
        if (parts[1]) {
          channel.appendLine('🔒 ADDED SECURITY REQUIREMENTS:');
          channel.appendLine('-'.repeat(40));
          channel.appendLine(parts[1]);
        }
        
        channel.appendLine('');
        channel.appendLine('='.repeat(80));
        channel.appendLine('✅ Use this enhanced prompt with your AI assistant for secure code generation');
        channel.appendLine('='.repeat(80));
        channel.show();
      } else if (selection === 'Copy Enhanced Prompt') {
        vscode.env.clipboard.writeText(enrichedPrompt);
        vscode.window.showInformationMessage('📋 Enhanced prompt copied to clipboard!');
      }
    });
  }
}