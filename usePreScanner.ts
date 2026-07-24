import { useEffect, useState } from 'react';

export interface CoverageStats {
  lines: number;
  percentage: number;
}

export interface PreScannerResult {
  instantAlert: string | null;
  coverage: CoverageStats;
}

/**
 * Custom hook to perform instant client-side pre-scanning on editor code buffers.
 * Detects hardcoded credentials/secrets before submitting code for deep backend AST analysis.
 */
export const usePreScanner = (code: string): PreScannerResult => {
  const [instantAlert, setInstantAlert] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<CoverageStats>({
    lines: 0,
    percentage: 100,
  });

  useEffect(() => {
    if (!code || code.trim() === '') {
      setCoverage({ lines: 0, percentage: 100 });
      setInstantAlert(null);
      return;
    }

    // Debounce client-side regex check to keep editor typing fluid
    const handler = setTimeout(() => {
      const lineCount = code.split('\n').length;
      setCoverage({ lines: lineCount, percentage: 100 });

      // Extended regex for secrets (Stripe, AWS, JWT, API Keys)
      const secretRegex =
        /(sk_live_[0-9a-zA-Z]{24,}|AKIA[0-9A-Z]{16}|JWT_SECRET\s*=\s*["'][^"']+["']|(api_key|api_secret|master_key)\s*=\s*["'][^"']+["'])/i;

      if (secretRegex.test(code)) {
        setInstantAlert(
          '🚨 Warning: Immediate detection of sensitive credential/secret key in editor buffer!'
        );
      } else {
        setInstantAlert(null);
      }
    }, 150);

    return () => clearTimeout(handler);
  }, [code]);

  return { instantAlert, coverage };
};
