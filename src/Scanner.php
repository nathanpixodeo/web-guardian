<?php

namespace WebGuardian;

use WebGuardian\Scanner\WordPressScanner;
use WebGuardian\Scanner\LaravelScanner;
use WebGuardian\Scanner\PrestaShopScanner;
use WebGuardian\Scanner\GenericScanner;
use WebGuardian\Detector\MalwareDetector;
use WebGuardian\Detector\BackdoorDetector;
use WebGuardian\Detector\VulnerabilityDetector;
use WebGuardian\Analyzer\FileAnalyzer;
use WebGuardian\Analyzer\DatabaseAnalyzer;

class Scanner
{
    private string $path;
    private array $options;
    private array $results;

    private MalwareDetector $malwareDetector;
    private BackdoorDetector $backdoorDetector;
    private VulnerabilityDetector $vulnDetector;
    private FileAnalyzer $fileAnalyzer;
    private DatabaseAnalyzer $dbAnalyzer;

    private ?string $progressFile = null;
    private float $startTime = 0.0;

    public function __construct(string $path, array $options = [])
    {
        $this->path = realpath($path);
        $this->options = array_merge([
            'type'          => 'generic',
            'depth'         => 10,
            'no-backup'     => false,
            'no-perm'       => false,
            'verbose'       => false,
            'rules'         => null,
            'progress_file' => null,
        ], $options);

        $this->progressFile = $this->options['progress_file'];

        $this->malwareDetector   = new MalwareDetector($this->options);
        $this->backdoorDetector  = new BackdoorDetector($this->options);
        $this->vulnDetector      = new VulnerabilityDetector($this->options);
        $this->fileAnalyzer      = new FileAnalyzer($this->options);
        $this->dbAnalyzer        = new DatabaseAnalyzer($this->options);

        $this->results = [
            'scanned_at'   => date('c'),
            'path'         => $this->path,
            'type'         => $this->options['type'],
            'summary'      => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0, 'total' => 0],
            'findings'     => [],
            'stats'        => ['files_scanned' => 0, 'files_skipped' => 0, 'elapsed_ms' => 0],
        ];
    }

    public function run(): array
    {
        $this->startTime = microtime(true);
        $this->log("Starting scan of {$this->path} (type: {$this->options['type']})");
        $this->writeProgress('cms_scan', 'Running CMS-specific scanner...');

        // Detect CMS type
        $cmsScanner = match ($this->options['type']) {
            'wordpress'  => new WordPressScanner($this->path, $this->options),
            'laravel'    => new LaravelScanner($this->path, $this->options),
            'prestashop' => new PrestaShopScanner($this->path, $this->options),
            default      => new GenericScanner($this->path, $this->options),
        };

        $findings = [];
        $this->log("Running CMS-specific scanner...");
        $cmsFindings = $cmsScanner->scan();
        $findings = array_merge($findings, $cmsFindings);

        // Walk files
        $this->log("Walking filesystem...");
        $this->writeProgress('file_scan', 'Scanning files...');
        $progressCounter = 0;
        $callback = function (\SplFileInfo $file) use (&$findings, &$progressCounter) {
            if ($this->shouldSkip($file)) {
                $this->results['stats']['files_skipped']++;
                return;
            }
            $this->results['stats']['files_scanned']++;

            $path = $file->getRealPath();
            $ext  = strtolower($file->getExtension());

            if (in_array($ext, ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'suspected'])) {
                $content = file_get_contents($path);
                if ($content === false) return;

                $malware = $this->malwareDetector->analyze($path, $content);
                foreach ($malware as $m) {
                    $m['type'] = $m['type'] ?? 'malware';
                    $findings[] = $m;
                }

                $backdoor = $this->backdoorDetector->analyze($path, $content);
                foreach ($backdoor as $b) {
                    $b['type'] = $b['type'] ?? 'backdoor';
                    $findings[] = $b;
                }
            }

            if (in_array($ext, ['php', 'phtml', 'php5', 'js', 'htaccess', 'env'])) {
                $sensitive = $this->fileAnalyzer->checkSensitiveContent($path);
                foreach ($sensitive as $s) {
                    $s['type'] = $s['type'] ?? 'sensitive';
                    $findings[] = $s;
                }
            }

            if (!$this->options['no-perm']) {
                $permIssues = $this->fileAnalyzer->checkPermissions($path);
                foreach ($permIssues as $p) {
                    $p['type'] = $p['type'] ?? 'permission';
                    $findings[] = $p;
                }
            }

            $progressCounter++;
            if ($this->progressFile && $progressCounter % 10 === 0) {
                $this->writeProgress('file_scan', $path);
            }
        };

        $this->walkDirectory($this->path, $callback, $this->options['depth']);

        // Check for common vulnerability patterns
        $this->log("Checking for vulnerability patterns...");
        $this->writeProgress('vuln_scan', 'Checking vulnerability patterns...');
        $vulnFindings = $this->vulnDetector->scanDirectory($this->path);
        $findings = array_merge($findings, $vulnFindings);

        // Check database config files for exposure
        $this->log("Analyzing configuration files...");
        $this->writeProgress('db_scan', 'Analyzing configuration files...');
        $dbFindings = $this->dbAnalyzer->findExposedConfigs($this->path);
        $findings = array_merge($findings, $dbFindings);

        // Deduplicate findings
        $seen = [];
        $unique = [];
        foreach ($findings as $f) {
            $key = ($f['file'] ?? '') . '|' . ($f['line'] ?? 0) . '|' . ($f['pattern'] ?? '');
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $f;
            }
        }
        $findings = $unique;

        // Sort by severity
        $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($findings, function ($a, $b) use ($severityOrder) {
            return ($severityOrder[$a['severity'] ?? 'info'] <=> $severityOrder[$b['severity'] ?? 'info']);
        });

        // Update summary
        foreach ($findings as $f) {
            $sev = $f['severity'] ?? 'info';
            if (isset($this->results['summary'][$sev])) {
                $this->results['summary'][$sev]++;
            }
            $this->results['summary']['total']++;
        }
        $this->results['findings'] = $findings;
        $this->results['stats']['elapsed_ms'] = (int) ((microtime(true) - $this->startTime) * 1000);

        $this->log("Scan complete. {$this->results['summary']['total']} findings in {$this->results['stats']['elapsed_ms']}ms");
        $this->writeProgress('completed');

        return $this->results;
    }

    private function walkDirectory(string $path, callable $callback, int $maxDepth, int $depth = 0): void
    {
        if ($depth > $maxDepth) return;

        $iterator = new \FilesystemIterator($path, \FilesystemIterator::SKIP_DOTS);
        foreach ($iterator as $file) {
            if ($file->isDir()) {
                $dirName = $file->getBasename();
                if (str_starts_with($dirName, '.') || $dirName === 'vendor' || $dirName === 'node_modules' ||
                    $dirName === 'storage' || $dirName === 'cache') {
                    continue;
                }
                $this->walkDirectory($file->getRealPath(), $callback, $maxDepth, $depth + 1);
            } elseif ($file->isFile()) {
                $callback($file);
            }
        }
    }

    private function shouldSkip(\SplFileInfo $file): bool
    {
        $name = $file->getBasename();
        if (str_starts_with($name, '.')) return true;

        $ext = strtolower($file->getExtension());
        $skipExts = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'webp',
                      'mp4', 'avi', 'mov', 'mkv', 'woff', 'woff2', 'ttf', 'eot',
                      'zip', 'tar', 'gz', 'rar', '7z', 'pdf', 'doc', 'docx',
                      'xls', 'xlsx', 'po', 'mo', 'pot', 'map', 'min.css', 'min.js'];

        if (in_array($ext, $skipExts)) return true;

        if ($file->getSize() > 10 * 1024 * 1024) return true; // skip files > 10MB

        return false;
    }

    private function writeProgress(string $status, string $currentFile = ''): void
    {
        if (!$this->progressFile) return;

        $findingsCount = 0;
        foreach ($this->results['summary'] as $k => $v) {
            if (in_array($k, ['critical', 'high', 'medium', 'low', 'info'])) {
                $findingsCount += $v;
            }
        }

        $data = json_encode([
            'status'        => $status,
            'phase'         => $status,
            'files_scanned' => $this->results['stats']['files_scanned'],
            'files_skipped' => $this->results['stats']['files_skipped'],
            'current_file'  => $currentFile,
            'findings_count'=> $findingsCount,
            'elapsed_ms'    => (int) ((microtime(true) - $this->startTime) * 1000),
        ]);

        $dir = dirname($this->progressFile);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        @file_put_contents($this->progressFile, $data, LOCK_EX);
    }

    private function log(string $message): void
    {
        if ($this->options['verbose']) {
            echo "[*] $message\n";
        }
    }

    public function getResults(): array
    {
        return $this->results;
    }
}
