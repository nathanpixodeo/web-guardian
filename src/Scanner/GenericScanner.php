<?php

namespace WebGuardian\Scanner;

class GenericScanner
{
    private string $path;
    private array $options;

    private const DANGEROUS_FUNCTIONS = [
        'eval'          => 'Code execution via eval()',
        'exec'          => 'System command execution',
        'shell_exec'    => 'Shell command execution',
        'system'        => 'System command execution',
        'passthru'      => 'System command execution',
        'popen'         => 'Process execution',
        'proc_open'     => 'Process execution',
        'assert'        => 'Dynamic code execution via assert',
        'create_function' => 'Deprecated code creation function',
        'pcntl_exec'    => 'Process execution in current space',
        'ob_start'      => 'Output buffering - often used in wrappers',
        'call_user_func' => 'Callback execution - potential for injection',
        'call_user_func_array' => 'Callback execution - potential for injection',
        'array_map'     => 'Can execute callbacks dynamically',
        'array_filter'  => 'Can execute callbacks dynamically',
        'array_walk'    => 'Can execute callbacks dynamically',
        'register_shutdown_function' => 'Can execute callbacks on shutdown',
        'register_tick_function' => 'Can execute callbacks on ticks',
        'set_error_handler' => 'Error handler - potential for abuse',
        'set_exception_handler' => 'Exception handler - potential for abuse',
        'mb_ereg_replace' . '/e' => 'Deprecated /e modifier in mb_ereg_replace',
        'preg_filter'   => 'Can use /e modifier - code execution',
        'phpinfo'       => 'Exposes PHP configuration',
    ];

    private const OBFUSCATION_PATTERNS = [
        '/\bchr\s*\(\s*\d{2,3}\s*\)/' => 'chr() with numeric values - possible string building',
        '/\$(?:_|GLOBALS|_[A-Z]+)\s*\[[^\]]*\]\s*\{/' => 'Variable variable with superglobal',
        '/\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}/' => 'Hex-encoded characters in string',
        '/\$\w+\s*=\s*[\'\"][A-Za-z0-9+\/=]{100,}[\'\"]\s*;/' => 'Long base64-like string in variable',
        '/\bextract\s*\(\s*\$_/' => 'extract() from superglobal - variable injection',
        '/\bparse_str\s*\(\s*\$_/' => 'parse_str() from superglobal - variable injection',
    ];

    public function __construct(string $path, array $options = [])
    {
        $this->path = $path;
        $this->options = $options;
    }

    public function scan(): array
    {
        $findings = [];

        $findings = array_merge($findings, $this->checkComposerIntegrity());
        $findings = array_merge($findings, $this->checkHtaccess());
        $findings = array_merge($findings, $this->checkGitExposure());
        $findings = array_merge($findings, $this->checkPhpConfig());
        $findings = array_merge($findings, $this->checkBackupFiles());
        $findings = array_merge($findings, $this->checkInformationDisclosure());

        return $findings;
    }

    private function checkComposerIntegrity(): array
    {
        $findings = [];
        $composerJson = $this->path . '/composer.json';

        if (!file_exists($composerJson)) return $findings;

        $content = file_get_contents($composerJson);
        if (!$content) return $findings;

        $config = json_decode($content, true);
        if (!$config) {
            $findings[] = [
                'file'     => $composerJson,
                'line'     => 0,
                'pattern'  => 'invalid_composer',
                'severity' => 'medium',
                'type'     => 'generic',
                'message'  => 'composer.json is not valid JSON - may have been tampered with',
            ];
            return $findings;
        }

        // Check for minimum-stability
        if (isset($config['minimum-stability']) && $config['minimum-stability'] !== 'stable') {
            $findings[] = [
                'file'     => $composerJson,
                'line'     => 0,
                'pattern'  => 'unstable_deps',
                'severity' => 'medium',
                'type'     => 'generic',
                'message'  => "Composer minimum-stability is '{$config['minimum-stability']}' - may include unstable packages",
            ];
        }

        // Check if require-dev deps might be exposed
        if (isset($config['require-dev']) && count($config['require-dev']) > 0) {
            if (!isset($config['scripts']['install']) || !str_contains(json_encode($config), '--no-dev')) {
                $findings[] = [
                    'file'     => $composerJson,
                    'line'     => 0,
                    'pattern'  => 'dev_deps_production',
                    'severity' => 'low',
                    'type'     => 'generic',
                    'message'  => 'Dev dependencies are installed - ensure composer install --no-dev is used in production',
                ];
            }
        }

        return $findings;
    }

    private function checkHtaccess(): array
    {
        $findings = [];

        // Walk from root looking for .htaccess files
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->getBasename() !== '.htaccess') continue;

            $content = @file_get_contents($file->getRealPath());
            if (!$content) continue;

            $lines = explode("\n", $content);

            // Check for obvious bypasses or dangerous directives
            $dangerousHtaccess = [
                '/RewriteEngine\s+On/i' => false, // Fine standalone
                '/RewriteRule.*\*\.php/i' => 'Potential PHP execution in disallowed directories',
                '/AddType\s+application\/x-httpd-php/i' => 'AddType PHP handler - possible arbitrary PHP execution',
                '/AddHandler\s+(cgi-script|php\d?-script)/i' => 'AddHandler script execution',
                '/Options\s+.*-Indexes/i' => false, // Fine
                '/Options\s+.*\+Indexes/i' => 'Directory indexing is enabled - information disclosure',
                '/Allow\s+from\s+all/i' => 'Permissive access control',
                '/Satisfy\s+any/i' => 'Loose authentication requirement',
                '/SetEnvIfNoCase\s+.*phpMyAdmin/i' => 'References phpMyAdmin - possible misconfiguration',
                '/\<FilesMatch\s*".*\.php"/i' => false, // Check further
            ];

            $fullContent = $content;
            foreach ($dangerousHtaccess as $pattern => $message) {
                if ($message === false) continue;
                if (preg_match($pattern, $fullContent)) {
                    $findings[] = [
                        'file'     => $file->getRealPath(),
                        'line'     => 0,
                        'pattern'  => 'dangerous_htaccess',
                        'severity' => 'high',
                        'type'     => 'generic',
                        'message'  => $message,
                    ];
                }
            }
        }

        return $findings;
    }

    private function checkGitExposure(): array
    {
        $findings = [];
        $gitDir = $this->path . '/.git';

        if (!is_dir($gitDir)) return $findings;

        // Check if .git is accessible from the web (common vulnerability)
        $gitHead = $gitDir . '/HEAD';
        if (file_exists($gitHead) && is_readable($gitHead)) {
            $findings[] = [
                'file'     => $gitHead,
                'line'     => 0,
                'pattern'  => 'git_exposure',
                'severity' => 'high',
                'type'     => 'generic',
                'message'  => '.git directory is present and accessible. Attackers can download the entire repository history.',
            ];

            // Check for sensitive files in git history
            $gitConfig = $gitDir . '/config';
            if (file_exists($gitConfig)) {
                $config = file_get_contents($gitConfig);
                if (preg_match('/\[remote\s+"origin"\]\s*\n\s*url\s*=\s*(.+)/i', $config, $m)) {
                    $url = $m[1];
                    if (str_contains($url, '://') && !str_contains($url, 'github.com') && !str_contains($url, 'gitlab')) {
                        // Could be a private remote - info only
                    }
                }
            }
        }

        return $findings;
    }

    private function checkPhpConfig(): array
    {
        $findings = [];
        $phpIni = $this->path . '/php.ini';

        if (!file_exists($phpIni)) {
            $phpIni = $this->path . '/.user.ini';
            if (!file_exists($phpIni)) return $findings;
        }

        $content = file_get_contents($phpIni);

        $dangerousSettings = [
            '/^display_errors\s*=\s*On/i' => 'display_errors is enabled - may expose sensitive paths and configurations',
            '/^display_startup_errors\s*=\s*On/i' => 'display_startup_errors is enabled',
            '/^allow_url_fopen\s*=\s*On/i' => 'allow_url_fopen is enabled - remote file inclusion risk',
            '/^allow_url_include\s*=\s*On/i' => 'allow_url_include is enabled - CRITICAL remote file inclusion risk',
            '/^expose_php\s*=\s*On/i' => 'expose_php is enabled - PHP version is exposed in headers',
            '/^file_uploads\s*=\s*On/i' => false, // Fine normally
            '/^upload_max_filesize\s*=\s*\d+M/i' => false, // Fine
            '/^disable_functions\s*=\s*$/i' => 'disable_functions is empty - all PHP functions are available for exploitation',
        ];

        foreach ($dangerousSettings as $pattern => $message) {
            if ($message === false) continue;
            if (preg_match($pattern, $content)) {
                $findings[] = [
                    'file'     => $phpIni,
                    'line'     => 0,
                    'pattern'  => 'dangerous_php_setting',
                    'severity' => 'high',
                    'type'     => 'generic',
                    'message'  => $message,
                ];
            }
        }

        return $findings;
    }

    private function checkBackupFiles(): array
    {
        if ($this->options['no-backup']) return [];

        $findings = [];
        $backupPatterns = [
            '/\.bak$/i', '/\.backup$/i', '/\.old$/i', '/\.orig$/i',
            '/\.swp$/i', '/~$/', '/\.save$/i', '/\.copy$/i',
            '/\.php\.old$/i', '/\.php\.bak$/i', '/\.php~$/i',
            '/\.sql\.bak$/i', '/\.sql\.old$/i',
            '/\.env\.bak$/i', '/\.env\.old$/i', '/\.env\.save$/i',
            '/\.gitignore\.bak/i',
        ];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        $backupCount = 0;
        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $name = $file->getBasename();
            foreach ($backupPatterns as $pattern) {
                if (preg_match($pattern, $name)) {
                    $backupCount++;
                    if ($backupCount <= 10) {
                        $ext = strtolower($file->getExtension());
                        $severity = in_array($ext, ['php', 'sql', 'env']) ? 'high' : 'medium';
                        $findings[] = [
                            'file'     => $file->getRealPath(),
                            'line'     => 0,
                            'pattern'  => 'backup_file',
                            'severity' => $severity,
                            'type'     => 'generic',
                            'message'  => "Backup file found: {$name} - may expose source code or sensitive data",
                        ];
                    }
                }
            }
        }

        if ($backupCount > 10) {
            $findings[] = [
                'file'     => $this->path,
                'line'     => 0,
                'pattern'  => 'multiple_backups',
                'severity' => 'high',
                'type'     => 'generic',
                'message'  => "Total of $backupCount backup/temp files found across the project",
            ];
        }

        return $findings;
    }

    private function checkInformationDisclosure(): array
    {
        $findings = [];

        // Check for phpinfo() in codebase
        $directoryIterator = new \RecursiveDirectoryIterator($this->path, \FilesystemIterator::SKIP_DOTS);
        $filterIterator = new \RecursiveCallbackFilterIterator($directoryIterator, function ($current, $key, $iterator) {
            if ($iterator->hasChildren()) {
                $dirName = $current->getBasename();
                return !(str_starts_with($dirName, '.') || $dirName === 'vendor' || $dirName === 'node_modules' ||
                         $dirName === 'storage' || $dirName === 'cache');
            }
            if (!$current->isFile()) return false;
            if (!in_array(strtolower($current->getExtension()), ['php', 'phtml', 'php5', 'html', 'htm'])) return false;
            if ($current->getSize() > 10 * 1024 * 1024) return false;
            return true;
        });
        $iterator = new \RecursiveIteratorIterator($filterIterator, \RecursiveIteratorIterator::SELF_FIRST);

        $phpinfoFiles = [];
        set_time_limit(0);
        foreach ($iterator as $file) {
            $found = false;
            $handle = @fopen($file->getRealPath(), 'r');
            if ($handle) {
                while (!feof($handle)) {
                    $chunk = @fread($handle, 8192);
                    if ($chunk === false || $chunk === '') break;
                    if (preg_match('/\bphpinfo\s*\(\s*\)/', $chunk)) {
                        $found = true;
                        break;
                    }
                }
                fclose($handle);
            }
            if ($found) {
                $phpinfoFiles[] = $file->getRealPath();
            }
        }

        foreach (array_slice($phpinfoFiles, 0, 5) as $f) {
            $findings[] = [
                'file'     => $f,
                'line'     => 0,
                'pattern'  => 'phpinfo_exposed',
                'severity' => 'high',
                'type'     => 'generic',
                'message'  => 'phpinfo() call found - exposes extensive PHP/Server configuration',
            ];
        }

        // Check for README files that might contain sensitive info
        $readmeFiles = glob($this->path . '/README*');
        foreach ($readmeFiles as $rf) {
            // Just info - these are usually fine
        }

        return $findings;
    }
}
