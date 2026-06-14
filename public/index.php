<?php
/**
 * WebGuardian - Web Dashboard
 *
 * Production-grade security scanner UI built with Tailwind CSS.
 * Start with: php -S localhost:8080 -t public/
 */

require_once __DIR__ . '/../vendor/autoload.php';

use WebGuardian\Scanner;
use WebGuardian\Detector\MalwareDetector;
use WebGuardian\Report\ReportGenerator;
use WebGuardian\Report\Formatters\JsonFormatter;

// ---- API Endpoints ----
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['api'])) {
    header('Content-Type: application/json');

    if ($_GET['api'] === 'rules_status') {
        // Count built-in patterns
        $detector = new MalwareDetector(['no_external' => true]);
        $ref = new ReflectionMethod($detector, 'loadBuiltinPatterns');
        $ref->setAccessible(true);
        $builtinPatterns = $ref->invoke($detector);

        // Count external patterns
        $externalDir = __DIR__ . '/../rules/external';
        $externalCount = 0;
        $externalFiles = [];
        if (is_dir($externalDir)) {
            foreach (new FilesystemIterator($externalDir, FilesystemIterator::SKIP_DOTS) as $f) {
                if ($f->getExtension() !== 'json' || $f->getBasename() === '.merged.json') continue;
                $content = @file_get_contents($f->getRealPath());
                if ($content) {
                    $data = json_decode($content, true);
                    $c = count($data['patterns'] ?? []);
                    $externalCount += $c;
                    $externalFiles[] = [
                        'name'    => $f->getBasename(),
                        'size'    => $f->getSize(),
                        'patterns'=> $c,
                        'updated' => date('Y-m-d H:i:s', $f->getMTime()),
                    ];
                }
            }
        }

        // Last update time
        $lastUpdate = 'never';
        $mergedFile = $externalDir . '/.merged.json';
        if (file_exists($mergedFile)) {
            $lastUpdate = date('Y-m-d H:i:s', filemtime($mergedFile));
        }

        echo json_encode([
            'success'        => true,
            'builtin'        => count($builtinPatterns),
            'external'       => $externalCount,
            'total'          => count($builtinPatterns) + $externalCount,
            'external_files' => $externalFiles,
            'last_update'    => $lastUpdate,
            'scanner_version'=> '1.0.0',
        ]);
        exit;
    }

    if ($_GET['api'] === 'update_rules') {
        $script = __DIR__ . '/../tools/update-rules.sh';
        if (!file_exists($script)) {
            echo json_encode(['success' => false, 'error' => 'Update script not found']);
            exit;
        }

        $output = [];
        $returnCode = 0;
        exec("bash $script --quiet 2>&1", $output, $returnCode);

        // Wait and re-read status
        $detector = new MalwareDetector();
        $ref = new ReflectionMethod($detector, 'loadBuiltinPatterns');
        $ref->setAccessible(true);
        $builtinPatterns = $ref->invoke($detector);

        $externalDir = __DIR__ . '/../rules/external';
        $externalCount = 0;
        if (is_dir($externalDir)) {
            foreach (new FilesystemIterator($externalDir, FilesystemIterator::SKIP_DOTS) as $f) {
                if ($f->getExtension() !== 'json' || $f->getBasename() === '.merged.json') continue;
                $content = @file_get_contents($f->getRealPath());
                if ($content) {
                    $data = json_decode($content, true);
                    $externalCount += count($data['patterns'] ?? []);
                }
            }
        }

        echo json_encode([
            'success'     => $returnCode === 0,
            'return_code' => $returnCode,
            'output'      => implode("\n", $output),
            'builtin'     => count($builtinPatterns),
            'external'    => $externalCount,
            'total'       => count($builtinPatterns) + $externalCount,
            'last_update' => date('Y-m-d H:i:s'),
        ]);
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Unknown API action']);
    exit;
}

// ---- Scan Logic ----
$scanResult = null;
$scanError = null;
$scanRunning = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['scan_path'])) {
    $scanRunning = true;
    $path = $_POST['scan_path'];
    $type = $_POST['scan_type'] ?? 'auto';
    $depth = (int)($_POST['scan_depth'] ?? 10);
    $checkBackup = isset($_POST['check_backup']);
    $checkPerm = isset($_POST['check_perm']);

    if (!is_dir($path)) {
        $scanError = "Directory does not exist or is not readable: " . htmlspecialchars($path);
        $scanRunning = false;
    } else {
        try {
            $options = [
                'type'      => $type,
                'depth'     => $depth,
                'no-backup' => !$checkBackup,
                'no-perm'   => !$checkPerm,
                'verbose'   => false,
            ];

            $scanner = new Scanner($path, $options);
            $results = $scanner->run();

            $generator = new ReportGenerator($results);
            $report = $generator->generate();

            $jsonFormatter = new JsonFormatter();
            $scanResult = json_decode($jsonFormatter->format($report), true);
            $scanRunning = false;
        } catch (\Exception $e) {
            $scanError = "Scan error: " . $e->getMessage();
            $scanRunning = false;
        }
    }
}

// Count rules for display
$detector = new MalwareDetector();
$ref = new ReflectionMethod($detector, 'loadBuiltinPatterns');
$ref->setAccessible(true);
$builtinCount = count($ref->invoke($detector));

$externalDir = __DIR__ . '/../rules/external';
$externalCount = 0;
if (is_dir($externalDir)) {
    foreach (new FilesystemIterator($externalDir, FilesystemIterator::SKIP_DOTS) as $f) {
        if ($f->getExtension() !== 'json' || $f->getBasename() === '.merged.json') continue;
        $content = @file_get_contents($f->getRealPath());
        if ($content) {
            $data = json_decode($content, true);
            $externalCount += count($data['patterns'] ?? []);
        }
    }
}

$lastUpdate = 'Never';
$mergedFile = $externalDir . '/.merged.json';
if (file_exists($mergedFile)) {
    $lastUpdate = date('Y-m-d H:i:s', filemtime($mergedFile));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebGuardian - Security Scanner Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Inter', system-ui, sans-serif; }
        @keyframes pulse-slow { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        @keyframes slide-up { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes scan-progress { 0% { width: 0%; } 30% { width: 30%; } 60% { width: 60%; } 100% { width: 100%; } }
        @keyframes spin-slow { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .animate-slide-up { animation: slide-up 0.5s ease-out; }
        .animate-scan { animation: scan-progress 2s ease-in-out infinite; }
        .animate-spin-slow { animation: spin-slow 2s linear infinite; }
        [x-cloak] { display: none !important; }
    </style>
</head>
<body class="bg-gradient-to-br from-slate-50 to-slate-100 min-h-screen">
    <!-- Navigation -->
    <nav class="bg-white border-b border-slate-200 shadow-sm">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                        <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                        </svg>
                    </div>
                    <div>
                        <h1 class="text-xl font-bold text-slate-900">WebGuardian</h1>
                        <p class="text-xs text-slate-500 -mt-0.5">Security Scanner Dashboard</p>
                    </div>
                </div>
                <div class="flex items-center gap-4">
                    <span class="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 bg-emerald-50 text-emerald-700 rounded-full text-xs font-medium">
                        <span class="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></span>
                        v1.0.0
                    </span>
                    <a href="https://github.com/nathanpixodeo/webguardian" target="_blank" class="text-slate-400 hover:text-slate-600 transition-colors">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Hero -->
        <div class="text-center mb-10 animate-slide-up">
            <h2 class="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
                Malware &amp; Security Scanner
            </h2>
            <p class="mt-3 text-lg text-slate-500 max-w-2xl mx-auto">
                Detect malware, backdoors, vulnerabilities, and security misconfigurations in WordPress, Laravel, and PHP applications.
            </p>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Sidebar -->
            <div class="lg:col-span-1 space-y-6">
                <!-- Scan Form -->
                <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
                    <h3 class="text-lg font-semibold text-slate-900 mb-5 flex items-center gap-2">
                        <svg class="w-5 h-5 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                        New Scan
                    </h3>

                    <form method="POST" action="" id="scanForm" class="space-y-5">
                        <div>
                            <label for="scan_path" class="block text-sm font-medium text-slate-700 mb-1.5">Target Path <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-4 w-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                                    </svg>
                                </div>
                                <input type="text" name="scan_path" id="scan_path" required
                                    placeholder="/var/www/html or ."
                                    class="w-full pl-10 pr-4 py-2.5 border border-slate-300 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 placeholder:text-slate-400 transition-shadow"
                                    value="<?= htmlspecialchars($_POST['scan_path'] ?? getcwd()) ?>">
                            </div>
                        </div>

                        <div>
                            <label for="scan_type" class="block text-sm font-medium text-slate-700 mb-1.5">CMS Type</label>
                            <select name="scan_type" id="scan_type" class="w-full px-4 py-2.5 border border-slate-300 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500">
                                <option value="auto" <?= ($_POST['scan_type'] ?? 'auto') === 'auto' ? 'selected' : '' ?>>Auto Detect</option>
                                <option value="wordpress" <?= ($_POST['scan_type'] ?? '') === 'wordpress' ? 'selected' : '' ?>>WordPress</option>
                                <option value="laravel" <?= ($_POST['scan_type'] ?? '') === 'laravel' ? 'selected' : '' ?>>Laravel</option>
                                <option value="generic" <?= ($_POST['scan_type'] ?? '') === 'generic' ? 'selected' : '' ?>>Generic PHP</option>
                            </select>
                        </div>

                        <div>
                            <label for="scan_depth" class="block text-sm font-medium text-slate-700 mb-1.5">Max Depth</label>
                            <input type="number" name="scan_depth" id="scan_depth" min="1" max="50"
                                value="<?= (int)($_POST['scan_depth'] ?? 10) ?>"
                                class="w-full px-4 py-2.5 border border-slate-300 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500">
                        </div>

                        <div class="space-y-3">
                            <label class="text-sm font-medium text-slate-700 block">Options</label>
                            <label class="flex items-center gap-3 cursor-pointer group">
                                <input type="checkbox" name="check_backup" <?= isset($_POST['check_backup']) ? 'checked' : '' ?>
                                    class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">
                                <span class="text-sm text-slate-600 group-hover:text-slate-800">Check backup files</span>
                            </label>
                            <label class="flex items-center gap-3 cursor-pointer group">
                                <input type="checkbox" name="check_perm" checked
                                    class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">
                                <span class="text-sm text-slate-600 group-hover:text-slate-800">Check file permissions</span>
                            </label>
                        </div>

                        <button type="submit" id="scanBtn"
                            class="w-full py-3 px-6 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl shadow-lg shadow-indigo-200 hover:shadow-xl hover:from-indigo-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed">
                            <span id="scanBtnText" class="flex items-center justify-center gap-2">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                                </svg>
                                Start Scan
                            </span>
                        </button>
                    </form>

                    <div class="mt-6 pt-5 border-t border-slate-100">
                        <h4 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Quick Tips</h4>
                        <ul class="space-y-2 text-xs text-slate-500">
                            <li class="flex items-start gap-2">
                                <svg class="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                                Use <code class="bg-slate-100 px-1 rounded">.</code> for current directory
                            </li>
                            <li class="flex items-start gap-2">
                                <svg class="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                                Ctrl+Enter to submit
                            </li>
                        </ul>
                    </div>
                </div>

                <!-- Rules Version Card -->
                <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6" id="rulesCard">
                    <h3 class="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                        <svg class="w-5 h-5 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
                        </svg>
                        Detection Rules
                    </h3>

                    <div id="rulesStatus" class="space-y-4">
                        <!-- Status display (static initial, updated via API) -->
                        <div class="grid grid-cols-2 gap-3">
                            <div class="bg-indigo-50 rounded-xl p-3 text-center">
                                <div class="text-2xl font-bold text-indigo-600" id="builtinCount"><?= $builtinCount ?></div>
                                <div class="text-xs text-indigo-500 mt-0.5">Built-in</div>
                            </div>
                            <div class="bg-purple-50 rounded-xl p-3 text-center">
                                <div class="text-2xl font-bold text-purple-600" id="externalCount"><?= $externalCount ?></div>
                                <div class="text-xs text-purple-500 mt-0.5">External</div>
                            </div>
                        </div>

                        <div class="text-center">
                            <div class="text-xs text-slate-400">Total: <span id="totalCount"><?= $builtinCount + $externalCount ?></span> patterns</div>
                        </div>

                        <div class="bg-slate-50 rounded-xl px-3 py-2 text-xs text-slate-500 flex items-center justify-between">
                            <span>Last update:</span>
                            <span id="lastUpdate" class="font-medium text-slate-700"><?= $lastUpdate ?></span>
                        </div>

                        <!-- Action buttons -->
                        <div class="flex gap-2">
                            <button id="checkVersionBtn"
                                onclick="checkRulesVersion()"
                                class="flex-1 py-2 px-3 bg-white border border-slate-300 rounded-xl text-xs font-medium text-slate-700 hover:bg-slate-50 hover:border-slate-400 transition-all flex items-center justify-center gap-1.5">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                </svg>
                                Check Version
                            </button>
                            <button id="updateRulesBtn"
                                onclick="updateRules()"
                                class="flex-1 py-2 px-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-xl text-xs font-medium hover:from-indigo-700 hover:to-purple-700 transition-all flex items-center justify-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                </svg>
                                Update Now
                            </button>
                        </div>

                        <!-- Update output (hidden by default) -->
                        <div id="updateOutput" class="hidden">
                            <div class="bg-slate-900 text-green-400 rounded-xl p-3 text-xs font-mono max-h-32 overflow-y-auto" id="updateLog"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Results Area -->
            <div class="lg:col-span-2 space-y-6">
                <?php if ($scanRunning): ?>
                    <!-- Loading -->
                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-10 text-center animate-slide-up">
                        <div class="w-16 h-16 bg-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-5">
                            <svg class="w-8 h-8 text-indigo-600 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                            </svg>
                        </div>
                        <h3 class="text-xl font-semibold text-slate-900 mb-2">Scanning in Progress...</h3>
                        <p class="text-slate-500 mb-6">Analyzing files for malware, backdoors, and vulnerabilities</p>
                        <div class="max-w-md mx-auto">
                            <div class="h-2 bg-slate-100 rounded-full overflow-hidden">
                                <div class="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full animate-scan"></div>
                            </div>
                            <p class="text-xs text-slate-400 mt-3"><?= htmlspecialchars($_POST['scan_path'] ?? '') ?></p>
                        </div>
                    </div>
                <?php elseif ($scanError): ?>
                    <!-- Error -->
                    <div class="bg-red-50 border border-red-200 rounded-2xl p-6 animate-slide-up">
                        <div class="flex items-start gap-4">
                            <div class="w-10 h-10 bg-red-100 rounded-xl flex items-center justify-center shrink-0">
                                <svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            </div>
                            <div>
                                <h3 class="font-semibold text-red-800">Scan Failed</h3>
                                <p class="text-sm text-red-600 mt-1"><?= $scanError ?></p>
                            </div>
                        </div>
                    </div>
                <?php elseif ($scanResult): ?>
                    <!-- Results Dashboard -->
                    <div class="animate-slide-up space-y-6">
                        <?php
                        $summary = $scanResult['summary'] ?? [];
                        $findings = $scanResult['findings'] ?? [];
                        $meta = $scanResult['metadata'] ?? [];
                        $total = $summary['total'] ?? 0;
                        $critical = $summary['critical'] ?? 0;
                        $high = $summary['high'] ?? 0;
                        $medium = $summary['medium'] ?? 0;
                        $low = $summary['low'] ?? 0;
                        $info = $summary['info'] ?? 0;

                        $severityColor = $critical > 0 ? 'red' : ($high > 0 ? 'orange' : ($medium > 0 ? 'yellow' : ($total > 0 ? 'blue' : 'emerald')));
                        $statusText = $critical > 0 ? 'Critical Issues Found' : ($high > 0 ? 'High Severity Issues' : ($medium > 0 ? 'Medium Severity' : ($total > 0 ? 'Low Severity' : 'Clean')));
                        ?>

                        <div class="<?= "bg-{$severityColor}-50 border-{$severityColor}-200" ?> border rounded-2xl p-6">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center gap-4">
                                    <div class="<?= "w-14 h-14 bg-{$severityColor}-100 rounded-2xl flex items-center justify-center" ?>">
                                        <?php if ($total === 0): ?>
                                        <svg class="w-7 h-7 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                                        <?php else: ?>
                                        <svg class="<?= "w-7 h-7 text-{$severityColor}-600" ?>" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                        <?php endif; ?>
                                    </div>
                                    <div>
                                        <h2 class="<?= "text-2xl font-bold text-{$severityColor}-900" ?>"><?= $statusText ?></h2>
                                        <p class="<?= "text-sm text-{$severityColor}-600" ?>">Scan completed in <?= number_format($meta['duration_ms'] ?? 0) ?>ms</p>
                                    </div>
                                </div>
                                <span class="hidden sm:inline-flex items-center px-3 py-1 <?= "bg-{$severityColor}-100 text-{$severityColor}-700" ?> rounded-full text-sm font-medium">
                                    <?= date('H:i:s', strtotime($meta['scanned_at'] ?? 'now')) ?>
                                </span>
                            </div>
                        </div>

                        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
                            <?php
                            $stats = [
                                ['label' => 'Total', 'count' => $total, 'color' => 'slate'],
                                ['label' => 'Critical', 'count' => $critical, 'color' => 'red'],
                                ['label' => 'High', 'count' => $high, 'color' => 'orange'],
                                ['label' => 'Medium', 'count' => $medium, 'color' => 'yellow'],
                                ['label' => 'Low', 'count' => $low, 'color' => 'blue'],
                                ['label' => 'Info', 'count' => $info, 'color' => 'gray'],
                            ];
                            foreach ($stats as $stat):
                                $c = $stat['color'];
                            ?>
                            <div class="bg-white rounded-xl border border-slate-200 p-4 text-center shadow-sm hover:shadow-md transition-shadow">
                                <div class="<?= "text-2xl sm:text-3xl font-bold text-{$c}-600" ?>"><?= $stat['count'] ?></div>
                                <div class="text-xs text-slate-500 font-medium mt-1"><?= $stat['label'] ?></div>
                            </div>
                            <?php endforeach; ?>
                        </div>

                        <div class="bg-white rounded-2xl border border-slate-200 shadow-sm">
                            <div class="px-6 py-4 border-b border-slate-100">
                                <h3 class="font-semibold text-slate-900">Scan Information</h3>
                            </div>
                            <div class="px-6 py-4">
                                <dl class="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                                    <div><dt class="text-slate-500">Path</dt><dd class="font-medium text-slate-900 truncate" title="<?= htmlspecialchars($meta['path'] ?? '') ?>"><?= htmlspecialchars($meta['path'] ?? '') ?></dd></div>
                                    <div><dt class="text-slate-500">CMS Type</dt><dd class="font-medium text-slate-900 capitalize"><?= htmlspecialchars($meta['type'] ?? '') ?></dd></div>
                                    <div><dt class="text-slate-500">Files Scanned</dt><dd class="font-medium text-slate-900"><?= number_format($meta['files_scanned'] ?? 0) ?></dd></div>
                                    <div><dt class="text-slate-500">Duration</dt><dd class="font-medium text-slate-900"><?= number_format($meta['duration_ms'] ?? 0) ?>ms</dd></div>
                                </dl>
                            </div>
                        </div>

                        <?php if (!empty($findings)): ?>
                        <div class="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                            <div class="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
                                <h3 class="font-semibold text-slate-900">Findings</h3>
                                <span class="text-xs text-slate-400"><?= count($findings) ?> issues</span>
                            </div>
                            <div class="divide-y divide-slate-100">
                                <?php foreach (array_slice($findings, 0, 100) as $i => $finding):
                                    $sev = $finding['severity'] ?? 'info';
                                    $sevColors = [
                                        'critical' => ['bg' => 'bg-red-50', 'border' => 'border-red-200', 'text' => 'text-red-800', 'badge' => 'bg-red-100 text-red-700', 'dot' => 'bg-red-500'],
                                        'high'     => ['bg' => 'bg-orange-50', 'border' => 'border-orange-200', 'text' => 'text-orange-800', 'badge' => 'bg-orange-100 text-orange-700', 'dot' => 'bg-orange-500'],
                                        'medium'   => ['bg' => 'bg-yellow-50', 'border' => 'border-yellow-200', 'text' => 'text-yellow-800', 'badge' => 'bg-yellow-100 text-yellow-700', 'dot' => 'bg-yellow-500'],
                                        'low'      => ['bg' => 'bg-blue-50', 'border' => 'border-blue-200', 'text' => 'text-blue-800', 'badge' => 'bg-blue-100 text-blue-700', 'dot' => 'bg-blue-500'],
                                        'info'     => ['bg' => 'bg-gray-50', 'border' => 'border-gray-200', 'text' => 'text-gray-600', 'badge' => 'bg-gray-100 text-gray-600', 'dot' => 'bg-gray-400'],
                                    ];
                                    $sc = $sevColors[$sev] ?? $sevColors['info'];
                                ?>
                                <div class="<?= "{$sc['bg']} px-6 py-4 finding-enter" ?>" style="animation-delay: <?= $i * 0.05 ?>s">
                                    <div class="flex items-start gap-3">
                                        <span class="w-2 h-2 rounded-full mt-2 shrink-0 <?= $sc['dot'] ?>"></span>
                                        <div class="flex-1 min-w-0">
                                            <div class="flex items-start justify-between gap-3">
                                                <p class="<?= "text-sm font-medium {$sc['text']}" ?>"><?= htmlspecialchars($finding['message'] ?? '') ?></p>
                                                <span class="<?= "shrink-0 px-2 py-0.5 rounded text-xs font-semibold {$sc['badge']}" ?>"><?= strtoupper($sev) ?></span>
                                            </div>
                                            <div class="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                                                <span class="truncate max-w-xs" title="<?= htmlspecialchars($finding['file'] ?? '') ?>"><?= htmlspecialchars(basename($finding['file'] ?? '')) ?></span>
                                                <?php if (!empty($finding['line'])): ?><span>Line <?= (int)$finding['line'] ?></span><?php endif; ?>
                                                <span class="text-slate-400"><?= htmlspecialchars($finding['pattern'] ?? '') ?></span>
                                            </div>
                                            <?php if (!empty($finding['file'])): ?>
                                            <p class="mt-1 text-xs text-slate-400 font-mono truncate" title="<?= htmlspecialchars($finding['file']) ?>"><?= htmlspecialchars($finding['file']) ?></p>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                                <?php endforeach; ?>
                            </div>
                            <?php if (count($findings) > 100): ?>
                            <div class="px-6 py-4 bg-slate-50 text-center text-sm text-slate-500">+ <?= count($findings) - 100 ?> more findings.</div>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <!-- Empty State -->
                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-12 text-center animate-slide-up">
                        <div class="w-20 h-20 bg-gradient-to-br from-indigo-50 to-purple-50 rounded-3xl flex items-center justify-center mx-auto mb-6 shadow-sm">
                            <svg class="w-10 h-10 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                        </div>
                        <h3 class="text-xl font-semibold text-slate-900 mb-2">Ready to Scan</h3>
                        <p class="text-slate-500 max-w-md mx-auto mb-6">
                            Enter a directory path on the left and click <strong>Start Scan</strong> to begin analyzing your project for security issues.
                        </p>
                        <div class="flex flex-wrap items-center justify-center gap-3 text-sm text-slate-400">
                            <span class="flex items-center gap-1.5"><svg class="w-4 h-4 text-emerald-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg> Malware detection</span>
                            <span class="flex items-center gap-1.5"><svg class="w-4 h-4 text-emerald-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg> Vulnerability scanning</span>
                            <span class="flex items-center gap-1.5"><svg class="w-4 h-4 text-emerald-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg> CMS security checks</span>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div class="bg-white rounded-xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition-shadow">
                            <div class="w-10 h-10 bg-red-100 rounded-xl flex items-center justify-center mb-3"><svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg></div>
                            <h4 class="font-semibold text-slate-900 text-sm mb-1">Malware Detection</h4>
                            <p class="text-xs text-slate-500">Signature + heuristic detection of web shells, backdoors, and obfuscated code.</p>
                        </div>
                        <div class="bg-white rounded-xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition-shadow">
                            <div class="w-10 h-10 bg-orange-100 rounded-xl flex items-center justify-center mb-3"><svg class="w-5 h-5 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg></div>
                            <h4 class="font-semibold text-slate-900 text-sm mb-1">Vulnerability Scan</h4>
                            <p class="text-xs text-slate-500">SQLi, XSS, LFI, SSRF, insecure deserialization, and more.</p>
                        </div>
                        <div class="bg-white rounded-xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition-shadow">
                            <div class="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center mb-3"><svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg></div>
                            <h4 class="font-semibold text-slate-900 text-sm mb-1">CMS Hardening</h4>
                            <p class="text-xs text-slate-500">WordPress & Laravel specific configuration and exposure checks.</p>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </main>

    <footer class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 mt-8 border-t border-slate-200">
        <div class="flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-slate-400">
            <p>WebGuardian v1.0.0 &mdash; Open Source Security Scanner</p>
            <div class="flex items-center gap-4">
                <a href="https://github.com/nathanpixodeo/webguardian" class="hover:text-slate-600 transition-colors">GitHub</a>
                <a href="#" class="hover:text-slate-600 transition-colors">Documentation</a>
                <a href="#" class="hover:text-slate-600 transition-colors">Report Issue</a>
            </div>
        </div>
    </footer>

    <script>
        // Form submission
        const form = document.getElementById('scanForm');
        const btn = document.getElementById('scanBtn');
        const btnText = document.getElementById('scanBtnText');

        if (form) {
            form.addEventListener('submit', function() {
                btn.disabled = true;
                btnText.innerHTML = `<svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Scanning...`;
            });
        }

        // Ctrl+Enter shortcut
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (form) form.requestSubmit();
            }
        });

        // ---- Rules Version Management ----

        async function checkRulesVersion() {
            const btn = document.getElementById('checkVersionBtn');
            const originalHTML = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = `<svg class="w-3.5 h-3.5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Checking...`;

            try {
                const res = await fetch('?api=rules_status');
                const data = await res.json();

                if (data.success) {
                    document.getElementById('builtinCount').textContent = data.builtin;
                    document.getElementById('externalCount').textContent = data.external;
                    document.getElementById('totalCount').textContent = data.total;
                    document.getElementById('lastUpdate').textContent = data.last_update;

                    // Flash effect on card
                    const card = document.getElementById('rulesStatus');
                    card.classList.add('animate-slide-up');
                    setTimeout(() => card.classList.remove('animate-slide-up'), 500);

                    btn.innerHTML = `<svg class="w-3.5 h-3.5 text-emerald-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> Version Checked`;
                    setTimeout(() => { btn.innerHTML = originalHTML; btn.disabled = false; }, 2000);
                } else {
                    throw new Error('API error');
                }
            } catch (err) {
                btn.innerHTML = '<span class="text-red-500">Failed</span>';
                setTimeout(() => { btn.innerHTML = originalHTML; btn.disabled = false; }, 2000);
            }
        }

        async function updateRules() {
            const btn = document.getElementById('updateRulesBtn');
            const output = document.getElementById('updateOutput');
            const log = document.getElementById('updateLog');
            const originalHTML = btn.innerHTML;

            btn.disabled = true;
            btn.innerHTML = `<svg class="w-3.5 h-3.5 animate-spin-slow" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Updating...`;
            output.classList.remove('hidden');
            log.textContent = 'Connecting to sources...\n';

            try {
                const res = await fetch('?api=update_rules');
                const data = await res.json();

                if (data.success) {
                    log.textContent += `✓ Sources processed\n`;
                    log.textContent += `  Built-in: ${data.builtin} patterns\n`;
                    log.textContent += `  External: ${data.external} patterns\n`;
                    log.textContent += `  Total: ${data.total} patterns\n`;
                    log.textContent += `  Last update: ${data.last_update}\n`;

                    // Update status display
                    document.getElementById('builtinCount').textContent = data.builtin;
                    document.getElementById('externalCount').textContent = data.external;
                    document.getElementById('totalCount').textContent = data.total;
                    document.getElementById('lastUpdate').textContent = data.last_update;

                    log.textContent += `\n✓ Update complete!`;

                    btn.innerHTML = `<svg class="w-3.5 h-3.5 text-white" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> Updated`;
                    setTimeout(() => { btn.innerHTML = originalHTML; btn.disabled = false; }, 3000);
                } else {
                    throw new Error(data.error || 'Update failed');
                }
            } catch (err) {
                log.textContent += `✗ Error: ${err.message}\n`;
                btn.innerHTML = 'Failed';
                setTimeout(() => { btn.innerHTML = originalHTML; btn.disabled = false; }, 3000);
            }
        }

        // Auto-check rules version on page load
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(checkRulesVersion, 1000);
        });
    </script>
</body>
</html>
