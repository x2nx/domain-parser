<?php

/**
 * Public Suffix List 数据导入工具
 * 
 * 从 publicsuffix.org 下载域名后缀列表并处理
 * 支持 WHOIS 和 RDAP 服务器信息获取
 */

// 配置
$config = [
    'psl_url' => 'https://publicsuffix.org/list/public_suffix_list.dat',
    'rdap_url' => 'https://data.iana.org/rdap/dns.json',
    'output_file' => __DIR__ . '/data.php',
    'cache_file' => __DIR__ . '/whois_cache.json',
    'request_interval' => 0.5, // WHOIS 查询间隔（秒）
    'timeout' => 10 // 连接超时时间（秒）
];

// 全局变量
$whoisCache = [];
$rdapServers = [];
$requestCount = 0;
$lastRequestTime = 0;

echo "=== Public Suffix List 数据导入工具 ===\n\n";

// 1. 加载缓存
loadWhoisCache();

// 2. 下载 Public Suffix List
echo "正在下载 Public Suffix List...\n";
$lines = downloadFile($config['psl_url']);
echo "下载完成，共 " . count($lines) . " 行\n\n";

// 3. 加载 RDAP 服务器数据
echo "正在加载 RDAP 服务器列表...\n";
loadRdapServers();
echo "RDAP 服务器加载完成，共 " . count($rdapServers) . " 个\n\n";

// 4. 处理数据
echo "开始处理域名后缀数据...\n";
$domains = processSuffixList($lines);

// 5. 保存数据
echo "\n正在保存数据文件...\n";
saveData($domains);

// 6. 保存缓存
saveWhoisCache();

echo "\n=== 导入完成 ===\n";
echo "总计处理: " . count($domains) . " 个域名后缀\n";
echo "WHOIS 缓存数量: " . count($whoisCache) . "\n";
echo "实际 WHOIS 查询次数: " . $requestCount . "\n";

// ========== 函数定义 ==========

/**
 * 加载 WHOIS 缓存
 */
function loadWhoisCache(): void
{
    global $whoisCache, $config;
    
    if (file_exists($config['cache_file'])) {
        $whoisCache = json_decode(file_get_contents($config['cache_file']), true) ?: [];
        echo "加载 WHOIS 缓存: " . count($whoisCache) . " 条记录\n";
    }
}

/**
 * 保存 WHOIS 缓存
 */
function saveWhoisCache(): void
{
    global $whoisCache, $config;
    
    file_put_contents(
        $config['cache_file'],
        json_encode($whoisCache, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)
    );
}

/**
 * 下载文件并按行分割
 * 
 * @param string $url 文件 URL
 * @return array 文件行数组
 */
function downloadFile(string $url): array
{
    $data = file_get_contents($url);
    
    if ($data === false) {
        die("错误: 无法下载文件 $url\n");
    }
    
    return explode("\n", $data);
}

/**
 * 加载 RDAP 服务器列表
 */
function loadRdapServers(): void
{
    global $rdapServers, $config;
    
    $data = file_get_contents($config['rdap_url']);
    
    if ($data === false) {
        die("错误: 无法下载 RDAP 服务器列表\n");
    }
    
    $rdapData = json_decode($data, true);
    
    if (!empty($rdapData['services'])) {
        foreach ($rdapData['services'] as $service) {
            [$suffixes, $servers] = $service;
            if (is_array($suffixes)) {
                foreach ($suffixes as $suffix) {
                    $rdapServers[$suffix] = current($servers);
                }
            }
        }
    }
}

/**
 * 处理 Public Suffix List
 * 
 * @param array $lines 文件行数组
 * @return array 处理后的域名数据
 */
function processSuffixList(array $lines): array
{
    global $rdapServers;
    
    $domains = [];
    $type = null;
    $comments = [];
    $processed = 0;
    
    foreach ($lines as $index => $line) {
        // 处理特殊标记
        if (strpos($line, '===BEGIN ICANN DOMAINS===') !== false) {
            $type = 'ICANN';
            $comments = [];
            continue;
        }
        
        if (strpos($line, '===END ICANN DOMAINS===') !== false) {
            $type = null;
            continue;
        }
        
        if (strpos($line, '===BEGIN PRIVATE DOMAINS===') !== false) {
            $type = 'PRIVATE';
            $comments = [];
            continue;
        }
        
        if (strpos($line, '===END PRIVATE DOMAINS===') !== false) {
            $type = null;
            continue;
        }
        
        // 跳过空行
        if (empty($line)) {
            continue;
        }
        
        // 处理注释
        if (mb_substr($line, 0, 3) === '// ') {
            $comments[] = mb_substr($line, 3);
            continue;
        }
        
        // 处理域名后缀
        $processed++;
        
        // 获取服务器信息
        $rdapServer = $rdapServers[$line] ?? '';
        $whoisServer = '';
        
        // 只有在没有 RDAP 数据时才查询 WHOIS
        if (empty($rdapServer)) {
            $whoisServer = getWhoisServer($line);
        }
        
        $domains[$line] = [
            'suffix' => $line,
            'type' => $type,
            'comments' => $comments,
            'whois' => $whoisServer,
            'rdap' => $rdapServer
        ];
        
        echo "[$processed] $line - RDAP: " . ($rdapServer ?: '无') 
            . " - WHOIS: " . ($whoisServer ?: '无') . "\n";
        
        $comments = [];
        
        // 显示进度统计
        if ($processed % 100 === 0) {
            echo "\n进度: 已处理 $processed 条记录\n";
        }
    }
    
    return $domains;
}

/**
 * 获取 WHOIS 服务器地址
 * 
 * @param string $domain 域名
 * @return string WHOIS 服务器地址
 */
function getWhoisServer(string $domain): string
{
    global $whoisCache;
    
    if (empty($domain)) {
        return '';
    }
    
    // 提取顶级域名
    $tld = extractTld($domain);
    
    // 检查缓存
    if (isset($whoisCache[$tld])) {
        echo "  [缓存命中] $domain -> {$whoisCache[$tld]}\n";
        return $whoisCache[$tld];
    }
    
    // 执行查询
    return queryWhoisServer($tld);
}

/**
 * 提取顶级域名
 * 
 * @param string $domain 域名
 * @return string 顶级域名
 */
function extractTld(string $domain): string
{
    if (strpos($domain, '.') === false) {
        return $domain;
    }
    
    $parts = explode('.', ltrim($domain, '*.!'));
    return end($parts);
}

/**
 * 查询 WHOIS 服务器
 * 
 * @param string $tld 顶级域名
 * @return string WHOIS 服务器地址
 */
function queryWhoisServer(string $tld): string
{
    global $whoisCache, $requestCount;
    
    // 限速
    throttle();
    
    echo "  [WHOIS查询] $tld...";
    
    // 执行查询
    $response = tcpRequest('whois.iana.org', 43, $tld);
    $requestCount++;
    
    if ($response['success'] && !empty($response['data'])) {
        // 解析 WHOIS 服务器地址
        if (preg_match('/^whois:\s+([a-z0-9][\w\.\-]*[a-z0-9])/im', $response['data'], $matches)) {
            $server = trim($matches[1]);
            if ($server === 'status') {
                $server = '';
            }
        } else {
            $server = '';
        }
        
        // 保存到缓存
        $whoisCache[$tld] = $server;
        
        // 定期保存缓存
        if ($requestCount % 10 === 0) {
            saveWhoisCache();
        }
        
        echo $server ? " 成功: $server\n" : " 无 WHOIS 服务器\n";
        
        return $server;
    }
    
    echo " 失败\n";
    
    $whoisCache[$tld] = '';
    return '';
}

/**
 * 限速
 */
function throttle(): void
{
    global $lastRequestTime, $config;
    
    $currentTime = microtime(true);
    $timeDiff = $currentTime - $lastRequestTime;
    
    if ($timeDiff < $config['request_interval']) {
        $sleepTime = ($config['request_interval'] - $timeDiff) * 1000000;
        usleep((int)$sleepTime);
    }
    
    $lastRequestTime = microtime(true);
}

/**
 * TCP 请求
 * 
 * @param string $host 目标主机
 * @param int $port 目标端口
 * @param string $data 发送的数据
 * @return array 响应数据
 */
function tcpRequest(string $host, int $port, string $data): array
{
    global $config;
    
    $socket = @fsockopen($host, $port, $errno, $errstr, $config['timeout']);
    
    if (!$socket) {
        return [
            'success' => false,
            'error' => $errstr ?? "连接失败 ($errno)"
        ];
    }
    
    stream_set_timeout($socket, $config['timeout']);
    stream_set_blocking($socket, 0);
    
    if (!empty($data)) {
        $send = fputs($socket, trim($data) . "\r\n");
        if (!$send) {
            fclose($socket);
            return [
                'success' => false,
                'error' => '写入数据失败'
            ];
        }
    }
    
    $rawContent = '';
    $null = null;
    $readArray = [$socket];
    
    while (!feof($socket)) {
        if (!empty($socket)) {
            if (stream_select($readArray, $null, $null, $config['timeout'])) {
                $rawContent .= fgets($socket, 1024);
            }
        }
    }
    
    fclose($socket);
    
    return [
        'success' => true,
        'data' => $rawContent
    ];
}

/**
 * 保存数据到文件
 * 
 * @param array $domains 域名数据
 */
function saveData(array $domains): void
{
    global $config;
    
    $code = "<?php\n\nreturn " . arrayToPhpCode($domains) . ';';
    file_put_contents($config['output_file'], $code);
}

/**
 * 将数组转换为 PHP 代码
 * 
 * @param array $data 数据数组
 * @param int $level 缩进级别
 * @return string PHP 代码
 */
function arrayToPhpCode(array $data, int $level = 0): string
{
    $output = "[\n";
    $level++;
    $tabs = str_repeat("\t", $level);
    
    foreach ($data as $key => $node) {
        $keyStr = is_int($key) ? '' : var_export($key, true) . ' => ';
        $valueStr = is_array($node) 
            ? arrayToPhpCode($node, $level) 
            : var_export($node, true);
        $output .= $tabs . $keyStr . $valueStr . ",\n";
    }
    
    $level--;
    $tabs = str_repeat("\t", $level);
    $output .= $tabs . ']';
    
    return $output;
}
