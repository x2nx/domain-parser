<?php

if (!function_exists('tcp_request')) {
    /**
     * @param string $host 目标主机
     * @param int $port 目标端口
     * @param string $data 需要发送的数据
     * @param int $timeout 超时时间
     * @return array
     */
    function tcp_request($host = 'whois.iana.org', $port = 43, $data = '', $timeout = 10) {
        // 创建 socket 资源
        $socket =  @fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$socket) {
            return [
                'status_code'   => 1001,
                'message'       => $errstr($errno)
            ];
        }
        stream_set_timeout($socket, $timeout);
        stream_set_blocking($socket, 0);
        if (!empty($data)) {
            // 发送数据到服务器
            $send = fputs($socket, trim($data) . "\r\n");
            if (!$send) {
                return [
                    'status_code'   => 1001,
                    'message'       => '写入数据失败'
                ];
            }
        }
        $rawContent = '';
        $null = null;
        $data = [$socket];
        while (!feof($socket)) {
            if (!empty($socket)) {
                if (stream_select($data, $null, $null, $timeout)) {
                    $rawContent.= fgets($socket, 1024);
                }
            }
        }
        // 关闭 socket 连接
        fclose($socket);
        return [
            'status_code'   => 1000,
            'message'       => 'ok',
            'data'          => $rawContent
        ];
    }
}

if (!function_exists('whois')) {
    /**
     * @param $domain string 输入查询的域名
     * @param bool $is_server 是否返回whois查询地址
     * @return false|mixed|string|void
     */
    function whois(string $domain = '',bool $is_server = false) {
        if (empty($domain)) return false;
        $data = tcp_request('whois.iana.org', 43, $domain);
        if ($data['status_code'] === 1000 && !empty($data['data'])) {
            preg_match('/whois:\s(.*)/', $data['data'], $whois);
            $server = trim($whois[1] ?? '');
            if ($is_server) {
                return $server;
            }
            $whois_info = tcp_request($server, 43, $domain);
            return $whois_info['status_code'] === 1000 ? $whois_info['data'] : '';
        }
    }
}

$data = file_get_contents('https://publicsuffix.org/list/public_suffix_list.dat');
if ($data === false) {
    throw new RuntimeException('Could not download public suffix list');
}

$list = explode("\n", $data);

function arrayToCode(array $data, $level = 0): string
{
    $output = '['."\n";

    $level++;

    $tabs = str_repeat("\t", $level);

    foreach ($data as $key => $node) {
        $key = is_int($key) ? '' : var_export($key, true).' => ';
        $value = is_array($node) ? arrayToCode($node, $level) : var_export($node, true);
        $output .= $tabs.$key.$value.",\n";
    }

    $level--;

    $tabs = str_repeat("\t", $level);

    $output .= $tabs.']';

    return $output;
}

$type = null;
$comments = [];
$domains = [];

foreach ($list as $key => $line) {
    if (mb_strpos($line, '===BEGIN ICANN DOMAINS===')) {
        $type = 'ICANN';
        $comments = [];

        continue;
    }

    if (mb_strpos($line, '===END ICANN DOMAINS===')) {
        $type = null;

        continue;
    }

    if (mb_strpos($line, '===BEGIN PRIVATE DOMAINS===')) {
        $type = 'PRIVATE';
        $comments = [];

        continue;
    }

    if (mb_strpos($line, '===END PRIVATE DOMAINS===')) {
        $type = null;

        continue;
    }

    if (empty($line)) {
        continue;
    }

    if (mb_substr($line, 0, mb_strlen('// ')) === '// ') {
        $comments[] = mb_substr($line, mb_strlen('// '));

        continue;
    }

    $domains[$line] = [
        'suffix'    => $line,
        'type'      => $type,
        'comments'  => $comments,
        'whois'     => whois($line, true)
    ];

    print_r($domains[$line]);
    sleep(1);

    $comments = [];
}

if (! isset($domains['com'])) {
    throw new RuntimeException('.com is missing from public suffix list; it must be corrupted');
}

file_put_contents(__DIR__.'/data.php', "<?php\n\nreturn ".arrayToCode($domains).';');
