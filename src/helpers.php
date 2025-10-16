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

if (!function_exists('iana_whois')) {
    /**
     * Returns whois info or server info
     * @param $domain string 输入查询的域名
     * @param bool $is_server 是否返回whois查询地址
     * @return false|mixed|string|void
     */
    function iana_whois(string $domain = '',bool $is_server = false) {
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

if (!function_exists('iana_domain')) {
    /**
     * Returns obtain complete domain name information
     * @param $domain 域名地址
     * @return array|false
     * @throws Exception
     */
    function iana_domain($domain = '') {
        if (empty($domain)) {
            return false;
        }
        $domain_info = new \X2nx\DomainParser\Core\DomainParser($domain);

        return [
            'domain'            => $domain_info->get(),
            'sub_domain'        => $domain_info->getSub(),
            'domain_name'       => $domain_info->getName(),
            'full_domain'       => $domain_info->getRegisterable(),
            'top_level_tld'     => $domain_info->getSuffix(),
            'whois_server'      => $domain_info->getWhoisServer(),
            'whois_info'        => $domain_info->getWhoisInfo(),
            'whois_formatted'   => $domain_info->getWhoisFormatted(),
            'whois_parsed'      => $domain_info->getWhoisParsed(),
            'rdap_server'       => $domain_info->getRdapServer(),
            'rdap_info'         => $domain_info->getRdapInfo(),
            'rdap_formatted'    => $domain_info->getRdapFormatted(),
            'rdap_summary'      => $domain_info->getRdapSummary(),
            'rdap_parsed'       => $domain_info->getRdapParsed(),
        ];
    }
}

if (!function_exists('iana_domain_info')) {
    /**
     * Returns whois or rdap info
     * @param $domain 域名地址
     * @return array|false
     */
    function iana_domain_info($domain = '') {
        if (empty($domain)) {
            return false;
        }
        $domain_info = new \X2nx\DomainParser\Parser($domain);

        $info = [];

        if (!empty($domain_info->getWhoisParsed())) {
            $info = $domain_info->getWhoisParsed();
        }
        if (!empty($domain_info->getRdapParsed())) {
            $info = $domain_info->getRdapParsed();
        }
        if (!empty($domain_info->getRdapFormatted())) {
            $info['parsed_text'] = $domain_info->getRdapFormatted();
        }
        if (!empty($domain_info->getWhoisFormatted())) {
            $info['parsed_text'] = $domain_info->getWhoisFormatted();
        }
        
        return $info;
    }
}