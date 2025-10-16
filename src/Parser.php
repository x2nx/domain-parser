<?php

namespace X2nx\DomainParser;

use X2nx\DomainParser\Parsers\WhoisParser;
use X2nx\DomainParser\Parsers\RdapParser;
use X2nx\DomainParser\Formatters\WhoisFormatter;
use X2nx\DomainParser\Formatters\RdapFormatter;

/**
 * 域名解析器
 * 
 * 解析域名结构并提供WHOIS/RDAP查询功能
 */
class Parser
{
    /**
     * 域名后缀列表
     *
     * @var array<string, array{suffix: string, type: string, whois?: string, rdap?: string}>
     */
    protected static $list = [];

    /**
     * 完整域名
     *
     * @var string
     */
    protected $domain = '';

    /**
     * 顶级域（TLD）
     *
     * @var string
     */
    protected $tld = '';

    /**
     * 公共后缀
     *
     * @var string
     */
    protected $suffix = '';

    /**
     * 域名名称（不含后缀）
     *
     * @var string
     */
    protected $name = '';

    /**
     * 子域名
     *
     * @var string
     */
    protected $sub = '';

    /**
     * PSL规则
     *
     * @var string
     */
    protected $rule = '';

    /**
     * 域名各部分
     *
     * @var string[]
     */
    protected $parts = [];

    /**
     * 构造函数
     *
     * @param string $domain 域名
     * @throws \InvalidArgumentException
     */
    public function __construct(string $domain)
    {
        // 验证域名格式
        if (strpos($domain, 'http://') === 0 || strpos($domain, 'https://') === 0) {
            throw new \InvalidArgumentException("Invalid domain: {$domain}. Please remove http:// or https://");
        }

        $this->domain = mb_strtolower($domain);
        $this->parts = explode('.', $this->domain);

        // 加载域名后缀列表
        if (empty(self::$list)) {
            self::$list = include __DIR__ . '/../data/data.php';
        }
    }

    /**
     * 获取完整域名
     *
     * @return string
     */
    public function get(): string
    {
        return $this->domain;
    }

    /**
     * 获取顶级域（TLD）
     *
     * @return string
     */
    public function getTLD(): string
    {
        if ($this->tld) {
            return $this->tld;
        }

        if (empty($this->parts)) {
            return '';
        }

        $this->tld = end($this->parts);

        return $this->getRegisterable();
    }

    /**
     * 获取公共后缀
     *
     * @return string
     */
    public function getSuffix(): string
    {
        if ($this->suffix) {
            return $this->suffix;
        }

        for ($i = 0; $i < count($this->parts); $i++) {
            $joined = implode('.', array_slice($this->parts, $i));
            $next = implode('.', array_slice($this->parts, $i + 1));
            $exception = '!' . $joined;
            $wildcard = '*.' . $next;

            if (array_key_exists($exception, self::$list)) {
                $this->suffix = $next;
                $this->rule = $exception;
                return $next;
            }

            if (array_key_exists($joined, self::$list)) {
                $this->suffix = $joined;
                $this->rule = $joined;
                return $joined;
            }

            if (array_key_exists($wildcard, self::$list)) {
                $this->suffix = $joined;
                $this->rule = $wildcard;
                return $joined;
            }
        }

        return '';
    }

    /**
     * 获取PSL规则
     *
     * @return string
     */
    public function getRule(): string
    {
        if (!$this->rule) {
            $this->getSuffix();
        }
        return $this->rule;
    }

    /**
     * 获取可注册域名
     *
     * @return string
     */
    public function getRegisterable(): string
    {
        if (!$this->isKnown()) {
            return '';
        }

        $registerable = $this->getName() . '.' . $this->getSuffix();

        return $registerable;
    }

    /**
     * 获取域名名称（不含后缀和子域名）
     *
     * @return string
     */
    public function getName(): string
    {
        if ($this->name) {
            return $this->name;
        }

        $suffix = $this->getSuffix();
        $suffix = (!empty($suffix)) ? '.' . $suffix : '.' . $this->getTLD();

        $name = explode('.', mb_substr($this->domain, 0, mb_strlen($suffix) * -1));

        $this->name = end($name);

        return $this->name;
    }

    /**
     * 获取子域名
     *
     * @return string
     */
    public function getSub(): string
    {
        $name = $this->getName();
        $name = (!empty($name)) ? '.' . $name : '';

        $suffix = $this->getSuffix();
        $suffix = (!empty($suffix)) ? '.' . $suffix : '.' . $this->getTLD();

        $domain = $name . $suffix;

        $sub = explode('.', mb_substr($this->domain, 0, mb_strlen($domain) * -1));

        $this->sub = implode('.', $sub);

        return $this->sub;
    }

    /**
     * 获取WHOIS服务器地址
     *
     * @return string
     */
    public function getWhoisServer(): string
    {
        if (!array_key_exists($this->getSuffix(), self::$list)) {
            return '';
        }

        return self::$list[$this->getSuffix()]['whois'] ?? '';
    }

    /**
     * 获取WHOIS原始信息
     *
     * @return string
     */
    public function getWhoisInfo(): string
    {
        $server = $this->getWhoisServer();
        if (empty($server)) {
            return '';
        }

        try {
            $registerable = $this->getRegisterable();
            if (empty($registerable)) {
                return '';
            }

            $response = $this->queryWhois($server, $registerable);
            return $response;
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * 获取格式化的WHOIS信息
     *
     * @return string
     */
    public function getWhoisFormatted(): string
    {
        $whoisInfo = $this->getWhoisInfo();

        if (empty($whoisInfo)) {
            return '';
        }

        $parsed = WhoisParser::parse($whoisInfo);
        return WhoisFormatter::format($parsed);
    }

    /**
     * 获取解析后的WHOIS结构化数据
     *
     * @return array
     */
    public function getWhoisParsed(): array
    {
        $whoisInfo = $this->getWhoisInfo();

        if (empty($whoisInfo)) {
            return [];
        }

        return WhoisParser::parse($whoisInfo);
    }

    /**
     * 获取RDAP服务器地址
     *
     * @return string
     */
    public function getRdapServer(): string
    {
        if (!array_key_exists($this->getSuffix(), self::$list)) {
            return '';
        }

        return self::$list[$this->getSuffix()]['rdap'] ?? '';
    }

    /**
     * 获取RDAP原始信息（JSON格式）
     *
     * @return string
     */
    public function getRdapInfo(): string
    {
        $server = $this->getRdapServer();
        if (empty($server)) {
            return '';
        }

        try {
            $registerable = $this->getRegisterable();
            if (empty($registerable)) {
                return '';
            }

            $url = rtrim($server, '/') . '/domain/' . $registerable;
            $response = $this->queryRdap($url);
            return $response;
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * 获取格式化的RDAP信息
     *
     * @return string
     */
    public function getRdapFormatted(): string
    {
        $rdapInfo = $this->getRdapInfo();

        if (empty($rdapInfo)) {
            return '';
        }

        return RdapFormatter::format($rdapInfo);
    }

    /**
     * 获取RDAP摘要信息
     *
     * @return array
     */
    public function getRdapSummary(): array
    {
        $rdapInfo = $this->getRdapInfo();

        if (empty($rdapInfo)) {
            return [];
        }

        return RdapParser::getSummary($rdapInfo);
    }

    /**
     * 获取解析后的RDAP结构化数据
     *
     * @return array
     */
    public function getRdapParsed(): array
    {
        $rdapInfo = $this->getRdapInfo();

        if (empty($rdapInfo)) {
            return [];
        }

        return RdapParser::parse($rdapInfo);
    }

    /**
     * 检查后缀是否已知
     *
     * @return bool
     */
    public function isKnown(): bool
    {
        return array_key_exists($this->getRule(), self::$list);
    }

    /**
     * 检查是否为ICANN域名
     *
     * @return bool
     */
    public function isICANN(): bool
    {
        if (isset(self::$list[$this->getRule()]) && self::$list[$this->getRule()]['type'] === 'ICANN') {
            return true;
        }

        return false;
    }

    /**
     * 检查是否为私有域名
     *
     * @return bool
     */
    public function isPrivate(): bool
    {
        if (isset(self::$list[$this->getRule()]) && self::$list[$this->getRule()]['type'] === 'PRIVATE') {
            return true;
        }

        return false;
    }

    /**
     * 检查是否为测试域名
     *
     * @return bool
     */
    public function isTest(): bool
    {
        return in_array($this->getTLD(), ['test', 'localhost']);
    }

    /**
     * 查询WHOIS服务器
     *
     * @param string $server WHOIS服务器地址
     * @param string $domain 域名
     * @param int $timeout 超时时间（秒）
     * @return string
     * @throws \RuntimeException
     */
    protected function queryWhois(string $server, string $domain, int $timeout = 10): string
    {
        $fp = @fsockopen($server, 43, $errno, $errstr, $timeout);

        if (!$fp) {
            throw new \RuntimeException("Cannot connect to WHOIS server {$server}: {$errstr} ({$errno})");
        }

        // 设置超时
        stream_set_timeout($fp, $timeout);

        // 发送查询
        fwrite($fp, $domain . "\r\n");

        // 读取响应
        $response = '';
        while (!feof($fp)) {
            $response .= fgets($fp, 128);
        }

        fclose($fp);

        return $response;
    }

    /**
     * 查询RDAP服务器
     *
     * @param string $url RDAP URL
     * @param int $timeout 超时时间（秒）
     * @return string
     * @throws \RuntimeException
     */
    protected function queryRdap(string $url, int $timeout = 10): string
    {
        // 优先使用curl
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Accept: application/rdap+json, application/json',
                'User-Agent: X2nx-DomainParser/3.0'
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);

            if ($response === false) {
                throw new \RuntimeException("RDAP query failed: {$error}");
            }

            if ($httpCode >= 400) {
                throw new \RuntimeException("RDAP query failed with HTTP {$httpCode}");
            }

            return $response;
        }

        // 降级使用file_get_contents
        $context = stream_context_create([
            'http' => [
                'timeout' => $timeout,
                'header' => "Accept: application/rdap+json, application/json\r\n" .
                           "User-Agent: X2nx-DomainParser/3.0\r\n"
            ]
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            throw new \RuntimeException("RDAP query failed");
        }

        return $response;
    }
}
