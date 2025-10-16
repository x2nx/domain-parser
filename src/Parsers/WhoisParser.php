<?php

namespace X2nx\DomainParser\Parsers;

use X2nx\DomainParser\Core\AbstractParser;

/**
 * WHOIS 文本解析器
 * 
 * 将各种 WHOIS 服务器返回的文本解析为结构化数据
 */
class WhoisParser extends AbstractParser
{
    /**
     * 解析 WHOIS 文本为结构化数据
     * 
     * @param string $whoisText WHOIS 原始文本
     * @return array 结构化的域名信息
     */
    public static function parse(string $whoisText): array
    {
        if (empty($whoisText)) {
            return [];
        }
        
        $data = self::getDefaultStructure();
        $data['raw_text'] = $whoisText;
        
        $lines = explode("\n", $whoisText);
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            // 跳过注释和空行
            if (empty($line) || strpos($line, '%') === 0 || strpos($line, '#') === 0 || strpos($line, '>>>') === 0) {
                continue;
            }
            
            // 解析键值对
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                if (empty($value)) {
                    continue;
                }
                
                self::parseKeyValue($data, strtolower($key), $value);
            }
        }
        
        // 后处理
        self::postProcess($data);
        
        return $data;
    }
    
    /**
     * 解析键值对
     * 
     * @param array &$data 数据数组
     * @param string $key 键名
     * @param string $value 值
     */
    private static function parseKeyValue(array &$data, string $key, string $value): void
    {
        // 域名基本信息
        if (self::matchesKey($key, ['domain name', '域名'])) {
            if (empty($data['domain'])) {
                $data['domain'] = $value;
            }
        } elseif (self::matchesKey($key, ['registry domain id', 'domain id', 'roid', '域名roid'])) {
            if (empty($data['domain_id'])) {
                $data['domain_id'] = $value;
            }
        } elseif (self::matchesKey($key, ['domain status', '域名状态'])) {
            $statusValue = trim(preg_split('/\s+http/i', $value)[0]);
            if (!empty($statusValue)) {
                $data['status'][] = $statusValue;
            }
        }
        // 注册商信息
        elseif (self::parseRegistrarInfo($data, $key, $value)) {
            // 注册商信息已处理
        }
        // 日期信息
        elseif (self::parseDateInfo($data, $key, $value)) {
            // 日期信息已处理
        }
        // 联系人信息
        elseif (self::parseContactInfo($data, $key, $value)) {
            // 联系人信息已处理
        }
        // 名称服务器
        elseif (self::matchesKey($key, ['name server', 'nameserver', 'nserver', 'name servers'])) {
            self::parseNameservers($data, $value);
        }
        // DNSSEC
        elseif (self::matchesKey($key, ['dnssec'])) {
            $data['dnssec'] = $value;
        }
    }
    
    /**
     * 解析注册商信息
     * 
     * @param array &$data 数据数组
     * @param string $key 键名
     * @param string $value 值
     * @return bool 是否处理了该键
     */
    private static function parseRegistrarInfo(array &$data, string $key, string $value): bool
    {
        $registrarFields = self::getRegistrarFields();
        
        foreach ($registrarFields as $field => $patterns) {
            if (self::matchesKey($key, $patterns)) {
                if ($field === 'name' && !empty($data['registrar']['name'])) {
                    return true; // 避免覆盖已存在的名称
                }
                $data['registrar'][$field] = $value;
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 解析日期信息
     * 
     * @param array &$data 数据数组
     * @param string $key 键名
     * @param string $value 值
     * @return bool 是否处理了该键
     */
    private static function parseDateInfo(array &$data, string $key, string $value): bool
    {
        $dateFields = self::getDateFields();
        
        foreach ($dateFields as $field => $patterns) {
            if (self::matchesKey($key, $patterns)) {
                if (empty($data['dates'][$field])) {
                    $data['dates'][$field] = $value;
                }
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 解析联系人信息
     * 
     * @param array &$data 数据数组
     * @param string $key 键名
     * @param string $value 值
     * @return bool 是否处理了该键
     */
    private static function parseContactInfo(array &$data, string $key, string $value): bool
    {
        $contactTypes = ['registrant', 'admin', 'tech', 'billing'];
        $contactFields = self::getContactFields();
        
        foreach ($contactTypes as $type) {
            foreach ($contactFields as $field => $patterns) {
                // 构建多种匹配模式
                $typePatterns = [];
                
                // 模式1: "type field" (如 "registrant email")
                foreach ($patterns as $pattern) {
                    $typePatterns[] = $type . ' ' . $pattern;
                }
                
                // 模式2: "type contact field" (如 "registrant contact email")
                foreach ($patterns as $pattern) {
                    $typePatterns[] = $type . ' contact ' . $pattern;
                }
                
                // 模式3: 直接匹配字段名（用于某些whois格式）
                // 只有当键名完全匹配类型名时才使用直接匹配
                if (strtolower($key) === $type) {
                    $typePatterns = array_merge($typePatterns, $patterns);
                }
                
                // 模式4: 特殊处理 - 如果键名就是联系人类型，默认为name字段
                if (strtolower($key) === $type && $field === 'name') {
                    $typePatterns[] = $type;
                }
                
                if (self::matchesKey($key, $typePatterns)) {
                    // 特殊处理：如果键名包含"contact"但字段不是email/phone，则跳过
                    if (strpos($key, 'contact') !== false && !in_array($field, ['email', 'phone'])) {
                        continue;
                    }
                    
                    // 特殊处理：如果键名包含"server"但字段不是url，则跳过
                    if (strpos($key, 'server') !== false && $field !== 'url') {
                        continue;
                    }
                    
                    // 特殊处理注册人名称，避免被邮箱覆盖
                    if ($type === 'registrant' && $field === 'name' && !empty($data[$type]['name'])) {
                        return true;
                    }
                    
                    $data[$type][$field] = $value;
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * 解析名称服务器
     * 
     * @param array &$data 数据数组
     * @param string $value 值
     */
    private static function parseNameservers(array &$data, string $value): void
    {
        $nsList = preg_split('/[\s,]+/', $value);
        foreach ($nsList as $ns) {
            $ns = trim(strtolower($ns));
            if (!empty($ns) && strpos($ns, '.') !== false) {
                $data['nameservers'][] = $ns;
            }
        }
    }
    
    /**
     * 后处理数据
     * 
     * @param array &$data 数据数组
     */
    private static function postProcess(array &$data): void
    {
        // 去重名称服务器
        $data['nameservers'] = array_values(array_unique(array_filter($data['nameservers'])));
        
        // 清理空的注册商信息
        if (empty(array_filter($data['registrar']))) {
            $data['registrar'] = ['name' => ''];
        }
    }
}
