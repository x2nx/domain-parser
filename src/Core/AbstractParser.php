<?php

namespace X2nx\DomainParser\Core;

/**
 * 抽象解析器基类
 * 
 * 提供通用的解析方法和数据结构
 */
abstract class AbstractParser
{
    /**
     * 获取默认的数据结构
     * 
     * @return array
     */
    protected static function getDefaultStructure(): array
    {
        return [
            'domain' => '',
            'domain_id' => '',
            'registrar' => [
                'name' => '',
                'iana_id' => '',
                'whois_server' => '',
                'url' => '',
                'email' => '',
                'phone' => ''
            ],
            'registrant' => [],
            'admin' => [],
            'tech' => [],
            'billing' => [],
            'status' => [],
            'nameservers' => [],
            'dates' => [
                'created' => '',
                'updated' => '',
                'database' => '',
                'expires' => ''
            ],
            'dnssec' => '',
            'raw_text' => ''
        ];
    }
    
    /**
     * 获取联系人字段映射
     * 
     * @return array
     */
    protected static function getContactFields(): array
    {
        return [
            'name' => ['name', 'fn', 'contact name', 'contact'],
            'organization' => ['organization', 'org', 'company', 'organization name'],
            'email' => ['email', 'contact email', 'e-mail', 'mail'],
            'phone' => ['phone', 'tel', 'telephone', 'contact phone', 'phone number'],
            'fax' => ['fax', 'fax number'],
            'url' => ['url', 'website', 'web', 'homepage'],
            'title' => ['title', 'role', 'position'],
            'street' => ['street', 'address', 'street address', 'addr'],
            'city' => ['city', 'locality'],
            'state' => ['state', 'province', 'region', 'state/province'],
            'postal_code' => ['postal_code', 'zip', 'postal', 'zip code'],
            'country' => ['country', 'country code']
        ];
    }
    
    /**
     * 获取日期字段映射
     * 
     * @return array
     */
    protected static function getDateFields(): array
    {
        return [
            'created' => ['creation date', 'created', 'registered', 'registered on', 'registration time'],
            'updated' => ['updated date', 'changed', 'modified', 'last modified'],
            'database' => ['last updated', 'changed', 'modified', 'last modified'],
            'expires' => ['expiry date', 'expiration date', 'expires', 'paid-till', 'registry expiry date', 'expiration time']
        ];
    }
    
    /**
     * 获取注册商字段映射
     * 
     * @return array
     */
    protected static function getRegistrarFields(): array
    {
        return [
            'name' => ['registrar', 'sponsoring registrar', '注册商', 'registrar name'],
            'iana_id' => ['registrar iana id', 'registrar id', 'iana id'],
            'whois_server' => ['registrar whois server', 'whois server', 'registrar whois'],
            'url' => ['registrar url', '注册商链接', 'registrar website', 'registrar web', 'registrar homepage'],
            'email' => ['registrar abuse contact email', 'registrar email', 'abuse email', 'registrar contact email'],
            'phone' => ['registrar abuse contact phone', 'registrar phone', 'abuse phone', 'registrar contact phone']
        ];
    }
    
    /**
     * 检查键是否匹配指定的模式
     * 
     * @param string $key 键名
     * @param array $patterns 模式数组
     * @return bool
     */
    protected static function matchesKey(string $key, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (strpos($key, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 安全地获取数组值
     * 
     * @param array $array 数组
     * @param string $key 键名
     * @param mixed $default 默认值
     * @return mixed
     */
    protected static function safeGet(array $array, string $key, $default = '')
    {
        return $array[$key] ?? $default;
    }
    
    /**
     * 清理和标准化值
     * 
     * @param mixed $value 原始值
     * @return string
     */
    protected static function cleanValue($value): string
    {
        if (is_array($value)) {
            return implode(', ', array_filter($value, function($item) {
                return !is_array($item) && !empty($item);
            }));
        }
        return trim((string)$value);
    }
}
