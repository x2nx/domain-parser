<?php

namespace X2nx\DomainParser\Formatters;

use X2nx\DomainParser\Parsers\RdapParser;

/**
 * RDAP 响应格式化器
 * 
 * 将 RDAP JSON 响应格式化为统一的文本格式
 */
class RdapFormatter
{
    /**
     * 格式化 RDAP JSON 响应为统一文本格式
     * 
     * @param string|array $rdapResponse RDAP 响应
     * @return string 格式化的文本
     */
    public static function format($rdapResponse): string
    {
        if (is_string($rdapResponse)) {
            $data = json_decode($rdapResponse, true);
        } else {
            $data = $rdapResponse;
        }
        
        if (empty($data)) {
            return '';
        }
        
        $output = [];
        
        $output[] = "% RDAP QUERY RESPONSE";
        $output[] = "%";
        
        // 域名
        if (!empty($data['ldhName'])) {
            $output[] = "Domain Name: " . strtoupper($data['ldhName']);
        }
        
        // 域名句柄/ID
        if (!empty($data['handle'])) {
            $output[] = "Domain ID: " . $data['handle'];
        }
        
        // 注册商信息
        $registrar = self::findEntityByRole($data, 'registrar');
        if ($registrar) {
            $output[] = "";
            $output[] = "Registrar Information:";
            
            if (!empty($registrar['vcardArray'])) {
                $vcard = self::parseVCard($registrar['vcardArray']);
                if (!empty($vcard['fn'])) {
                    $output[] = "  Registrar: " . $vcard['fn'];
                }
                if (!empty($vcard['email'])) {
                    $output[] = "  Registrar Abuse Contact Email: " . $vcard['email'];
                }
                if (!empty($vcard['tel'])) {
                    $output[] = "  Registrar Abuse Contact Phone: " . $vcard['tel'];
                }
            }
            
            if (!empty($registrar['handle'])) {
                $output[] = "  Registrar IANA ID: " . $registrar['handle'];
            }
        }
        
        // 查找专门的 abuse 实体
        $abuse = self::findEntityByRole($data, 'abuse');
        if ($abuse && !empty($abuse['vcardArray'])) {
            $vcard = self::parseVCard($abuse['vcardArray']);
            if (!empty($vcard['email'])) {
                $output[] = "  Registrar Abuse Contact Email: " . $vcard['email'];
            }
            if (!empty($vcard['tel'])) {
                $output[] = "  Registrar Abuse Contact Phone: " . $vcard['tel'];
            }
        }
        
        // 注册人信息
        $registrant = self::findEntityByRole($data, 'registrant');
        if ($registrant) {
            $output[] = "";
            $output[] = "Registrant Information:";
            $output = array_merge($output, self::formatEntity($registrant, "  "));
        }
        
        // 管理联系人
        $admin = self::findEntityByRole($data, 'administrative');
        if ($admin) {
            $output[] = "";
            $output[] = "Admin Contact:";
            $output = array_merge($output, self::formatEntity($admin, "  "));
        }
        
        // 技术联系人
        $tech = self::findEntityByRole($data, 'technical');
        if ($tech) {
            $output[] = "";
            $output[] = "Tech Contact:";
            $output = array_merge($output, self::formatEntity($tech, "  "));
        }
        
        // 状态信息
        if (!empty($data['status'])) {
            $output[] = "";
            $output[] = "Domain Status:";
            foreach ($data['status'] as $status) {
                $output[] = "  " . $status;
            }
        }
        
        // 名称服务器
        if (!empty($data['nameservers'])) {
            $output[] = "";
            $output[] = "Name Servers:";
            foreach ($data['nameservers'] as $ns) {
                $output[] = "  " . strtoupper($ns['ldhName']);
            }
        }
        
        // DNSSEC
        if (isset($data['secureDNS'])) {
            if (!empty($data['secureDNS']['delegationSigned'])) {
                $output[] = "";
                $output[] = "DNSSEC: signedDelegation";
            } else {
                $output[] = "";
                $output[] = "DNSSEC: unsigned";
            }
        }
        
        // 日期信息
        if (!empty($data['events'])) {
            $output[] = "";
            foreach ($data['events'] as $event) {
                $action = $event['eventAction'] ?? '';
                $date = $event['eventDate'] ?? '';
                
                switch ($action) {
                    case 'registration':
                        $output[] = "Created Date: " . $date;
                        break;
                    case 'last changed':
                        $output[] = "Updated Date: " . $date;
                        break;
                    case 'last update of RDAP database':
                        $output[] = "Database Updated Date: " . $date;
                        break;
                    case 'expiration':
                        $output[] = "Expiry Date: " . $date;
                        break;
                }
            }
        }
        
        return implode("\n", $output);
    }
    
    /**
     * 查找指定角色的实体
     * 
     * @param array $data RDAP 数据
     * @param string $role 角色名称
     * @return array|null 实体数据
     */
    private static function findEntityByRole(array $data, string $role): ?array
    {
        if (empty($data['entities'])) {
            return null;
        }
        
        foreach ($data['entities'] as $entity) {
            if (!empty($entity['roles']) && in_array($role, $entity['roles'])) {
                return $entity;
            }
            
            // 检查嵌套实体
            if (!empty($entity['entities'])) {
                foreach ($entity['entities'] as $nestedEntity) {
                    if (!empty($nestedEntity['roles']) && in_array($role, $nestedEntity['roles'])) {
                        return $nestedEntity;
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * 格式化实体信息
     * 
     * @param array $entity 实体数据
     * @param string $prefix 行前缀
     * @return array 格式化后的行数组
     */
    private static function formatEntity(array $entity, string $prefix = ""): array
    {
        $output = [];
        
        if (!empty($entity['vcardArray'])) {
            $vcard = self::parseVCard($entity['vcardArray']);
            
            foreach ($vcard as $key => $value) {
                if (!empty($value)) {
                    $label = ucwords(str_replace('_', ' ', $key));
                    $output[] = $prefix . $label . ": " . $value;
                }
            }
        }
        
        return $output;
    }
    
    /**
     * 解析 vCard 数组
     * 
     * @param array $vcardArray vCard 数组
     * @return array 解析后的数据
     */
    private static function parseVCard(array $vcardArray): array
    {
        $result = [];
        
        if (empty($vcardArray[1])) {
            return $result;
        }
        
        foreach ($vcardArray[1] as $entry) {
            if (!is_array($entry) || count($entry) < 4) {
                continue;
            }
            
            $key = strtolower($entry[0]);
            $value = $entry[3];
            
            switch ($key) {
                case 'fn':
                    $result['fn'] = $value;
                    break;
                    
                case 'org':
                    $result['org'] = self::cleanValue($value);
                    break;
                    
                case 'adr':
                    if (is_array($value)) {
                        self::parseAddress($result, $value);
                    }
                    break;
                    
                case 'email':
                case 'tel':
                case 'telephone':
                case 'fax':
                case 'url':
                case 'website':
                case 'title':
                case 'role':
                    if (empty($result[$key])) {
                        $result[$key] = self::cleanValue($value);
                    }
                    break;
            }
        }
        
        return $result;
    }
    
    /**
     * 解析地址信息
     * 
     * @param array &$result 结果数组
     * @param array $value 地址数组
     */
    private static function parseAddress(array &$result, array $value): void
    {
        // vCard 地址格式: [邮政信箱, 扩展地址, 街道地址, 城市, 省/州, 邮编, 国家]
        $addressFields = [
            'street' => [1, 2], // 扩展地址 + 街道地址
            'city' => [3],
            'state' => [4],
            'postal_code' => [5],
            'country' => [6]
        ];
        
        foreach ($addressFields as $field => $indices) {
            $parts = [];
            foreach ($indices as $index) {
                $part = $value[$index] ?? '';
                if (!is_array($part) && !empty($part)) {
                    $parts[] = $part;
                }
            }
            if (!empty($parts)) {
                $result[$field] = trim(implode(' ', $parts));
            }
        }
        
        // 保留完整地址用于显示
        $addrParts = array_filter($value, function($part) {
            return !is_array($part) && !empty($part);
        });
        if (!empty($addrParts)) {
            $result['adr'] = implode(', ', $addrParts);
        }
    }
    
    /**
     * 清理和标准化值
     * 
     * @param mixed $value 原始值
     * @return string
     */
    private static function cleanValue($value): string
    {
        if (is_array($value)) {
            return implode(', ', array_filter($value, function($item) {
                return !is_array($item) && !empty($item);
            }));
        }
        return trim((string)$value);
    }
}
