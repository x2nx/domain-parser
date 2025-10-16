<?php

namespace X2nx\DomainParser\Parsers;

use X2nx\DomainParser\Core\AbstractParser;

/**
 * RDAP JSON 解析器
 * 
 * 将 RDAP JSON 响应解析为结构化数据
 */
class RdapParser extends AbstractParser
{
    /**
     * 解析 RDAP JSON 响应为结构化数据（与 WhoisParser 格式一致）
     * 
     * @param string|array $rdapResponse RDAP 响应
     * @return array 结构化的域名信息
     */
    public static function parse($rdapResponse): array
    {
        if (is_string($rdapResponse)) {
            $data = json_decode($rdapResponse, true);
        } else {
            $data = $rdapResponse;
        }
        
        if (empty($data)) {
            return [];
        }
        
        $result = self::getDefaultStructure();
        $result['raw_text'] = $rdapResponse;
        
        // 基本信息
        $result['domain'] = strtolower($data['ldhName'] ?? $data['unicodeName'] ?? '');
        $result['domain_id'] = $data['handle'] ?? '';
        $result['status'] = $data['status'] ?? [];
        
        // 名称服务器
        if (!empty($data['nameservers'])) {
            foreach ($data['nameservers'] as $ns) {
                if (!empty($ns['ldhName'])) {
                    $result['nameservers'][] = strtolower($ns['ldhName']);
                }
            }
        }
        
        // DNSSEC
        if (isset($data['secureDNS'])) {
            $result['dnssec'] = !empty($data['secureDNS']['delegationSigned']) ? 'signedDelegation' : 'unsigned';
        }
        
        // 日期
        if (!empty($data['events'])) {
            foreach ($data['events'] as $event) {
                $action = $event['eventAction'] ?? '';
                $date = $event['eventDate'] ?? '';
                
                switch ($action) {
                    case 'registration':
                        $result['dates']['created'] = $date;
                        break;
                    case 'last changed':
                        $result['dates']['updated'] = $date;
                        break;
                    case 'last update of RDAP database':
                        $result['dates']['database'] = $date;
                        break;
                    case 'expiration':
                        $result['dates']['expires'] = $date;
                        break;
                }
            }
        }
        
        // 注册商信息
        self::parseRegistrarInfo($result, $data);
        
        // 联系人信息
        self::parseContactInfo($result, $data);
        
        return $result;
    }
    
    /**
     * 解析注册商信息
     * 
     * @param array &$result 结果数组
     * @param array $data RDAP 数据
     */
    private static function parseRegistrarInfo(array &$result, array $data): void
    {
        $registrar = self::findEntityByRole($data, 'registrar');
        if ($registrar) {
            if (!empty($registrar['handle'])) {
                $result['registrar']['iana_id'] = $registrar['handle'];
            }
            
            if (!empty($registrar['vcardArray'])) {
                $vcard = self::parseVCard($registrar['vcardArray']);
                $result['registrar']['name'] = $vcard['fn'] ?? '';
                $result['registrar']['email'] = $vcard['email'] ?? '';
                $result['registrar']['phone'] = $vcard['tel'] ?? '';
                $result['registrar']['url'] = $vcard['url'] ?? '';
            }
            
            // 从链接中提取注册商网站信息
            if (!empty($registrar['links'])) {
                foreach ($registrar['links'] as $link) {
                    if (!empty($link['href']) && empty($result['registrar']['url'])) {
                        // 检查链接类型，优先选择网站链接
                        if (isset($link['type']) && $link['type'] === 'text/html') {
                            $result['registrar']['url'] = $link['href'];
                            break;
                        } elseif (empty($result['registrar']['url'])) {
                            $result['registrar']['url'] = $link['href'];
                        }
                    }
                }
            }
        }
        
        // 查找专门的 abuse 实体，补充注册商 abuse 联系信息
        $abuse = self::findEntityByRole($data, 'abuse');
        if ($abuse && !empty($abuse['vcardArray'])) {
            $vcard = self::parseVCard($abuse['vcardArray']);
            // 如果注册商没有邮箱，使用 abuse 实体的邮箱
            if (empty($result['registrar']['email']) && !empty($vcard['email'])) {
                $result['registrar']['email'] = $vcard['email'];
            }
            // 如果注册商没有电话，使用 abuse 实体的电话
            if (empty($result['registrar']['phone']) && !empty($vcard['tel'])) {
                $result['registrar']['phone'] = $vcard['tel'];
            }
        }
    }
    
    /**
     * 解析联系人信息
     * 
     * @param array &$result 结果数组
     * @param array $data RDAP 数据
     */
    private static function parseContactInfo(array &$result, array $data): void
    {
        $contactTypes = [
            'registrant' => 'registrant',
            'admin' => 'administrative',
            'tech' => 'technical',
            'billing' => 'billing'
        ];
        
        foreach ($contactTypes as $resultKey => $role) {
            $entity = self::findEntityByRole($data, $role);
            if ($entity && !empty($entity['vcardArray'])) {
                $vcard = self::parseVCard($entity['vcardArray']);
                $result[$resultKey] = [
                    'name' => $vcard['fn'] ?? '',
                    'organization' => $vcard['org'] ?? '',
                    'email' => $vcard['email'] ?? '',
                    'phone' => $vcard['tel'] ?? '',
                    'fax' => $vcard['fax'] ?? '',
                    'url' => $vcard['url'] ?? '',
                    'title' => $vcard['title'] ?? '',
                    'street' => $vcard['street'] ?? '',
                    'city' => $vcard['city'] ?? '',
                    'state' => $vcard['state'] ?? '',
                    'postal_code' => $vcard['postal_code'] ?? '',
                    'country' => $vcard['country'] ?? '',
                    'adr' => $vcard['adr'] ?? ''
                ];
            }
        }
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
     * 获取简化版本的信息（只包含关键字段）
     * 
     * @param string|array $rdapResponse RDAP 响应
     * @return array 关键信息数组
     */
    public static function getSummary($rdapResponse): array
    {
        if (is_string($rdapResponse)) {
            $data = json_decode($rdapResponse, true);
        } else {
            $data = $rdapResponse;
        }
        
        if (empty($data)) {
            return [];
        }
        
        $summary = [
            'domain' => strtoupper($data['ldhName'] ?? ''),
            'status' => $data['status'] ?? [],
            'nameservers' => [],
            'dates' => [],
            'registrar' => ''
        ];
        
        // 名称服务器
        if (!empty($data['nameservers'])) {
            foreach ($data['nameservers'] as $ns) {
                if (!empty($ns['ldhName'])) {
                    $summary['nameservers'][] = strtoupper($ns['ldhName']);
                }
            }
        }
        
        // 日期
        if (!empty($data['events'])) {
            foreach ($data['events'] as $event) {
                $action = $event['eventAction'] ?? '';
                $date = $event['eventDate'] ?? '';
                
                switch ($action) {
                    case 'registration':
                        $summary['dates']['registration'] = $date;
                        break;
                    case 'expiration':
                        $summary['dates']['expiration'] = $date;
                        break;
                    case 'last changed':
                        $summary['dates']['last changed'] = $date;
                        break;
                    case 'last update of RDAP database':
                        $summary['dates']['last update of RDAP database'] = $date;
                        break;
                }
            }
        }
        
        // 注册商
        $registrar = self::findEntityByRole($data, 'registrar');
        if ($registrar && !empty($registrar['vcardArray'])) {
            $vcard = self::parseVCard($registrar['vcardArray']);
            $summary['registrar'] = $vcard['fn'] ?? '';
        }
        
        return $summary;
    }
}
