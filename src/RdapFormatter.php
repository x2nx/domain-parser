<?php

namespace X2nx\DomainParser;

/**
 * RDAP 响应格式化器
 * 
 * 将 RDAP JSON 响应转换为类似 WHOIS 的文本格式
 */
class RdapFormatter
{
    /**
     * 将 RDAP JSON 响应转换为 WHOIS 风格的文本
     * 
     * @param string|array $rdapResponse RDAP 响应（JSON 字符串或数组）
     * @return string 格式化后的文本
     */
    public static function format($rdapResponse): string
    {
        // 如果是字符串，先解析为数组
        if (is_string($rdapResponse)) {
            $data = json_decode($rdapResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return "Error: Invalid JSON response\n";
            }
        } else {
            $data = $rdapResponse;
        }
        
        if (empty($data)) {
            return "Error: Empty response\n";
        }
        
        $output = [];
        
        // 添加头部信息
        $output[] = "% RDAP QUERY RESPONSE";
        $output[] = "%";
        
        // 域名信息
        if (!empty($data['ldhName'])) {
            $output[] = "Domain Name: " . strtoupper($data['ldhName']);
        } elseif (!empty($data['unicodeName'])) {
            $output[] = "Domain Name: " . $data['unicodeName'];
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
                if (!empty($ns['ldhName'])) {
                    $output[] = "  " . strtoupper($ns['ldhName']);
                }
            }
        }
        
        // DNSSEC 信息
        if (isset($data['secureDNS'])) {
            $output[] = "";
            if (!empty($data['secureDNS']['delegationSigned'])) {
                $output[] = "DNSSEC: signedDelegation";
                
                if (!empty($data['secureDNS']['dsData'])) {
                    foreach ($data['secureDNS']['dsData'] as $ds) {
                        $dsInfo = sprintf(
                            "  DS: %s %s %s %s",
                            $ds['keyTag'] ?? '',
                            $ds['algorithm'] ?? '',
                            $ds['digestType'] ?? '',
                            $ds['digest'] ?? ''
                        );
                        $output[] = trim($dsInfo);
                    }
                }
            } else {
                $output[] = "DNSSEC: unsigned";
            }
        }
        
        // 重要日期
        $output[] = "";
        if (!empty($data['events'])) {
            foreach ($data['events'] as $event) {
                $eventType = ucfirst(str_replace('_', ' ', $event['eventAction'] ?? ''));
                $eventDate = $event['eventDate'] ?? '';
                
                switch ($event['eventAction'] ?? '') {
                    case 'registration':
                        $output[] = "Created Date: " . $eventDate;
                        break;
                    case 'last changed':
                    case 'last update of RDAP database':
                        $output[] = "Updated Date: " . $eventDate;
                        break;
                    case 'expiration':
                        $output[] = "Expiry Date: " . $eventDate;
                        break;
                    default:
                        $output[] = "$eventType: " . $eventDate;
                }
            }
        }
        
        // 备注信息
        if (!empty($data['remarks'])) {
            $output[] = "";
            $output[] = "Remarks:";
            foreach ($data['remarks'] as $remark) {
                if (!empty($remark['title'])) {
                    $output[] = "  " . $remark['title'];
                }
                if (!empty($remark['description'])) {
                    foreach ((array)$remark['description'] as $desc) {
                        $output[] = "  " . $desc;
                    }
                }
            }
        }
        
        // 通知信息
        if (!empty($data['notices'])) {
            $output[] = "";
            foreach ($data['notices'] as $notice) {
                if (!empty($notice['title'])) {
                    $output[] = ">>> " . $notice['title'];
                }
                if (!empty($notice['description'])) {
                    foreach ((array)$notice['description'] as $desc) {
                        $output[] = $desc;
                    }
                }
                if (!empty($notice['links'])) {
                    foreach ($notice['links'] as $link) {
                        if (!empty($link['href'])) {
                            $output[] = "URL: " . $link['href'];
                        }
                    }
                }
                $output[] = "";
            }
        }
        
        // RDAP 一致性级别
        if (!empty($data['rdapConformance'])) {
            $output[] = "";
            $output[] = "RDAP Conformance:";
            foreach ($data['rdapConformance'] as $conformance) {
                $output[] = "  " . $conformance;
            }
        }
        
        return implode("\n", $output);
    }
    
    /**
     * 根据角色查找实体
     * 
     * @param array $data RDAP 数据
     * @param string $role 角色名称
     * @return array|null 实体数据或 null
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
        $lines = [];
        
        if (!empty($entity['handle'])) {
            $lines[] = $prefix . "ID: " . $entity['handle'];
        }
        
        if (!empty($entity['vcardArray'])) {
            $vcard = self::parseVCard($entity['vcardArray']);
            
            if (!empty($vcard['fn'])) {
                $lines[] = $prefix . "Name: " . $vcard['fn'];
            }
            
            if (!empty($vcard['org'])) {
                $lines[] = $prefix . "Organization: " . $vcard['org'];
            }
            
            if (!empty($vcard['adr'])) {
                $lines[] = $prefix . "Address: " . $vcard['adr'];
            }
            
            if (!empty($vcard['email'])) {
                $lines[] = $prefix . "Email: " . $vcard['email'];
            }
            
            if (!empty($vcard['tel'])) {
                $lines[] = $prefix . "Phone: " . $vcard['tel'];
            }
        }
        
        return $lines;
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
                    $result['org'] = is_array($value) ? implode(', ', $value) : $value;
                    break;
                    
                case 'adr':
                    if (is_array($value)) {
                        // vCard 地址格式: [邮政信箱, 扩展地址, 街道地址, 城市, 省/州, 邮编, 国家]
                        $result['street'] = trim(($value[2] ?? '') . ' ' . ($value[1] ?? ''));
                        $result['city'] = $value[3] ?? '';
                        $result['state'] = $value[4] ?? '';
                        $result['postal_code'] = $value[5] ?? '';
                        $result['country'] = $value[6] ?? '';
                        
                        // 保留完整地址用于显示
                        $addrParts = array_filter($value);
                        $result['adr'] = implode(', ', $addrParts);
                    }
                    break;
                    
                case 'email':
                    if (empty($result['email'])) {
                        $result['email'] = $value;
                    }
                    break;
                    
                case 'tel':
                    if (empty($result['tel'])) {
                        $result['tel'] = is_array($value) ? ($value['uri'] ?? $value[0] ?? '') : $value;
                    }
                    break;
                    
                case 'fax':
                    if (empty($result['fax'])) {
                        $result['fax'] = is_array($value) ? ($value['uri'] ?? $value[0] ?? '') : $value;
                    }
                    break;
            }
        }
        
        return $result;
    }
    
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
        
        // 初始化与 WhoisParser 一致的结构
        $result = [
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
                'expires' => ''
            ],
            'dnssec' => '',
            'raw_text' => $rdapResponse
        ];
        
        // 域名
        $result['domain'] = strtolower($data['ldhName'] ?? $data['unicodeName'] ?? '');
        
        // 域名 ID
        $result['domain_id'] = $data['handle'] ?? '';
        
        // 状态
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
            if (!empty($data['secureDNS']['delegationSigned'])) {
                $result['dnssec'] = 'signedDelegation';
            } else {
                $result['dnssec'] = 'unsigned';
            }
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
                    case 'last update of RDAP database':
                        $result['dates']['updated'] = $date;
                        break;
                    case 'expiration':
                        $result['dates']['expires'] = $date;
                        break;
                }
            }
        }
        
        // 注册商信息
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
            }
        }
        
        // 注册人信息
        $registrant = self::findEntityByRole($data, 'registrant');
        if ($registrant && !empty($registrant['vcardArray'])) {
            $vcard = self::parseVCard($registrant['vcardArray']);
            $result['registrant'] = [
                'name' => $vcard['fn'] ?? '',
                'organization' => $vcard['org'] ?? '',
                'email' => $vcard['email'] ?? '',
                'phone' => $vcard['tel'] ?? '',
                'fax' => $vcard['fax'] ?? '',
                'street' => $vcard['street'] ?? '',
                'city' => $vcard['city'] ?? '',
                'state' => $vcard['state'] ?? '',
                'postal_code' => $vcard['postal_code'] ?? '',
                'country' => $vcard['country'] ?? ''
            ];
        }
        
        // 管理联系人
        $admin = self::findEntityByRole($data, 'administrative');
        if ($admin && !empty($admin['vcardArray'])) {
            $vcard = self::parseVCard($admin['vcardArray']);
            $result['admin'] = [
                'name' => $vcard['fn'] ?? '',
                'organization' => $vcard['org'] ?? '',
                'email' => $vcard['email'] ?? '',
                'phone' => $vcard['tel'] ?? '',
                'fax' => $vcard['fax'] ?? '',
                'street' => $vcard['street'] ?? '',
                'city' => $vcard['city'] ?? '',
                'state' => $vcard['state'] ?? '',
                'postal_code' => $vcard['postal_code'] ?? '',
                'country' => $vcard['country'] ?? ''
            ];
        }
        
        // 技术联系人
        $tech = self::findEntityByRole($data, 'technical');
        if ($tech && !empty($tech['vcardArray'])) {
            $vcard = self::parseVCard($tech['vcardArray']);
            $result['tech'] = [
                'name' => $vcard['fn'] ?? '',
                'organization' => $vcard['org'] ?? '',
                'email' => $vcard['email'] ?? '',
                'phone' => $vcard['tel'] ?? '',
                'fax' => $vcard['fax'] ?? '',
                'street' => $vcard['street'] ?? '',
                'city' => $vcard['city'] ?? '',
                'state' => $vcard['state'] ?? '',
                'postal_code' => $vcard['postal_code'] ?? '',
                'country' => $vcard['country'] ?? ''
            ];
        }
        
        // 账单联系人
        $billing = self::findEntityByRole($data, 'billing');
        if ($billing && !empty($billing['vcardArray'])) {
            $vcard = self::parseVCard($billing['vcardArray']);
            $result['billing'] = [
                'name' => $vcard['fn'] ?? '',
                'organization' => $vcard['org'] ?? '',
                'email' => $vcard['email'] ?? '',
                'phone' => $vcard['tel'] ?? '',
                'fax' => $vcard['fax'] ?? ''
            ];
        }
        
        return $result;
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
        
        $summary = [];
        
        // 域名
        $summary['domain'] = $data['ldhName'] ?? $data['unicodeName'] ?? '';
        
        // 状态
        $summary['status'] = $data['status'] ?? [];
        
        // 名称服务器
        $summary['nameservers'] = [];
        if (!empty($data['nameservers'])) {
            foreach ($data['nameservers'] as $ns) {
                if (!empty($ns['ldhName'])) {
                    $summary['nameservers'][] = $ns['ldhName'];
                }
            }
        }
        
        // 日期
        $summary['dates'] = [];
        if (!empty($data['events'])) {
            foreach ($data['events'] as $event) {
                $action = $event['eventAction'] ?? '';
                $date = $event['eventDate'] ?? '';
                $summary['dates'][$action] = $date;
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

