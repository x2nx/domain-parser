<?php

namespace X2nx\DomainParser;

/**
 * WHOIS 文本解析器
 * 
 * 将各种 WHOIS 服务器返回的文本解析为结构化数据
 */
class WhoisParser
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
        
        $data = [
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
                'database'=> '',
                'expires' => ''
            ],
            'dnssec' => '',
            'raw_text' => $whoisText
        ];
        
        $lines = explode("\n", $whoisText);
        $currentSection = null;
        
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
                
                // 标准化键名
                $keyLower = strtolower($key);
                
                // 域名状态 - 必须在 '域名' 字段之前匹配，避免被 'domain' 模式误捕获
                if (self::matchesKey($keyLower, ['domain status', '域名状态'])) {
                    // 状态值可能包含 URL，只取状态名称部分
                    $statusValue = trim(preg_split('/\s+http/i', $value)[0]);
                    if (!empty($statusValue)) {
                        $data['status'][] = $statusValue;
                    }
                }
                
                // 域名 ID - 必须在 '域名' 字段之前匹配
                elseif (self::matchesKey($keyLower, ['registry domain id', 'domain id', 'roid', '域名roid'])) {
                    if (empty($data['domain_id'])) {
                        $data['domain_id'] = $value;
                    }
                }
                
                // 域名
                elseif (self::matchesKey($keyLower, ['domain name', '域名'])) {
                    if (empty($data['domain'])) {
                        $data['domain'] = $value;
                    }
                }
                
                // 注册商信息
                elseif (self::matchesKey($keyLower, ['registrar abuse contact email'])) {
                    $data['registrar']['email'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrar abuse contact phone'])) {
                    $data['registrar']['phone'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrar whois server'])) {
                    $data['registrar']['whois_server'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrar iana id'])) {
                    $data['registrar']['iana_id'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrar url', '注册商链接'])) {
                    $data['registrar']['url'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrar', 'sponsoring registrar', '注册商'])) {
                    if (empty($data['registrar']['name'])) {
                        $data['registrar']['name'] = $value;
                    }
                }
                
                // 名称服务器
                elseif (self::matchesKey($keyLower, ['name server', 'nameserver', 'nserver', 'name servers'])) {
                    $nsList = preg_split('/[\s,]+/', $value);
                    foreach ($nsList as $ns) {
                        $ns = trim(strtolower($ns));
                        if (!empty($ns) && strpos($ns, '.') !== false) {
                            $data['nameservers'][] = $ns;
                        }
                    }
                }
                
                // DNSSEC
                elseif (self::matchesKey($keyLower, ['dnssec'])) {
                    $data['dnssec'] = $value;
                }
                
                // 日期
                elseif (self::matchesKey($keyLower, ['creation date', 'created', 'registered', 'registered on', 'registration time'])) {
                    if (empty($data['dates']['created'])) {
                        $data['dates']['created'] = $value;
                    }
                }
                elseif (self::matchesKey($keyLower, ['updated date', 'changed', 'modified', 'last modified'])) {
                    if (empty($data['dates']['updated'])) {
                        $data['dates']['updated'] = $value;
                    }
                }
                elseif (self::matchesKey($keyLower, ['last updated', 'changed', 'modified', 'last modified'])) {
                    if (empty($data['dates']['database'])) {
                        $data['dates']['database'] = $value;
                    }
                }
                elseif (self::matchesKey($keyLower, ['expiry date', 'expiration date', 'expires', 'paid-till', 'registry expiry date', 'expiration time'])) {
                    if (empty($data['dates']['expires'])) {
                        $data['dates']['expires'] = $value;
                    }
                }
                
                // 注册人信息
                elseif (self::matchesKey($keyLower, ['registrant name', 'registrant'])) {
                    $data['registrant']['name'] = $value;
                    $currentSection = 'registrant';
                }
                elseif (self::matchesKey($keyLower, ['registrant organization', 'registrant org'])) {
                    $data['registrant']['organization'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant email'])) {
                    $data['registrant']['email'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant phone'])) {
                    $data['registrant']['phone'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant street', 'registrant address'])) {
                    $data['registrant']['street'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant city'])) {
                    $data['registrant']['city'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant state', 'registrant province'])) {
                    $data['registrant']['state'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant postal code', 'registrant zip'])) {
                    $data['registrant']['postal_code'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant country'])) {
                    $data['registrant']['country'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['registrant fax'])) {
                    $data['registrant']['fax'] = $value;
                }
                
                // 管理联系人
                elseif (self::matchesKey($keyLower, ['admin name', 'administrative contact', 'admin contact'])) {
                    $data['admin']['name'] = $value;
                    $currentSection = 'admin';
                }
                elseif (self::matchesKey($keyLower, ['admin organization', 'admin org'])) {
                    $data['admin']['organization'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin email'])) {
                    $data['admin']['email'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin phone'])) {
                    $data['admin']['phone'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin street', 'admin address'])) {
                    $data['admin']['street'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin city'])) {
                    $data['admin']['city'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin state', 'admin province'])) {
                    $data['admin']['state'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin postal code', 'admin zip'])) {
                    $data['admin']['postal_code'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin country'])) {
                    $data['admin']['country'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['admin fax'])) {
                    $data['admin']['fax'] = $value;
                }
                
                // 技术联系人
                elseif (self::matchesKey($keyLower, ['tech name', 'technical contact', 'tech contact'])) {
                    $data['tech']['name'] = $value;
                    $currentSection = 'tech';
                }
                elseif (self::matchesKey($keyLower, ['tech organization', 'tech org'])) {
                    $data['tech']['organization'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech email'])) {
                    $data['tech']['email'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech phone'])) {
                    $data['tech']['phone'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech street', 'tech address'])) {
                    $data['tech']['street'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech city'])) {
                    $data['tech']['city'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech state', 'tech province'])) {
                    $data['tech']['state'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech postal code', 'tech zip'])) {
                    $data['tech']['postal_code'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech country'])) {
                    $data['tech']['country'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['tech fax'])) {
                    $data['tech']['fax'] = $value;
                }
                
                // 账单联系人
                elseif (self::matchesKey($keyLower, ['billing name', 'billing contact'])) {
                    $data['billing']['name'] = $value;
                    $currentSection = 'billing';
                }
                elseif (self::matchesKey($keyLower, ['billing organization', 'billing org'])) {
                    $data['billing']['organization'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['billing email'])) {
                    $data['billing']['email'] = $value;
                }
                elseif (self::matchesKey($keyLower, ['billing phone'])) {
                    $data['billing']['phone'] = $value;
                }
            }
        }
        
        // 去重名称服务器
        $data['nameservers'] = array_values(array_unique(array_filter($data['nameservers'])));
        
        // 清理空的注册商信息
        if (empty(array_filter($data['registrar']))) {
            $data['registrar'] = ['name' => ''];
        }
        
        return $data;
    }
    
    /**
     * 检查键是否匹配指定的模式
     * 
     * @param string $key 键名
     * @param array $patterns 模式数组
     * @return bool
     */
    private static function matchesKey(string $key, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (strpos($key, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 格式化解析后的数据为统一文本格式
     * 
     * @param array $data 解析后的数据
     * @return string 格式化的文本
     */
    public static function formatParsed(array $data): string
    {
        $output = [];
        
        $output[] = "% WHOIS QUERY RESPONSE";
        $output[] = "%";
        
        // 域名
        if (!empty($data['domain'])) {
            $output[] = "Domain Name: " . strtoupper($data['domain']);
        }
        
        // 域名 ID
        if (!empty($data['domain_id'])) {
            $output[] = "Domain ID: " . $data['domain_id'];
        }
        
        // 注册商
        if (!empty($data['registrar'])) {
            $registrar = is_array($data['registrar']) ? $data['registrar'] : ['name' => $data['registrar']];
            
            if (!empty($registrar['name'])) {
                $output[] = "";
                $output[] = "Registrar Information:";
                $output[] = "  Registrar: " . $registrar['name'];
                
                if (!empty($registrar['iana_id'])) {
                    $output[] = "  Registrar IANA ID: " . $registrar['iana_id'];
                }
                if (!empty($registrar['whois_server'])) {
                    $output[] = "  Registrar WHOIS Server: " . $registrar['whois_server'];
                }
                if (!empty($registrar['url'])) {
                    $output[] = "  Registrar URL: " . $registrar['url'];
                }
                if (!empty($registrar['email'])) {
                    $output[] = "  Registrar Abuse Contact Email: " . $registrar['email'];
                }
                if (!empty($registrar['phone'])) {
                    $output[] = "  Registrar Abuse Contact Phone: " . $registrar['phone'];
                }
            }
        }
        
        // 注册人信息
        if (!empty($data['registrant']) && is_array($data['registrant'])) {
            $hasData = false;
            foreach ($data['registrant'] as $value) {
                if (!empty($value)) {
                    $hasData = true;
                    break;
                }
            }
            
            if ($hasData) {
                $output[] = "";
                $output[] = "Registrant Information:";
                foreach ($data['registrant'] as $key => $value) {
                    if (!empty($value)) {
                        $label = ucwords(str_replace('_', ' ', $key));
                        $output[] = "  " . $label . ": " . $value;
                    }
                }
            }
        }
        
        // 管理联系人
        if (!empty($data['admin']) && is_array($data['admin'])) {
            $hasData = false;
            foreach ($data['admin'] as $value) {
                if (!empty($value)) {
                    $hasData = true;
                    break;
                }
            }
            
            if ($hasData) {
                $output[] = "";
                $output[] = "Admin Contact:";
                foreach ($data['admin'] as $key => $value) {
                    if (!empty($value)) {
                        $label = ucwords(str_replace('_', ' ', $key));
                        $output[] = "  " . $label . ": " . $value;
                    }
                }
            }
        }
        
        // 技术联系人
        if (!empty($data['tech']) && is_array($data['tech'])) {
            $hasData = false;
            foreach ($data['tech'] as $value) {
                if (!empty($value)) {
                    $hasData = true;
                    break;
                }
            }
            
            if ($hasData) {
                $output[] = "";
                $output[] = "Tech Contact:";
                foreach ($data['tech'] as $key => $value) {
                    if (!empty($value)) {
                        $label = ucwords(str_replace('_', ' ', $key));
                        $output[] = "  " . $label . ": " . $value;
                    }
                }
            }
        }
        
        // 账单联系人
        if (!empty($data['billing']) && is_array($data['billing'])) {
            $hasData = false;
            foreach ($data['billing'] as $value) {
                if (!empty($value)) {
                    $hasData = true;
                    break;
                }
            }
            
            if ($hasData) {
                $output[] = "";
                $output[] = "Billing Contact:";
                foreach ($data['billing'] as $key => $value) {
                    if (!empty($value)) {
                        $label = ucwords(str_replace('_', ' ', $key));
                        $output[] = "  " . $label . ": " . $value;
                    }
                }
            }
        }
        
        // 状态
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
                $output[] = "  " . strtoupper($ns);
            }
        }
        
        // DNSSEC
        if (!empty($data['dnssec'])) {
            $output[] = "";
            $output[] = "DNSSEC: " . $data['dnssec'];
        }
        
        // 日期
        if (!empty($data['dates'])) {
            $output[] = "";
            if (!empty($data['dates']['created'])) {
                $output[] = "Created Date: " . $data['dates']['created'];
            }
            if (!empty($data['dates']['updated'])) {
                $output[] = "Updated Date: " . $data['dates']['updated'];
            }
            if (!empty($data['dates']['expires'])) {
                $output[] = "Expiry Date: " . $data['dates']['expires'];
            }
            if (!empty($data['dates']['database'])) {
                $output[] = "Database Updated Date: " . $data['dates']['database'];
            }
        }
        
        return implode("\n", $output);
    }
}