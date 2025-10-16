<?php

namespace X2nx\DomainParser\Formatters;

/**
 * WHOIS 响应格式化器
 * 
 * 将解析后的 WHOIS 数据格式化为统一的文本格式
 */
class WhoisFormatter
{
    /**
     * 格式化解析后的数据为统一文本格式
     * 
     * @param array $data 解析后的数据
     * @return string 格式化的文本
     */
    public static function format(array $data): string
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
            if (!empty($data['dates']['database'])) {
                $output[] = "Database Updated Date: " . $data['dates']['database'];
            }
            if (!empty($data['dates']['expires'])) {
                $output[] = "Expiry Date: " . $data['dates']['expires'];
            }
        }
        
        return implode("\n", $output);
    }
}
