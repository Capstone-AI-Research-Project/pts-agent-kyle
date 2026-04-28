// CASA Keyword Scanner — n8n Code Node
// Place this after the Investigation Type Switch fallback output.
// It scans the query (including any attached log content) for keywords
// associated with each investigation type and outputs matched types.
//
// Output: array of items, one per matched investigation type,
// each carrying the original query + the matched type.
// If no keywords match, defaults to auth_anomaly + lateral_movement
// (the two most broadly useful analysis paths).

const input = $input.first().json;
const query = (input.query || '').toLowerCase();

// Keyword definitions for each investigation type
const investigationKeywords = {
  auth_anomaly: [
    'failed login', 'login fail', 'authentication fail', 'invalid password',
    'brute force', 'credential stuff', 'account lockout', 'locked out',
    'invalid user', 'unknown user', 'logon failure', 'ssh login',
    'failed ssh', 'rdp login', 'kerberos', 'ntlm', 'password spray',
    'mfa', 'multi-factor', '4625', '4624', '4771', '4776',
    'pam_unix', 'sshd', 'accepted publickey', 'accepted password',
    'failed password', 'invalid credentials', 'unauthorized access',
    'root login', 'sudo', 'su:', 'authentication error',
    'access denied', 'permission denied', 'logon type'
  ],
  beaconing: [
    'beacon', 'c2', 'c&c', 'command and control', 'callback',
    'periodic', 'interval', 'heartbeat', 'dns tunnel', 'dns query',
    'domain age', 'newly registered', 'dga', 'domain generation',
    'jitter', 'sleep', 'implant', 'cobalt strike', 'metasploit',
    'reverse shell', 'outbound connection', 'suspicious domain',
    'external ip', 'known bad', 'threat intel', 'ioc',
    'every 60 seconds', 'every 30 seconds', 'regular interval',
    'nslookup', 'dns request', 'txt record', 'encoded dns'
  ],
  exfiltration: [
    'exfiltration', 'exfil', 'data theft', 'data leak', 'data loss',
    'large transfer', 'upload', 'google drive', 'dropbox', 'onedrive',
    'mega.nz', 'file share', 'bulk download', 'after hours',
    'off hours', 'unusual hour', '2am', '3am', '4am',
    'staging', 'archive', 'compress', 'zip', 'rar', '7z',
    'encrypted channel', 'outbound', 'egress', 'dlp',
    'sensitive file', 'confidential', 'proprietary', 'intellectual property',
    'usb', 'removable media', 'cloud storage', 'personal email',
    'large volume', 'bandwidth spike', 'data ratio'
  ],
  lateral_movement: [
    'lateral', 'east-west', 'pivot', 'pass-the-hash', 'pass the hash',
    'pth', 'pass-the-ticket', 'overpass', 'psexec', 'wmic', 'wmi',
    'winrm', 'powershell remote', 'smb', 'admin share', 'ipc$',
    'c$', 'admin$', 'remote desktop', 'rdp', 'ssh to', 'ssh from',
    'credential reuse', 'same credential', 'multiple host',
    'multiple server', 'spread', 'moved to', 'hopping',
    'internal scan', 'port scan', 'network scan', 'nmap',
    'service enumeration', 'net view', 'net use',
    '4648', '4624 type 3', 'type 10', 'remote logon'
  ],
  privilege_escalation: [
    'privilege escalation', 'privesc', 'priv esc', 'uac bypass', 'uac',
    'token manipulation', 'token impersonation', 'access token',
    'setuid', 'suid', 'setgid', 'sudo abuse', 'sudo', 'runas',
    'dll injection', 'dll hijack', 'dll side-load', 'named pipe',
    'process injection', 'process hollowing', 'elevated', 'elevation',
    'admin token', 'impersonation', '4672', '4688', '4648',
    'exploit local', 'kernel exploit', 'root', 'nt authority',
    'system privilege', 'seimpersonate', 'sedebug', 'potato'
  ],
  persistence: [
    'persistence', 'persist', 'backdoor', 'implant',
    'registry run', 'runonce', 'run key', 'autostart', 'startup folder',
    'scheduled task', '4698', '7045', 'service creation', 'new service',
    'wmi subscription', 'wmi event', 'com hijack', 'dll side-loading',
    'boot kit', 'bootkit', 'logon script', 'group policy', 'gpo',
    'cron job', 'crontab', 'systemd service', 'at job', 'rc.local',
    'browser extension', 'office macro', 'startup', 'autorun',
    'image file execution', 'ifeo', 'appinit', 'lsa', 'sssp'
  ],
  ransomware: [
    'ransomware', 'ransom', 'encrypt', 'encrypted files', 'file extension',
    'vssadmin', 'shadow copy', 'wmic shadowcopy', 'bcdedit', 'recovery disabled',
    'ransom note', 'readme.txt', 'how to decrypt', 'bitcoin', 'btc',
    'crypto wallet', 'monero', 'xmr', 'tor', 'onion', '.onion',
    'mass file modification', 'file entropy', 'wbadmin', 'locked files',
    'powershell encoded', 'invoke-expression', 'iex', '1102',
    'double extortion', 'data leak site', 'ryuk', 'lockbit', 'conti',
    'revil', 'blackcat', 'alphv', 'clop', 'maze', 'wannacry'
  ],
  insider_threat: [
    'insider threat', 'insider', 'internal threat', 'trusted insider',
    'unauthorized access', 'policy violation', 'after hours', 'off hours',
    'data hoarding', 'mass download', 'bulk download', 'mass copy',
    'email forwarding', 'forwarding rule', 'auto-forward',
    'disgruntled', 'termination', 'resignation', 'notice period',
    'competing company', 'competitor', 'personal device', 'personal cloud',
    'shadow it', 'need to know', 'least privilege violation',
    'usb', 'removable media', 'airdrop', 'bluetooth transfer',
    'screen capture', 'print', 'copy paste', 'clipboard'
  ],
  vulnerability_exploitation: [
    'vulnerability', 'exploit', 'cve', 'cve-', 'zero day', '0day', '0-day',
    'buffer overflow', 'stack overflow', 'heap overflow',
    'sql injection', 'sqli', 'xss', 'cross-site', 'cross site',
    'directory traversal', 'path traversal', 'lfi', 'rfi',
    'remote code execution', 'rce', 'command injection', 'cmd injection',
    'deserialization', 'ssrf', 'server-side request',
    'web shell', 'webshell', 'shell upload', 'file upload',
    'unpatched', 'patch', 'missing patch', 'vulnerable version',
    'shellcode', 'payload', 'metasploit', 'exploit-db',
    'w3wp', 'httpd', 'nginx error', 'apache error', '500 error'
  ]
};

// Scan for keyword matches
const matchedTypes = {};

for (const [type, keywords] of Object.entries(investigationKeywords)) {
  let matchCount = 0;
  const matchedKeywords = [];

  for (const keyword of keywords) {
    if (query.includes(keyword)) {
      matchCount++;
      matchedKeywords.push(keyword);
    }
  }

  if (matchCount > 0) {
    matchedTypes[type] = {
      count: matchCount,
      keywords: matchedKeywords
    };
  }
}

// Build output items — one per matched investigation type
const outputItems = [];
const types = Object.keys(matchedTypes);

if (types.length === 0) {
  // No keywords matched — run auth_anomaly as the safe default
  // (most comprehensive: runs both Log + Network analysts in parallel)
  outputItems.push({
    json: {
      query: input.query,
      domain: input.domain || 'mixed',
      investigation_type: 'auth_anomaly',
      scan_mode: 'comprehensive_default',
      matched_types: [],
      total_matches: 0,
      scan_note: 'No specific keywords detected — running default comprehensive analysis'
    }
  });
} else {
  // Output one item per matched type — downstream nodes will fan out
  for (const type of types) {
    outputItems.push({
      json: {
        query: input.query,
        domain: input.domain || 'mixed',
        investigation_type: type,
        scan_mode: 'comprehensive_keyword',
        matched_types: types,
        keyword_matches: matchedTypes[type].keywords,
        match_count: matchedTypes[type].count,
        total_matches: types.length,
        scan_note: `Keyword scan matched ${types.length} investigation type(s): ${types.join(', ')}`
      }
    });
  }
}

return outputItems;
