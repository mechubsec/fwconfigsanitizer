'use strict';
// Fixture suite for the fwconfigsanitizer engine, per the MEC-6 privacy review
// ("Proposed fwconfigsanitizer fixture suite"). Every input is synthetic
// (RFC 5737 / documentation IPs, example.net-style domains, FAKE* secrets).
//
// Each standard case (1-94) asserts that one or more sensitive tokens are
// ABSENT from sanitizeConfig's output. `expected` records the review's
// documented status at commit 99c5186 so the harness can flag drift.
//
// Cases are grouped by vendor and given minimal, realistic vendor-detection
// context (interface/zone/policy lines) so `detectVendor` classifies them the
// same way a real config would, which is what several of the underlying gaps
// depend on (vendor-gated rules only fire for the detected vendor, except
// when detection fails entirely and every rule runs).

const JUNOS_SET_CTX = 'set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30;\n';
const JUNOS_CURLY_CTX =
  'security {\n' +
  '    zones {\n' +
  '        security-zone trust;\n' +
  '    }\n' +
  '    policies {\n' +
  '        from-zone trust to-zone untrust {\n' +
  '        }\n' +
  '    }\n' +
  '}\n';
const PANOS_XML_OPEN = '<config version="10.2.0" urldb="paloaltonetworks">\n<devices>\n<entry name="localhost.localdomain">\n';
const PANOS_XML_CLOSE = '\n</entry>\n</devices>\n</config>\n';
const FORTIOS_CTX = 'config system global\nend\n';
const ASA_CTX = 'access-list OUTSIDE-IN extended permit ip any any\n';
const CHECKPOINT_CTX =
  'set interface eth0 ipv4-address 192.0.2.1 mask-length 24\n' +
  'set static-route default nexthop gateway address 192.0.2.254\n';

function junos(body) {
  return JUNOS_SET_CTX + body;
}
function junosCurly(body) {
  return JUNOS_CURLY_CTX + body;
}
function panos(body) {
  return PANOS_XML_OPEN + body + PANOS_XML_CLOSE;
}
function fortios(body) {
  return FORTIOS_CTX + body;
}
function asa(body) {
  return ASA_CTX + body;
}
function checkpoint(body) {
  return CHECKPOINT_CTX + body;
}

const cases = [
  // ---------------------------------------------------------------------
  // Junos set
  // ---------------------------------------------------------------------
  {
    id: 1, group: 'junos-set', expected: 'PASS',
    description: 'set system host-name FAKEHOST-fw01',
    input: junos('set system host-name FAKEHOST-fw01\n'),
    leakTokens: ['FAKEHOST-fw01'],
  },
  {
    id: 2, group: 'junos-set', expected: 'PASS',
    description: 'set system domain-name fakeorg.internal',
    input: junos('set system domain-name fakeorg.internal\n'),
    leakTokens: ['fakeorg.internal'],
  },
  {
    id: 3, group: 'junos-set', expected: 'PASS',
    description: 'set system login user fakejdoe full-name "Fakefirst Fakelast"',
    input: junos('set system login user fakejdoe full-name "Fakefirst Fakelast"\n'),
    leakTokens: ['Fakefirst Fakelast'],
  },
  {
    id: 4, group: 'junos-set', expected: 'PASS',
    description: 'encrypted-password "$6$FAKESALT$FAKEHASH"',
    input: junos('set system login user fakejdoe4 authentication encrypted-password "$6$FAKESALT4$FAKEHASH4"\n'),
    leakTokens: ['$6$FAKESALT4$FAKEHASH4'],
  },
  {
    id: 5, group: 'junos-set', expected: 'PASS',
    description: 'pre-shared-key ascii-text "$9$FAKEPSK"',
    input: junos('set security ike policy FAKEIKEPOL5 pre-shared-key ascii-text "$9$FAKEPSK5abcDE"\n'),
    leakTokens: ['$9$FAKEPSK5abcDE'],
  },
  {
    id: 6, group: 'junos-set', expected: 'PASS',
    description: 'hexadecimal "$9$FAKEHEX"',
    input: junos('set security ike policy FAKEIKEPOL6 pre-shared-key hexadecimal "$9$FAKEHEXfeed6"\n'),
    leakTokens: ['$9$FAKEHEXfeed6'],
  },
  {
    id: 7, group: 'junos-set', expected: 'PASS',
    description: 'set snmp community FAKECOMM',
    input: junos('set snmp community FAKECOMM7\n'),
    leakTokens: ['FAKECOMM7'],
  },
  {
    id: 8, group: 'junos-set', expected: 'PASS',
    description: 'snmp location "…" / contact "…555-0100"',
    input: junos('set snmp location "Fake City 8, FAKE-DC1"\nset snmp contact "Fake Contact 8 555-0100"\n'),
    leakTokens: ['Fake City 8, FAKE-DC1', 'Fake Contact 8 555-0100'],
  },
  {
    id: 9, group: 'junos-set', expected: 'PASS',
    description: 'SNMPv3 usm authentication-key / privacy-key plus the user',
    input: junos(
      'set snmp v3 usm local-engine user fakesnmpuser9 authentication-md5 authentication-key "$9$FAKEAUTHKEY9"\n' +
      'set snmp v3 usm local-engine user fakesnmpuser9 privacy-des privacy-key "$9$FAKEPRIVKEY9"\n'
    ),
    leakTokens: ['fakesnmpuser9', '$9$FAKEAUTHKEY9', '$9$FAKEPRIVKEY9'],
  },
  {
    id: 10, group: 'junos-set', expected: 'PASS',
    description: 'autonomous-system 64511',
    input: junos('set routing-options autonomous-system 64511;\n'),
    leakTokens: ['64511'],
  },
  {
    id: 11, group: 'junos-set', expected: 'PASS',
    description: 'peer-as 64512',
    input: junos('set protocols bgp group ext-peers peer-as 64512;\n'),
    leakTokens: ['64512'],
  },
  {
    id: 12, group: 'junos-set', expected: 'PASS',
    description: 'local-as 64513',
    input: junos('set protocols bgp group ext-peers local-as 64513;\n'),
    leakTokens: ['64513'],
  },
  {
    id: 13, group: 'junos-set', expected: 'PASS',
    description: 'members target:64514:100',
    input: junos('set policy-options community FAKECOMM13 members target:64514:100;\n'),
    leakTokens: ['target:64514:100'],
  },
  {
    id: 14, group: 'junos-set', expected: 'PASS',
    description: 'BGP authentication-key "$9$…"',
    input: junos('set protocols bgp group ext-peers authentication-key "$9$FAKEBGPKEY14";\n'),
    leakTokens: ['$9$FAKEBGPKEY14'],
  },
  {
    id: 15, group: 'junos-set', expected: 'PASS',
    description: 'OSPF md5 1 key "$9$…"',
    input: junos('set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key "$9$FAKEOSPFKEY15";\n'),
    leakTokens: ['$9$FAKEOSPFKEY15'],
  },
  {
    id: 16, group: 'junos-set', expected: 'PASS',
    description: 'radius-server 192.0.2.20 secret "$9$…"',
    input: junos('set system radius-server 192.0.2.20 secret "$9$FAKERADSECRET16"\n'),
    leakTokens: ['$9$FAKERADSECRET16'],
  },
  {
    id: 17, group: 'junos-set', expected: 'PASS',
    description: 'NTP authentication-key 1 type md5 value "$9$…"',
    input: junos('set system ntp authentication-key 1 type md5 value "$9$FAKENTPKEY17";\n'),
    leakTokens: ['$9$FAKENTPKEY17'],
  },
  {
    id: 18, group: 'junos-set', expected: 'PASS',
    description: 'syslog host syslog.fakeorg.lan any any (the host keyword must survive)',
    input: junos('set system syslog host syslog.fakeorg.lan any any;\n'),
    leakTokens: ['syslog.fakeorg.lan'],
    mustSurvive: ['syslog host '],
  },
  {
    id: 19, group: 'junos-set', expected: 'PASS',
    description: 'Unquoted description FAKECUST-CIRCUIT-12345',
    input: junos('set interfaces ge-0/0/1 unit 0 description FAKECUST-CIRCUIT-12345;\n'),
    leakTokens: ['FAKECUST-CIRCUIT-12345'],
  },
  {
    id: 20, group: 'junos-set', expected: 'PASS',
    description: 'login message "…FakeCorp…"',
    input: junos('set system login message "Welcome to FakeCorp-Internal-20 — authorized use only";\n'),
    leakTokens: ['FakeCorp-Internal-20'],
  },
  {
    id: 21, group: 'junos-set', expected: 'PASS',
    description: 'IKE gateway address vpn.fakeorg.corp',
    input: junos('set security ike gateway FAKEGW21 address vpn.fakeorg21.corp;\n'),
    leakTokens: ['vpn.fakeorg21.corp'],
  },
  {
    id: 22, group: 'junos-set', expected: 'PASS',
    description: 'base-distinguished-name dc=fakeorg,dc=example',
    input: junos('set system radius-server 192.0.2.22 base-distinguished-name "dc=fakeorg22,dc=example";\n'),
    leakTokens: ['dc=fakeorg22,dc=example'],
  },
  {
    id: 23, group: 'junos-set', expected: 'PASS',
    description: 'archive-sites "ftp://fakeuser:FAKEPASS@192.0.2.50/cfg"',
    input: junos('set system archival configuration archive-sites "ftp://fakeuser23:FAKEPASS23@192.0.2.50/cfg";\n'),
    leakTokens: ['fakeuser23:FAKEPASS23'],
  },
  {
    id: 24, group: 'junos-set', expected: 'PASS', // fixed: MAC addresses now redacted (M21)
    description: 'mac 00:00:5e:00:53:01',
    input: junos('set interfaces irb unit 24 mac 00:00:5e:00:53:24;\n'),
    leakTokens: ['00:00:5e:00:53:24'],
  },
  {
    id: 25, group: 'junos-set', expected: 'PASS',
    description: 'license keys key "FAKELICENSE…"',
    input: junos('set system license keys key "FAKELICENSE1234567890abcdef25"\n'),
    leakTokens: ['FAKELICENSE1234567890abcdef25'],
  },
  {
    id: 26, group: 'junos-set', expected: 'PASS',
    description: 'Hostname reused in syslog file FAKEHOST-fw01-messages',
    input: junos(
      'set system host-name FAKEHOST-fw01\n' +
      'set system syslog file FAKEHOST-fw01-messages any any;\n'
    ),
    leakTokens: ['FAKEHOST-fw01-messages'],
  },
  {
    id: 27, group: 'junos-set', expected: 'PASS',
    description: 'plain-text-password-value FAKEPLAIN',
    input: junos('set security ike policy FAKEIKEPOL27 pre-shared-key plain-text-password-value FAKEPLAIN27;\n'),
    leakTokens: ['FAKEPLAIN27'],
  },
  {
    id: 28, group: 'junos-set', expected: 'PASS', // fixed: IPv4 "_" boundary (M21)
    description: 'address H_192.0.2.10 …',
    input: junos('set security address-book global address H_192.0.2.10 192.0.2.10/32;\n'),
    leakTokens: ['H_192.0.2.10'],
  },
  {
    id: 29, group: 'junos-set', expected: 'PASS',
    description: 'url "https://…?token=FAKETOKEN"',
    input: junos('set system services rest listen https://portal.fakeorg29.corp/api?token=FAKETOKEN29;\n'),
    leakTokens: ['FAKETOKEN29'],
  },

  // ---------------------------------------------------------------------
  // Junos curly and XML
  // ---------------------------------------------------------------------
  {
    id: 30, group: 'junos-curly-xml', expected: 'PASS',
    description: 'host-name FAKEHOST;',
    input: junosCurly('system {\n    host-name FAKEHOST30;\n}\n'),
    leakTokens: ['FAKEHOST30'],
  },
  {
    id: 31, group: 'junos-curly-xml', expected: 'PASS',
    description: 'user fakecurly {',
    input: junosCurly('system {\n    login {\n        user fakecurly31 {\n            uid 2001;\n            class super-user;\n        }\n    }\n}\n'),
    leakTokens: ['fakecurly31'],
  },
  {
    id: 32, group: 'junos-curly-xml', expected: 'PASS',
    description: 'community FAKECOMM { … }',
    input: junosCurly('snmp {\n    community FAKECOMM32 {\n        authorization read-only;\n    }\n}\n'),
    leakTokens: ['FAKECOMM32'],
  },
  {
    id: 33, group: 'junos-curly-xml', expected: 'PASS',
    description: '/* Owner: Fakefirst … */',
    input: junosCurly('/* Owner: Fakefirst33 Fakelast33, ext 5533 */\nsystem {\n    host-name FAKEHOST33;\n}\n'),
    leakTokens: ['Fakefirst33 Fakelast33'],
  },
  {
    id: 34, group: 'junos-curly-xml', expected: 'PASS',
    description: 'peer-as 64520; local-as 64521; authentication-key "$9$…";',
    input: junosCurly('protocols {\n    bgp {\n        group ext-peers {\n            peer-as 64520;\n            local-as 64521;\n            authentication-key "$9$FAKEBGPKEY34";\n        }\n    }\n}\n'),
    leakTokens: ['64520', '64521', '$9$FAKEBGPKEY34'],
  },
  {
    id: 35, group: 'junos-curly-xml', expected: 'PASS',
    description: 'description FAKE; / server ntp1.fakeorg.corp; / domain-search fakeorg.internal;',
    input: junosCurly(
      'interfaces {\n    ge-0/0/2 {\n        unit 0 {\n            description FAKE-CURLY-DESC-35;\n        }\n    }\n}\n' +
      'system {\n    ntp {\n        server ntp1.fakeorg35.corp;\n    }\n    domain-search fakeorg35.internal;\n}\n'
    ),
    leakTokens: ['FAKE-CURLY-DESC-35', 'ntp1.fakeorg35.corp', 'fakeorg35.internal'],
  },
  {
    id: 36, group: 'junos-curly-xml', expected: 'PASS',
    description: 'Multi-line message',
    input: junosCurly(
      'system {\n    login {\n        message "Fake Corp 36 Confidential\\nAuthorized access only, line two 36";\n    }\n}\n'
    ),
    leakTokens: ['Fake Corp 36 Confidential'],
  },
  {
    id: 37, group: 'junos-curly-xml', expected: 'PASS',
    description: 'display xml output must be detected as Junos, not PAN-OS',
    input:
      '<configuration>\n' +
      '  <system>\n' +
      '    <host-name>FAKEHOST-fw01-37</host-name>\n' +
      '    <login>\n' +
      '      <user>\n' +
      '        <name>fakejdoe37</name>\n' +
      '        <authentication>\n' +
      '          <encrypted-password>$9$FAKEXMLHASH37</encrypted-password>\n' +
      '        </authentication>\n' +
      '      </user>\n' +
      '    </login>\n' +
      '  </system>\n' +
      '  <snmp>\n' +
      '    <community>\n' +
      '      <name>FAKECOMM37</name>\n' +
      '    </community>\n' +
      '  </snmp>\n' +
      '</configuration>\n',
    leakTokens: ['FAKEHOST-fw01-37', 'fakejdoe37', '$9$FAKEXMLHASH37', 'FAKECOMM37'],
  },

  // ---------------------------------------------------------------------
  // PAN-OS
  // ---------------------------------------------------------------------
  {
    id: 38, group: 'panos', expected: 'PASS',
    description: '<domain>fakeorg.internal</domain>',
    input: panos('<domain>fakeorg38.internal</domain>'),
    leakTokens: ['fakeorg38.internal'],
  },
  {
    id: 39, group: 'panos', expected: 'PASS',
    description: '<phash>',
    input: panos('<phash>$1$FAKEPANHASH39</phash>'),
    leakTokens: ['$1$FAKEPANHASH39'],
  },
  {
    id: 40, group: 'panos', expected: 'PASS',
    description: '<pre-shared-key><key>-AQ==…',
    input: panos('<pre-shared-key><key>-AQ==FAKEPSKVALUE40==</key></pre-shared-key>'),
    leakTokens: ['-AQ==FAKEPSKVALUE40=='],
  },
  {
    id: 41, group: 'panos', expected: 'PASS',
    description: '<snmp-community-string>, <location>, <contact>',
    input: panos('<snmp-community-string>FAKECOMM41</snmp-community-string><location>Fake City 41</location><contact>fakecontact41@example.corp</contact>'),
    leakTokens: ['FAKECOMM41', 'Fake City 41', 'fakecontact41@example.corp'],
  },
  {
    id: 42, group: 'panos', expected: 'PASS',
    description: '<authpwd> / <privpwd> plus the v3 user',
    input: panos('<v3-user>fakesnmpv3admin42</v3-user><authpwd>$9$FAKEAUTHPWD42</authpwd><privpwd>$9$FAKEPRIVPWD42</privpwd>'),
    leakTokens: ['fakesnmpv3admin42', '$9$FAKEAUTHPWD42', '$9$FAKEPRIVPWD42'],
  },
  {
    id: 43, group: 'panos', expected: 'PASS',
    description: 'RADIUS/TACACS <secret>-AQ==…',
    input: panos('<secret>-AQ==FAKERADSECRET43==</secret>'),
    leakTokens: ['-AQ==FAKERADSECRET43=='],
  },
  {
    id: 44, group: 'panos', expected: 'PASS',
    description: 'LDAP <base>, <bind-dn>, <bind-password>',
    input: panos('<base>dc=fakeorg44,dc=example</base><bind-dn>cn=fakebind44,dc=fakeorg44,dc=example</bind-dn><bind-password>-AQ==FAKEBINDPW44==</bind-password>'),
    leakTokens: ['dc=fakeorg44,dc=example', 'cn=fakebind44', '-AQ==FAKEBINDPW44=='],
  },
  {
    id: 45, group: 'panos', expected: 'PASS', // fixed: generic PEM regex + <public-key>/<common-name> handling (M21)
    description: '<common-name> and <public-key> certificate body',
    input: panos('<common-name>fakeorg45-ca.internal</common-name><public-key>-----BEGIN PUBLIC KEY-----\nFAKEKEYDATA45\n-----END PUBLIC KEY-----</public-key>'),
    leakTokens: ['fakeorg45-ca.internal', 'FAKEKEYDATA45'],
  },
  {
    id: 46, group: 'panos', expected: 'PASS', // fixed: IPv6 "<" boundary (M21)
    description: '<ip>fd12:3456:789a:4::5</ip>',
    input: panos('<ip>fd12:3456:789a:4::5</ip>'),
    leakTokens: ['fd12:3456:789a:4::5'],
  },
  {
    id: 47, group: 'panos', expected: 'PASS',
    description: '<local-as> / <peer-as>',
    input: panos('<local-as>64530</local-as><peer-as>64531</peer-as>'),
    leakTokens: ['64530', '64531'],
  },
  {
    id: 48, group: 'panos', expected: 'PASS',
    description: 'NTP <authentication-key>',
    input: panos('<authentication-key>$9$FAKENTPKEY48</authentication-key>'),
    leakTokens: ['$9$FAKENTPKEY48'],
  },
  {
    id: 49, group: 'panos', expected: 'PASS',
    description: '<login-banner>, <serial>FAKESN0001</serial>',
    input: panos('<login-banner>Welcome to FakeCorp49 — Authorized Use Only</login-banner><serial>FAKESN000149</serial>'),
    leakTokens: ['FakeCorp49', 'FAKESN000149'],
  },
  {
    id: 50, group: 'panos', expected: 'PASS',
    description: '<auth-code>',
    input: panos('<auth-code>FAKEAUTHCODE50</auth-code>'),
    leakTokens: ['FAKEAUTHCODE50'],
  },
  {
    id: 51, group: 'panos', expected: 'PASS',
    description: 'Set format pre-shared-key key -AQ==… / snmp-community-string / hostname',
    // Deliberately no XML/vendor markers: PAN-OS set-CLI syntax is not
    // recognised by detectVendor at all, so this stays vendor 'unknown'.
    input:
      'set network ike gateway GW1 authentication pre-shared-key key -AQ==FAKESETPSK51==\n' +
      'set deviceconfig system snmp-setting snmp-community-string FAKESETCOMM51\n' +
      'set deviceconfig system hostname FAKEHOST-fw01-51\n',
    leakTokens: ['-AQ==FAKESETPSK51==', 'FAKESETCOMM51', 'FAKEHOST-fw01-51'],
  },

  // ---------------------------------------------------------------------
  // FortiOS
  // ---------------------------------------------------------------------
  {
    id: 52, group: 'fortios', expected: 'PASS',
    description: '#config-version=…:user=fakeuser',
    input: fortios('#config-version=FGT60F-7.2.5-FW-build1517:opmode=0:vdom=0:user=fakeuser52\n'),
    leakTokens: ['fakeuser52'],
  },
  {
    id: 53, group: 'fortios', expected: 'PASS',
    description: 'Second edit "fakeadm2" in system admin',
    input: fortios(
      'config system admin\n' +
      '    edit "fakeadmin53a"\n' +
      '        set password ENC FAKEENC53A\n' +
      '    next\n' +
      '    edit "fakeadm53b"\n' +
      '        set password ENC FAKEENC53B\n' +
      '    next\n' +
      'end\n'
    ),
    leakTokens: ['fakeadm53b'],
  },
  {
    id: 54, group: 'fortios', expected: 'PASS',
    description: 'set psksecret ENC FAKE',
    input: fortios('config vpn ipsec phase1-interface\n    edit "FAKETUN54"\n        set psksecret ENC FAKE54PSKVALUE\n    next\nend\n'),
    leakTokens: ['FAKE54PSKVALUE'],
  },
  {
    id: 55, group: 'fortios', expected: 'PASS',
    description: 'config user local / edit "fakevpnuser"',
    input: fortios('config user local\n    edit "fakevpnuser55"\n        set type password\n    next\nend\n'),
    leakTokens: ['fakevpnuser55'],
  },
  {
    id: 56, group: 'fortios', expected: 'PASS',
    description: 'set server "radius.fakeorg.corp"',
    input: fortios('config user radius\n    edit "fakeradius56"\n        set server "radius.fakeorg56.corp"\n    next\nend\n'),
    leakTokens: ['radius.fakeorg56.corp'],
  },
  {
    id: 57, group: 'fortios', expected: 'PASS',
    description: 'SNMP community set name "FAKECOMM"',
    input: fortios('config system snmp community\n    edit 1\n        set name "FAKECOMM57"\n    next\nend\n'),
    leakTokens: ['FAKECOMM57'],
  },
  {
    id: 58, group: 'fortios', expected: 'PASS',
    description: 'set location / set contact-info',
    input: fortios('config system snmp sysinfo\n    set location "Fake Branch Office 58"\n    set contact-info "fakeadmin58@example.corp"\nend\n'),
    leakTokens: ['Fake Branch Office 58', 'fakeadmin58@example.corp'],
  },
  {
    id: 59, group: 'fortios', expected: 'PASS',
    description: 'set auth-pwd ENC / set priv-pwd ENC',
    input: fortios('config system snmp user\n    edit "fakesnmpuser59"\n        set auth-pwd ENC FAKE59AUTH\n        set priv-pwd ENC FAKE59PRIV\n    next\nend\n'),
    leakTokens: ['FAKE59AUTH', 'FAKE59PRIV'],
  },
  {
    id: 60, group: 'fortios', expected: 'PASS',
    description: 'set as 64540',
    input: fortios('config router bgp\n    set as 64540\nend\n'),
    leakTokens: ['64540'],
  },
  {
    id: 61, group: 'fortios', expected: 'PASS',
    description: 'NTP set key ENC',
    input: fortios('config system ntp\n    config ntpserver\n        edit 1\n            set key ENC FAKE61NTPKEY\n        next\n    end\nend\n'),
    leakTokens: ['FAKE61NTPKEY'],
  },
  {
    id: 62, group: 'fortios', expected: 'PASS',
    description: 'set domain "fakeorg.lan"',
    input: fortios('config system dns\n    set domain "fakeorg62.lan"\nend\n'),
    leakTokens: ['fakeorg62.lan'],
  },
  {
    id: 63, group: 'fortios', expected: 'PASS',
    description: 'LDAP set dn / set username "cn=…"',
    input: fortios('config user ldap\n    edit "fakeldap63"\n        set dn "dc=fakeorg63,dc=example"\n        set username "cn=fakebind63,dc=fakeorg63,dc=example"\n    next\nend\n'),
    leakTokens: ['dc=fakeorg63,dc=example', 'cn=fakebind63'],
  },
  {
    id: 64, group: 'fortios', expected: 'PASS', // fixed: generic PEM regex covers CERTIFICATE, not just PRIVATE KEY (M21)
    description: 'set certificate "-----BEGIN CERTIFICATE-----…"',
    input: fortios('config vpn certificate local\n    edit "FAKECERT64"\n        set certificate "-----BEGIN CERTIFICATE-----\nFAKECERTDATA64\n-----END CERTIFICATE-----"\n    next\nend\n'),
    leakTokens: ['FAKECERTDATA64'],
  },
  {
    id: 65, group: 'fortios', expected: 'PASS',
    description: 'Second edit "FAKE-ADDR-2" in firewall address',
    input: fortios(
      'config firewall address\n' +
      '    edit "FAKE-ADDR-65A"\n' +
      '        set subnet 192.0.2.0 255.255.255.0\n' +
      '    next\n' +
      '    edit "FAKE-ADDR-65B"\n' +
      '        set subnet 198.51.100.0 255.255.255.0\n' +
      '    next\n' +
      'end\n'
    ),
    leakTokens: ['FAKE-ADDR-65B'],
  },
  {
    id: 66, group: 'fortios', expected: 'PASS',
    description: 'set api-key ENC',
    input: fortios('config system api-user\n    edit "fakeapiuser66"\n        set api-key ENC FAKE66APIKEY\n    next\nend\n'),
    leakTokens: ['FAKE66APIKEY'],
  },
  {
    id: 67, group: 'fortios', expected: 'PASS',
    description: 'set alias / set description',
    input: fortios('config firewall address\n    edit "FAKE-ADDR-67"\n        set alias "Fake Alias 67"\n        set description "Fake Desc Text 67"\n    next\nend\n'),
    leakTokens: ['Fake Alias 67', 'Fake Desc Text 67'],
  },
  {
    id: 68, group: 'fortios', expected: 'PASS',
    description: 'Multi-line set buffer',
    input: fortios('config system replacemsg mail "fake-msg-68"\n    set buffer "Line one of the banner\\nFakeCorp confidential line two 68"\nend\n'),
    leakTokens: ['FakeCorp confidential line two 68'],
  },
  {
    id: 69, group: 'fortios', expected: 'PASS',
    description: 'set md5-keys 1 ENC, ppk-secret ENC, psksecret-remote ENC',
    input: fortios(
      'config router ospf\n    set md5-keys 1 ENC FAKE69MD5\nend\n' +
      'config vpn ipsec phase1-interface\n    edit "FAKETUN69"\n        set ppk-secret ENC FAKE69PPK\n        set psksecret-remote ENC FAKE69REMOTE\n    next\nend\n'
    ),
    leakTokens: ['FAKE69MD5', 'FAKE69PPK', 'FAKE69REMOTE'],
  },
  {
    id: 70, group: 'fortios', expected: 'PASS',
    description: 'set ipv6-gateway fd12:…',
    input: fortios('config system interface\n    edit "wan1"\n        set ipv6-gateway fd12:3456:789a:5::1\n    next\nend\n'),
    leakTokens: ['fd12:3456:789a:5::1'],
  },

  // ---------------------------------------------------------------------
  // Cisco ASA / IOS
  // ---------------------------------------------------------------------
  {
    id: 71, group: 'asa-ios', expected: 'PASS',
    description: 'hostname / domain-name',
    input: asa('hostname FAKEHOST71\ndomain-name fakeorg71.corp\n'),
    leakTokens: ['FAKEHOST71', 'fakeorg71.corp'],
  },
  {
    id: 72, group: 'asa-ios', expected: 'PASS',
    description: 'enable password $sha512$… pbkdf2',
    input: asa('enable password $sha512$FAKEHASH72 pbkdf2\n'),
    leakTokens: ['$sha512$FAKEHASH72'],
  },
  {
    id: 73, group: 'asa-ios', expected: 'PASS',
    description: 'IKEv1/v2 pre-shared-key',
    input: asa('tunnel-group 192.0.2.73 ipsec-attributes\n ikev1 pre-shared-key FAKEIKE73KEY\n'),
    leakTokens: ['FAKEIKE73KEY'],
  },
  {
    id: 74, group: 'asa-ios', expected: 'PASS',
    description: 'snmp-server host … community FAKE version 2c',
    input: asa('snmp-server host 192.0.2.74 community FAKECOMM74 version 2c\n'),
    leakTokens: ['FAKECOMM74'],
  },
  {
    id: 75, group: 'asa-ios', expected: 'PASS',
    description: 'snmp-server user … auth sha FAKE priv aes 128 FAKE',
    input: asa('snmp-server user fakesnmpuser75 FAKEGROUP75 v3 auth sha FAKE75AUTH priv aes 128 FAKE75PRIV\n'),
    leakTokens: ['FAKE75AUTH', 'FAKE75PRIV'],
  },
  {
    id: 76, group: 'asa-ios', expected: 'PASS',
    description: 'aaa-server key, ldap-login-password, ldap-base-dn, ldap-login-dn',
    input: asa(
      'aaa-server FAKEAAA76 protocol radius\n' +
      'aaa-server FAKEAAA76 (inside) host 192.0.2.76\n' +
      ' key FAKE76AAAKEY\n' +
      'ldap attribute-map FAKEMAP76\n' +
      ' ldap-login-password FAKE76LDAPPW\n' +
      ' ldap-login-dn cn=fakebind76,dc=fakeorg76,dc=example\n' +
      ' ldap-base-dn dc=fakeorg76,dc=example\n'
    ),
    leakTokens: ['FAKE76AAAKEY', 'FAKE76LDAPPW', 'fakebind76', 'dc=fakeorg76'],
  },
  {
    id: 77, group: 'asa-ios', expected: 'PASS',
    description: 'ntp authentication-key 1 md5 FAKE',
    input: asa('ntp authentication-key 1 md5 FAKE77NTPKEY\n'),
    leakTokens: ['FAKE77NTPKEY'],
  },
  {
    id: 78, group: 'asa-ios', expected: 'PASS',
    description: 'ospf message-digest-key, neighbor … password 0',
    input: asa('interface GigabitEthernet0/1\n ip ospf message-digest-key 1 md5 FAKE78OSPFKEY\nrouter bgp 64550\n neighbor 192.0.2.78 password 0 FAKE78NEIGHPW\n'),
    leakTokens: ['FAKE78OSPFKEY', 'FAKE78NEIGHPW'],
  },
  {
    id: 79, group: 'asa-ios', expected: 'PASS',
    description: 'banner motd',
    input: asa('banner motd ^FakeCorp79 Unauthorized Access Prohibited^\n'),
    leakTokens: ['FakeCorp79 Unauthorized Access Prohibited'],
  },
  {
    id: 80, group: 'asa-ios', expected: 'PASS',
    description: 'name 192.0.2.50 FAKE-DB description …',
    input: asa('name 192.0.2.80 FAKE-DB80 description Fake internal database server 80\n'),
    leakTokens: ['FAKE-DB80', 'Fake internal database server 80'],
  },
  {
    id: 81, group: 'asa-ios', expected: 'PASS', // fixed: trustpoint fqdn/subject-name CN + Cisco cert chain hex block (M21)
    description: 'Trustpoint subject-name / fqdn / cert-chain hex',
    input: asa(
      'crypto ca trustpoint FAKETP81\n' +
      ' subject-name CN=fakeorg81.example,O=FakeOrg81\n' +
      ' fqdn fakeorg81.example.corp\n' +
      'crypto ca certificate chain FAKETP81\n' +
      ' certificate ca 01\n' +
      '  308201 FAKECERTHEX81 A0030201\n' +
      '  quit\n'
    ),
    leakTokens: ['fakeorg81.example', 'fakeorg81.example.corp', 'FAKECERTHEX81'],
  },
  {
    id: 82, group: 'asa-ios', expected: 'PASS',
    description: 'access-list X remark …; an object used in an ACL',
    input: asa('access-list FAKEACL82 extended remark Fake circuit note 82\naccess-list FAKEACL82 extended permit ip object FAKE-OBJ82 any\n'),
    leakTokens: ['Fake circuit note 82', 'FAKE-OBJ82'],
  },
  {
    id: 83, group: 'asa-ios', expected: 'PASS',
    description: 'https://fakeuser:FAKEPW@wiki.fakeorg.corp/',
    input: asa('banner login ^See https://fakeuser83:FAKEPW83@wiki.fakeorg83.corp/ for details^\n'),
    // The URL rule only matches a scheme immediately followed by a domain, so
    // userinfo before the "@" breaks that match entirely; the username then
    // falls through untouched (the password+host also survive as a whole,
    // but get incidentally reformatted by the unrelated email rule, which
    // treats "FAKEPW83@wiki.fakeorg83.corp" as if it were an email address).
    leakTokens: ['fakeuser83'],
  },
  {
    id: 84, group: 'asa-ios', expected: 'PASS', // fixed: MAC addresses now redacted (M21)
    description: 'mac-address 0000.5e00.5302',
    input: asa('interface GigabitEthernet0/2\n mac-address 0000.5e00.5384\n'),
    leakTokens: ['0000.5e00.5384'],
  },
  {
    id: 85, group: 'asa-ios', expected: 'PASS',
    description: 'IOS enable secret 5, username u secret 9',
    input: asa('enable secret 5 $1$FAKE85ENABLE$abcdefghij\nusername fakeadmin85 secret 9 $9$FAKE85HASH$klmnopqrst\n'),
    leakTokens: ['$1$FAKE85ENABLE', 'fakeadmin85', '$9$FAKE85HASH'],
  },
  {
    id: 86, group: 'asa-ios', expected: 'PASS',
    description: 'IOS password 7, key-string 7, tacacs-server key, radius-server key, crypto isakmp key, ip ospf authentication-key',
    input: asa(
      'line vty 0 4\n password 7 FAKE86PW7\nkey chain FAKECHAIN86\n key 1\n  key-string 7 FAKE86KEYSTR\n' +
      'tacacs-server host 192.0.2.86 key FAKE86TACKEY\nradius-server key FAKE86RADKEY\n' +
      'crypto isakmp key FAKE86ISAKMPKEY address 192.0.2.87\ninterface Tunnel0\n ip ospf authentication-key FAKE86OSPFKEY\n'
    ),
    leakTokens: ['FAKE86PW7', 'FAKE86KEYSTR', 'FAKE86TACKEY', 'FAKE86RADKEY', 'FAKE86ISAKMPKEY', 'FAKE86OSPFKEY'],
  },
  {
    id: 87, group: 'asa-ios', expected: 'PASS',
    description: 'IOS local-as, set community AS:N, set extcommunity rt',
    input: asa(
      'router bgp 64560\n neighbor 192.0.2.88 local-as 64561\nroute-map FAKERM87 permit 10\n set community 64562:100\n set extcommunity rt 64563:100\n'
    ),
    leakTokens: ['64561', '64562:100', '64563:100'],
  },
  {
    id: 88, group: 'asa-ios', expected: 'PASS', // fixed: generic PEM regex covers OPENSSH PRIVATE KEY (M21)
    description: 'Embedded OPENSSH private-key PEM block',
    input: asa('crypto key generate rsa\n! embedded key material below\n-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA88\n-----END OPENSSH PRIVATE KEY-----\n'),
    leakTokens: ['FAKEKEYDATA88'],
  },

  // ---------------------------------------------------------------------
  // Check Point Gaia
  // ---------------------------------------------------------------------
  {
    id: 89, group: 'checkpoint', expected: 'PASS',
    description: 'set user … password-hash $6$…',
    input: checkpoint('set user fakeuser89 password-hash $6$FAKE89HASH\n'),
    leakTokens: ['$6$FAKE89HASH'],
  },
  {
    id: 90, group: 'checkpoint', expected: 'PASS',
    description: 'set expert-password-hash',
    input: checkpoint('set expert-password-hash $6$FAKE90EXPERTHASH\n'),
    leakTokens: ['$6$FAKE90EXPERTHASH'],
  },
  {
    id: 91, group: 'checkpoint', expected: 'PASS',
    description: 'set ntp server primary <fqdn> / set domainname',
    input: checkpoint('set ntp server primary fakentp91.example.corp\nset domainname fakeorg91.internal\n'),
    leakTokens: ['fakentp91.example.corp', 'fakeorg91.internal'],
  },
  {
    id: 92, group: 'checkpoint', expected: 'PASS',
    description: 'SNMP auth-pass-phrase / privacy-pass-phrase',
    input: checkpoint('set snmp usm auth-pass-phrase FAKE92AUTHPHRASE\nset snmp usm privacy-pass-phrase FAKE92PRIVPHRASE\n'),
    leakTokens: ['FAKE92AUTHPHRASE', 'FAKE92PRIVPHRASE'],
  },
  {
    id: 93, group: 'checkpoint', expected: 'PASS',
    description: 'set as / remote-as',
    input: checkpoint('set as 64570\nset bgp external-remote-as 64571\n'),
    leakTokens: ['64570', '64571'],
  },
  {
    id: 94, group: 'checkpoint', expected: 'PASS',
    description: 'msgvalue, SNMP contact/location',
    input: checkpoint('set message msgvalue "FAKE94MSG"\nset snmp contact "fakecontact94@example.corp"\nset snmp location "Fake Location 94"\n'),
    leakTokens: ['FAKE94MSG', 'fakecontact94@example.corp', 'Fake Location 94'],
  },

  // ---------------------------------------------------------------------
  // Regression cases from the H3b PR #10 review (request-changes findings
  // 1-7). Each reproduces a leak the review found in commit a48d62f.
  // ---------------------------------------------------------------------
  {
    id: 101, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 1: "enable password 7 X" -- the type-7 marker must not be eaten as the value',
    input: asa('enable password 7 FAKE101ENABLEPW\n'),
    leakTokens: ['FAKE101ENABLEPW'],
    mustSurvive: ['enable password 7 '],
  },
  {
    id: 102, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 1: "radius-server key 7 X" -- same type-7 marker bug',
    input: asa('radius-server key 7 FAKE102RADKEY\n'),
    leakTokens: ['FAKE102RADKEY'],
    mustSurvive: ['radius-server key 7 '],
  },
  {
    id: 103, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 1: "ip ospf message-digest-key 1 md5 7 X" -- same type-7 marker bug',
    input: asa('ip ospf message-digest-key 1 md5 7 FAKE103OSPFKEY\n'),
    leakTokens: ['FAKE103OSPFKEY'],
    mustSurvive: ['ip ospf message-digest-key 1 md5 7 '],
  },
  {
    id: 104, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 2: bare "password X" on a line-mode config line (line vty), no vendor-specific keyword around it',
    input: asa('line vty 0 4\n password FAKE104VTYPW\n'),
    leakTokens: ['FAKE104VTYPW'],
    mustSurvive: ['line vty 0 4', 'password '],
  },
  {
    id: 105, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 2: "username U password X privilege 15" without a trailing "encrypted" marker',
    input: asa('username fakeuser105 password FAKE105USERPW privilege 15\n'),
    leakTokens: ['FAKE105USERPW'],
    mustSurvive: ['privilege 15'],
  },
  {
    id: 106, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 2: "username U privilege 15 secret 9 $9$..." -- "privilege 15" sits between the username and "secret"',
    input: asa('username fakeuser106 privilege 15 secret 9 $9$FAKE106SECRET\n'),
    leakTokens: ['$9$FAKE106SECRET'],
    mustSurvive: ['privilege 15'],
  },
  {
    id: 107, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 2: PAN-OS set-CLI "... server s1 secret X" -- "secret" not directly preceded by "set "',
    input: 'set shared server-profile email fakeprof107 server s1 secret FAKE107SECRET\n',
    leakTokens: ['FAKE107SECRET'],
    mustSurvive: ['server s1'],
  },
  {
    id: 108, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 3: XML element with an attribute on the opening tag, e.g. <bind-password encrypted="yes">X</bind-password>',
    input: panos('<bind-password encrypted="yes">FAKE108BINDPW</bind-password>'),
    leakTokens: ['FAKE108BINDPW'],
  },
  {
    id: 109, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 3: CDATA-wrapped XML secret, e.g. <password><![CDATA[X]]></password>, and Junos display-xml nested <pre-shared-key><ascii-text>X</ascii-text></pre-shared-key>',
    input: panos('<password><![CDATA[FAKE109CDATAPW]]></password><pre-shared-key><ascii-text>$9$FAKE109PSK</ascii-text></pre-shared-key>'),
    leakTokens: ['FAKE109CDATAPW', '$9$FAKE109PSK'],
  },
  {
    id: 110, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Finding 4: ASA "snmp-server host inside 10.1.1.1 community X" -- two tokens between "host" and "community"',
    input: asa('snmp-server host inside 10.1.1.1 community FAKE110COMM\n'),
    leakTokens: ['FAKE110COMM'],
    mustSurvive: ['snmp-server host inside'],
  },

  // ---------------------------------------------------------------------
  // Regression cases from the H3b PR #10 round-2 review (request-changes
  // findings 1-5). Each reproduces a leak, or an over-redaction, the
  // review found in commit 66a306d.
  // ---------------------------------------------------------------------
  {
    id: 111, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Round 2 finding 1: "key config-key password-encrypt X" -- the master key value itself must be redacted',
    input: asa('key config-key password-encrypt FAKE111MASTERKEY\n'),
    leakTokens: ['FAKE111MASTERKEY'],
    mustSurvive: ['key config-key password-encrypt'],
  },
  {
    id: 112, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Round 2 finding 1: the generic catch-all must not over-redact structural "key"/"password" sub-command verbs',
    input: asa('crypto key generate rsa\nkey chain FAKE112CHAINNAME\npassword encryption aes\n'),
    leakTokens: [],
    mustSurvive: ['crypto key generate rsa', 'key chain FAKE112CHAINNAME', 'password encryption aes'],
  },
  {
    id: 113, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Round 2 finding 2: "*-pass-phrase" keyword (e.g. Fortinet private-key-pass-phrase) not covered by the catch-all',
    input: 'set ssl-ssh-profile x private-key-pass-phrase FAKE113PASSPHRASE\n',
    leakTokens: ['FAKE113PASSPHRASE'],
    mustSurvive: ['private-key-pass-phrase'],
  },
  {
    id: 114, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Round 2 finding 3: a secret in a URL query string, not just the userinfo, must be redacted',
    input: 'https://fakeuser114:FAKE114URLPW@wiki.fakeorg114.corp/x?token=FAKE114TOKEN\n',
    leakTokens: ['FAKE114URLPW', 'FAKE114TOKEN'],
  },
  {
    id: 115, group: 'regression-h3b-review', expected: 'PASS',
    description:
      'Round 2 finding 4 / round 3 finding 3: a truncated PEM block (no matching END line) must not fail open, must redact a legacy encrypted key\'s ciphertext body past its Proc-Type/DEK-Info headers (not just the headers themselves), and must not swallow the blank line that separates the block from the next stanza',
    input:
      '-----BEGIN RSA PRIVATE KEY-----\nMIIB114FAKE115KEYBODYFAKE115\nMIIC115MORE115FAKE115BODY115\n' +
      '\n' +
      '-----BEGIN DSA PRIVATE KEY-----\n' + // FAKE115 -- synthetic fixture, see .gitleaks.toml
      'Proc-Type: 4,ENCRYPTED\n' +
      'DEK-Info: AES-128-CBC,FAKE115DEKINFOSALT1234\n' +
      '\n' +
      'MIIC115ENCFAKE115BODYONE\n' +
      'MIIC115ENCFAKE115BODYTWO\n' +
      '\n' +
      'hostname fw-FAKE115NEXTLINE\n',
    leakTokens: ['FAKE115KEYBODYFAKE115', 'MORE115FAKE115BODY115', 'ENCFAKE115BODYONE', 'ENCFAKE115BODYTWO'],
    mustSurvive: ['\nhostname'],
  },
  {
    id: 116, group: 'regression-h3b-review', expected: 'PASS',
    description: 'Round 2 finding 5: an LDAP DN component containing a space must be fully redacted',
    input: 'ldap-base-dn OU=Firewall Admins,DC=fakeacme116,DC=local\n',
    leakTokens: ['Firewall Admins', 'fakeacme116'],
    mustSurvive: ['ldap-base-dn'],
  },

  // ---------------------------------------------------------------------
  // Regression cases from the H3b PR #10 round-3 review (request-changes
  // findings 1-3). Each reproduces a leak the review found in commit
  // 66a306d that survived the round-2 fixes.
  // ---------------------------------------------------------------------
  {
    id: 117, group: 'regression-h3b-review', expected: 'PASS',
    description:
      'Round 3 finding 1: URL query-string secrets must be redacted even when the host is a bare IP, a dot-less hostname, or the URL has no path before the query',
    input:
      'https://192.0.2.10/api?key=FAKE117IPHOSTKEY\n' +
      'https://fw01/api?password=FAKE117BAREHOSTPW\n' +
      'https://portal.fakeacme117.net?token=FAKE117NOPATHTOKEN\n',
    leakTokens: ['FAKE117IPHOSTKEY', 'FAKE117BAREHOSTPW', 'FAKE117NOPATHTOKEN'],
  },
  {
    id: 118, group: 'regression-h3b-review', expected: 'PASS',
    description:
      'Round 3 finding 2: bare "passphrase" keyword (no hyphen) not covered by the "*-pass-phrase" alternation -- FortiOS and IOS both use the unhyphenated form',
    input:
      'set passphrase FAKE118FORTIPASSPHRASE\n' +
      'crypto key export rsa k pem passphrase FAKE118IOSPASSPHRASE\n',
    leakTokens: ['FAKE118FORTIPASSPHRASE', 'FAKE118IOSPASSPHRASE'],
  },

  // ---------------------------------------------------------------------
  // Regression case from the round-3 re-review (MEC-731, NEW-1): the
  // truncated-PEM fix landed in commit 2863395 required a bare "\n"
  // straight after "-----BEGIN X-----", so a CRLF line ending, trailing
  // whitespace before the line break, or a body glued onto the same line
  // as the BEGIN marker all skipped the match and shipped the key
  // verbatim.
  // ---------------------------------------------------------------------
  {
    id: 119, group: 'regression-h3b-review', expected: 'PASS',
    description:
      'Re-review NEW-1: a truncated PEM block must redact on CRLF line endings, a trailing space after "-----BEGIN X-----", and a body glued onto the same line as the BEGIN marker',
    input:
      '-----BEGIN RSA PRIVATE KEY-----\r\nFAKE119CRLFBODYONE\r\nFAKE119CRLFBODYTWO\r\n' +
      '-----BEGIN EC PRIVATE KEY----- \nFAKE119TRAILSPACEBODY\n' +
      'x -----BEGIN OPENSSH PRIVATE KEY-----FAKE119ONELINEBODY\n',
    leakTokens: ['FAKE119CRLFBODYONE', 'FAKE119CRLFBODYTWO', 'FAKE119TRAILSPACEBODY', 'FAKE119ONELINEBODY'],
  },
];

module.exports = { cases };
