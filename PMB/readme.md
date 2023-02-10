# PMB

To search these vulnerabilities, I use the docker `https://github.com/jperon/pmb/` and I simply change the URL in the Dockerfile to match the latest version (`7.4.6`).

## PMB 7.4.6 - Reflected XSS - CVE-XXXX

- Affected version : 7.4.6
- Vulnerability Type : XSS Reflected (Unauthenticated)
- CWE-79

### Description

The web app incorrectly neutralizes user-controllable input before it is placed in output. This allows an attacker to make a Reflected XSS on `/pmb/admin/convert/export_z3950_new.php` and `/pmb/admin/convert/export_z3950.php` endpoint via the same `query` parameter.

### Exploitation

1. Go to `http://website.com/pmb/admin/convert/export_z3950_new.php` or `http://website.com/pmb/admin/convert/export_z3950.php`
2. Set parameter `command` to `search` and `query` to a JavaScript payload that end by `=or` (needed to bypass filter).
3. Trigger your Reflected XSS: `http://website.com/pmb/admin/convert/export_z3950.php?command=search&query=%3Cscript%3Ealert(document.domain);%3C/script%3E=or`

### PoC

Here is an example with an alert box :

![Reflected XSS - Exploit](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_ReflectedXSS/Exploit.png)

### Remediation

Sanitize the `query` parameter with `htlmentities` function.

![Reflected XSS - Remediation](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_ReflectedXSS/Remediation.png)

## PMB 7.4.6 - SQL Injection - CVE-XXXX

- Affected version : 7.4.6
- Vulnerability Type : SQL Injection (Unauthenticated)
- CWE-89

### Description

The web app incorrectly neutralizes user-controllable input before it is placed in an SQL Query. This allows an attacker to make a SQL Injection on `/pmb/edit.php` endpoint via the `user` parameter. This SQL Injection can lead to an account takeover if the SESSID cookie of the admin account is extracted.

### Exploitation

1. Go to `http://website.com/pmb/edit.php`
2. Set parameter `action=whatever&dest=TABLEAUCSV` and `user` to your SQL payload `%27%20OR%201=1;%23&password=password`
3. Trigger your SQL Injection: `http://website.com/pmb/edit.php?action=whatever&dest=TABLEAUCSV&user=%27%20OR%201=1;%23&password=password`

### PoC

Here is an example of a simple bypass :

![SQL Injection -Exploit](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_SQLInjection/Exploit.png)

### Remediation

Use prepared SQL query.

![SQL Injection - Remediation](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_SQLInjection/Remediation.png)

## PMB 7.4.6 - Unrestricted File Upload - CVE-XXXX

- Affected version : 7.4.6
- Vulnerability Type : Unrestricted File Upload (Authenticated)
- CWE-434

### Description

The web app allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment or overwrite configuration files. An attacker can host malicious files (ending with `#data-section` to make simple the exploitation of the RCE, see the next section).

### Exploitation

1. Go to `http://website.com/pmb/camera_upload.php`
2. Send a POST request with the parameters `upload_filename` that is the name of the file you want to upload and `imgBase64` the file content to upload.
3. To bypass the filter in place (image checking), your file need to starts with `GIF89a`.

### PoC

Here is an example of a file upload :

![Unrestricted File Upload - Exploit](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_UnrestrictedFileUpload/Exploit.png)

### Remediation

Check the extension of each file. DO NOT trust user input, and generate a random name for each file uploaded.

![Unrestricted File Upload - Remediation](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_UnrestrictedFileUpload/Remediation.png)

## PMB 7.4.6 - Remote Code Execution - CVE-XXXX

- Affected version : 7.4.6
- Vulnerability Type : XSS Reflected (Authenticated)
- CWE-94

### Description

The web app incorrectly neutralizes user-controllable input before it is placed in `exec` function. This allows an attacker to execute a shell command through the parameter `decompress`.

### Exploitation

1. Go to `http://website.com/pmb/admin/sauvegarde/restaure_act.php`
2. `filename` parameter need to point to a file that ends with `#data-section`. The web app use `fopen` so it's possible to pass a URL to this parameter.
3. `compress` parameter need to be `1`.
4. `decompress_type` need to be `external`.
5. `decompress` it's your shell command. That can the `id` command.

### PoC

Here is an example of a blind RCE :

![Remote Code Execution - Exploit](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_RemoteCodeExecution/Exploit.png)

### Remediation

Never trust user input and if possible do not decompress file with any external command that are controlled by user input.

![Remote Code Execution - Remediation](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_RemoteCodeExecution/Remediation.png)

## PMB 7.4.6 - Open Redirect - CVE-XXXX

- Affected version : 7.4.6
- Vulnerability Type : Open Redirect (Unauthenticated)
- CWE-601

### Description

The web app accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.

### Exploitation

1. Go to `http://website.com/pmb/opac_css/pmb.php`
2. Set `from` parameter to empty.
3. `url` parameter to the URL you want to redirect to.
4. `hash` parameter to the md5 of your `url` parameter.

### PoC

Here is an example of an Open Redirect :

![Open Redirect - Exploit](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_OpenRedirect/Exploit.png)

### Remediation

Check the domain with a whitelist.

![Open Redirect - Remediation](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_OpenRedirect/Remediation.png)

## PMB 7.4.6 - SQL Injection - CVE-XXXX

- Affected version : 7.4.6
- Vulnerability Type : SQL Injection (Unauthenticated)
- CWE-89

### Description

The web app incorrectly neutralizes user-controllable input before it is placed in an SQL Query. This allows an attacker to make a SQL Injection on `/pmb/opac_css/export.php` endpoint via the `notice_id` parameter. This SQL Injection can lead to an account takeover if the SESSID cookie of the admin account can be extracted.

### Exploitation

1. Go to `http://website.com/pmb/opac_css/export.php`
2. Set `action` parameter to `export`.
3. `notice_id` parameter need to start by `es` after that you can add your SQL payload.

### PoC

Here is an example of an SQL Injection :

![SQL Injection - Exploit](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_OpacCSS_SQLInjection/Exploit.png)

### Remediation

Use prepared SQL Query or add simple quote in this specific SQL query.

![SQL Injection - Remediation](https://raw.githubusercontent.com/AetherBlack/CVE/master/PMB/img/CVE-XXXX_OpacCSS_SQLInjection/Remediation.png)
