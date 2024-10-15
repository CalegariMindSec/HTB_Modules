# Injection Attacks

**Module Link**: https://academy.hackthebox.com/module/details/204

### Module Summary

There are many injection vulnerabilities, the most famous ones being  SQL injection, cross-site scripting, and command injection. While these  are certainly the most common in real-world web applications, other  not-very-known injection vulnerabilities exist. Since these injection  vulnerabilities are generally less common and less known, developers are more likely not to be aware of them and, therefore, be oblivious to the mitigations against them. If we can find a website that utilizes XPath, LDAP, or PDF generation libraries, testing it against these attacks  might allow us to move forward in our engagements.

In more detail, this module covers the following:

- `XPath Injection`:
  - Introduction to XPath Syntax
  - Exploitation of XPath injection to bypass authentication
  - Exploitation of XPath injection to exfiltrate data
  - Exploitation of blind and time-based XPath injections to exfiltrate data
- `LDAP Injection`:
  - Introduction to LDAP syntax
  - Exploitation of LDAP injection to bypass authentication
  - Exploitation of LDAP injection to exfiltrate data
- `HTML Injection in PDF Generation Libraries`:
  - Introduction to HTML injection in PDF generation libraries
  - Exploitation of PDF generation vulnerabilities leading to Server-Side Request Forgery (SSRF)
  - Exploitation of PDF generation vulnerabilities leading to Local File Inclusion (LFI)

#### XPath Injection

[XML Path Language (XPath)](https://www.w3.org/TR/xpath-3/) is a query language for [Extensible Markup Language (XML)](https://datatracker.ietf.org/doc/html/rfc5364) data, similar to how SQL is a query language for databases. As such,  XPath is used to query data from XML documents. Web applications that  need to retrieve data stored in an XML format thus rely on XPath to  retrieve the required data. [XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection) vulnerabilities arise when user input is inserted into XPath queries  without proper sanitization. Like SQLi vulnerabilities, XPath injection  jeopardizes the entire data as successfully exploiting XPath injection  allows an attacker to retrieve the entire XML document.

**References**:

- https://www.netspi.com/blog/technical-blog/web-application-pentesting/exploiting-xpath-injection-weaknesses/
- https://book.hacktricks.xyz/pentesting-web/xpath-injection
- https://bugbug.io/blog/testing-frameworks/the-ultimate-xpath-cheat-sheet/
- https://owasp.org/www-community/attacks/Blind_XPath_Injection
- https://www.wallarm.com/what/xpath-injection-attack
- https://github.com/orf/xcat

#### LDAP Injection

[Lightweight Directory Access Protocol (LDAP)](https://www.rfc-editor.org/rfc/rfc4511) is a protocol used to access directory servers such as `Active Directory` (`AD`). Web applications often use LDAP queries to enable integration with AD  services. For instance, LDAP can enable AD users to authenticate to the  web application. LDAP injection vulnerabilities arise when user input is inserted into search filters without proper sanitization. This can lead to authentication bypasses if LDAP authentication is incorrectly  implemented. Additionally, LDAP injection can lead to loss of data.

#### HTML Injection in PDF Generators

[Portable Document Format (PDF)](https://www.pdfa.org/resource/iso-32000-pdf/) files are commonly used for the distribution of documents. As such,  many web applications implement functionality to convert data to a PDF  format with the help of PDF generation libraries. These libraries read  HTML code as input and generate a PDF file from it. This allows the web  application to apply custom styles and formats to the generated PDF file by applying stylesheets to the input HTML code. Often, user input is  directly included in these generated PDF files. If the user input is not sanitized correctly, it is possible to inject HTML code into the input  of PDF generation libraries, which can lead to multiple vulnerabilities, including `Server-Side Request Forgery` (`SSRF`) and `Local File Inclusion` (`LFI`).