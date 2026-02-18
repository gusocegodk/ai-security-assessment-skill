# Insecure Deserialization

CWE-502 (Deserialization of Untrusted Data), OWASP A08:2021

## Table of Contents
- [Detection Patterns](#detection-patterns)
- [Python](#python)
- [Java](#java)
- [PHP](#php)
- [Ruby](#ruby)
- [JavaScript / Node.js](#javascript--nodejs)
- [.NET / C#](#net--c)

## Detection Patterns

```bash
# Python: Pickle, PyYAML, shelve
grep -rn "pickle\.loads\|pickle\.load\|cPickle\|shelve\.open\|yaml\.load\|yaml\.unsafe_load\|marshal\.loads\|jsonpickle\.decode" --include="*.py"

# Java: ObjectInputStream, XMLDecoder, SnakeYAML
grep -rn "ObjectInputStream\|readObject\|XMLDecoder\|XStream\|fromXML\|SnakeYAML\|Yaml\.load\|SerializationUtils\.deserialize" --include="*.java" --include="*.kt"

# PHP: unserialize
grep -rn "unserialize\|__wakeup\|__destruct" --include="*.php"

# Ruby: Marshal.load, YAML.load
grep -rn "Marshal\.load\|Marshal\.restore\|YAML\.load\b" --include="*.rb"

# JavaScript: node-serialize, funcster
grep -rn "node-serialize\|serialize\|unserialize\|funcster\|cryo" --include="*.js" --include="*.ts"

# .NET: BinaryFormatter, SoapFormatter
grep -rn "BinaryFormatter\|SoapFormatter\|ObjectStateFormatter\|LosFormatter\|NetDataContractSerializer\|TypeNameHandling" --include="*.cs" --include="*.vb"

# General: Base64 data in cookies/headers (potential serialized objects)
grep -rn "base64.*decode\|b64decode\|atob\|Buffer\.from.*base64" --include="*.py" --include="*.js" --include="*.java" | grep -i "cookie\|session\|header\|request"
```

## Python

### Vulnerable Patterns

```python
# VULNERABLE: Pickle with untrusted data
import pickle
data = pickle.loads(request.data)  # RCE

# VULNERABLE: Pickle from file upload
with open(uploaded_file, 'rb') as f:
    obj = pickle.load(f)

# VULNERABLE: PyYAML unsafe load
import yaml
config = yaml.load(user_input)  # RCE in PyYAML < 6.0
config = yaml.unsafe_load(user_input)  # Always dangerous

# VULNERABLE: shelve with user-controlled path
import shelve
db = shelve.open(user_provided_path)

# SECURE: Use JSON or safe alternatives
import json
data = json.loads(request.data)

# SECURE: PyYAML safe loader
config = yaml.safe_load(user_input)
```

### Exploitation

```python
# Pickle RCE payload
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(Exploit())
```

## Java

### Vulnerable Patterns

```java
// VULNERABLE: Deserializing untrusted stream
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // RCE via gadget chains

// VULNERABLE: XStream without security
XStream xstream = new XStream();
Object obj = xstream.fromXML(userInput);

// VULNERABLE: XMLDecoder
XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(data));
Object obj = decoder.readObject();

// SECURE: Whitelist allowed classes
ObjectInputStream ois = new ObjectInputStream(input) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized class", desc.getName());
        }
        return super.resolveClass(desc);
    }
};

// SECURE: Use JSON (Jackson with safe defaults)
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);  // DANGEROUS
MyClass obj = mapper.readValue(json, MyClass.class);  // SAFE - explicit type
```

### Known Gadget Chains

Libraries that enable exploitation when on classpath:
- Apache Commons Collections
- Spring Framework
- Apache Commons Beanutils
- Groovy
- JBoss / Hibernate

## PHP

### Vulnerable Patterns

```php
// VULNERABLE: Unserialize user input
$data = unserialize($_COOKIE['data']);  // Object injection
$data = unserialize($_POST['payload']);

// VULNERABLE: Magic methods enable exploitation
class FileHandler {
    public $filename;
    function __destruct() {
        unlink($this->filename);  // Arbitrary file deletion
    }
}

// SECURE: Use JSON
$data = json_decode($_POST['payload'], true);

// SECURE: Restrict allowed classes (PHP 7+)
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);
```

## Ruby

### Vulnerable Patterns

```ruby
# VULNERABLE: Marshal.load with untrusted data
obj = Marshal.load(params[:data])  # RCE

# VULNERABLE: YAML.load with untrusted input
data = YAML.load(params[:config])  # RCE

# SECURE: Use JSON
data = JSON.parse(params[:data])

# SECURE: YAML safe_load
data = YAML.safe_load(params[:config])
```

## JavaScript / Node.js

### Vulnerable Patterns

```javascript
// VULNERABLE: node-serialize with user input
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.body.data);  // RCE via IIFE

// VULNERABLE: cryo deserialization
const cryo = require('cryo');
const obj = cryo.parse(userData);

// VULNERABLE: funcster
const funcster = require('funcster');
const obj = funcster.deepDeserialize(userData);

// SECURE: JSON.parse (no code execution)
const data = JSON.parse(req.body.data);
```

## .NET / C#

### Vulnerable Patterns

```csharp
// VULNERABLE: BinaryFormatter
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // RCE

// VULNERABLE: TypeNameHandling in JSON.NET
JsonConvert.DeserializeObject<object>(input, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // RCE
});

// SECURE: Explicit type, no TypeNameHandling
var obj = JsonConvert.DeserializeObject<MyClass>(input);

// SECURE: Use System.Text.Json (no polymorphic deserialization by default)
var obj = System.Text.Json.JsonSerializer.Deserialize<MyClass>(input);
```

## Deserialization Checklist

- [ ] No native deserialization of untrusted data (pickle, ObjectInputStream, unserialize, Marshal)
- [ ] JSON used instead of native serialization for data exchange
- [ ] YAML uses safe_load, not load/unsafe_load
- [ ] Java classpath checked for known gadget chain libraries
- [ ] .NET avoids BinaryFormatter and TypeNameHandling.All
- [ ] Input integrity verified (HMAC/signature) before deserialization if native format required
- [ ] Class whitelisting enforced where native deserialization is unavoidable
