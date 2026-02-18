# Server-Side Template Injection (SSTI)

CWE-1336 (Template Injection), OWASP A03:2021

## Table of Contents
- [Detection Patterns](#detection-patterns)
- [Jinja2 / Python](#jinja2--python)
- [ERB / Ruby](#erb--ruby)
- [Velocity / FreeMarker / Java](#velocity--freemarker--java)
- [Twig / PHP](#twig--php)
- [Pug / EJS / JavaScript](#pug--ejs--javascript)

## Detection Patterns

```bash
# Python: User input rendered directly in templates
grep -rn "render_template_string\|Template(\|from_string\|Environment(" --include="*.py"

# Python: Format strings used as templates
grep -rn "\.format(.*request\|\.format(.*user\|%.*request" --include="*.py"

# Ruby: ERB template rendering with user input
grep -rn "ERB\.new\|render.*inline\|render.*text.*params" --include="*.rb"

# Java: Velocity/FreeMarker template with user input
grep -rn "VelocityEngine\|Velocity\.evaluate\|FreeMarkerTemplateUtils\|Configuration.*setDirectoryForTemplateLoading\|new Template(" --include="*.java" --include="*.kt"

# PHP: Twig/Blade user input in templates
grep -rn "Twig_Environment\|createTemplate\|renderString\|Environment.*render" --include="*.php"

# JavaScript: Pug/EJS with user input
grep -rn "pug\.render\|pug\.compile\|ejs\.render\|nunjucks\.renderString\|Handlebars\.compile" --include="*.js" --include="*.ts"

# General: User input flowing into template construction
grep -rn "template.*req\.\|template.*request\.\|template.*params\|template.*user_input" --include="*.py" --include="*.js" --include="*.java" --include="*.rb" --include="*.php"
```

## Jinja2 / Python

### Vulnerable Patterns

```python
# VULNERABLE: User input rendered as template
from flask import request
from jinja2 import Template

@app.route('/greet')
def greet():
    template = Template(f"Hello {request.args.get('name')}")  # SSTI
    return template.render()

# VULNERABLE: render_template_string with user input
@app.route('/page')
def page():
    return render_template_string(request.args.get('template'))  # RCE

# VULNERABLE: Format string used to build template
template_str = "Welcome, %s" % user_input
return render_template_string(template_str)

# SECURE: Pass user input as template variable
@app.route('/greet')
def greet():
    return render_template('greet.html', name=request.args.get('name'))
```

### Exploitation

```
# Detection payload
{{7*7}}  →  49

# RCE payloads (Jinja2)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

## ERB / Ruby

### Vulnerable Patterns

```ruby
# VULNERABLE: User input in ERB template
template = ERB.new(params[:template])
result = template.result(binding)

# VULNERABLE: Inline rendering with user data
render inline: params[:page]

# SECURE: Use template files with variables
render template: 'page', locals: { name: params[:name] }
```

### Exploitation

```
# Detection
<%= 7*7 %>  →  49

# RCE
<%= system('id') %>
<%= `id` %>
```

## Velocity / FreeMarker / Java

### Vulnerable Patterns

```java
// VULNERABLE: User input as Velocity template
VelocityEngine ve = new VelocityEngine();
StringWriter writer = new StringWriter();
Velocity.evaluate(context, writer, "tag", userInput);  // SSTI

// VULNERABLE: FreeMarker with user-controlled template
Configuration cfg = new Configuration();
Template template = new Template("name", new StringReader(userInput), cfg);  // SSTI
template.process(dataModel, out);

// SECURE: Load templates from fixed location, pass data as model
Template template = cfg.getTemplate("page.ftl");
template.process(dataModel, out);
```

### Exploitation

```
# FreeMarker RCE
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity RCE
#set($rt = $class.forName("java.lang.Runtime").getRuntime())
$rt.exec("id")
```

## Twig / PHP

### Vulnerable Patterns

```php
// VULNERABLE: User input as Twig template string
$twig = new \Twig\Environment($loader);
echo $twig->createTemplate($userInput)->render([]);  // SSTI

// VULNERABLE: String interpolation in template
$template = "Hello " . $_GET['name'];
echo $twig->createTemplate($template)->render([]);

// SECURE: Use template file with variables
echo $twig->render('hello.html.twig', ['name' => $name]);
```

### Exploitation

```
# Twig detection
{{7*7}}  →  49

# Twig RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

## Pug / EJS / JavaScript

### Vulnerable Patterns

```javascript
// VULNERABLE: User input compiled as Pug template
const pug = require('pug');
const html = pug.render(req.query.template);  // SSTI

// VULNERABLE: EJS with user-controlled template
const ejs = require('ejs');
ejs.render(req.body.template, data);  // SSTI

// VULNERABLE: Nunjucks string rendering
nunjucks.renderString(req.body.content, data);

// SECURE: Render from files, pass data as context
const html = pug.renderFile('views/page.pug', { name: req.query.name });
ejs.renderFile('views/page.ejs', data, callback);
```

## SSTI Checklist

- [ ] No user input passed to template constructors or compile functions
- [ ] Templates loaded from files, not constructed from strings
- [ ] User input only passed as template variables/context
- [ ] Template engine sandbox enabled where available (Jinja2 SandboxedEnvironment)
- [ ] Template rendering errors don't leak engine details
- [ ] Input validation rejects template syntax characters where possible
