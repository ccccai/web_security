title: web安全知多少
speaker: 蔡诗茵
plugins:
    - echarts
css:
    - theme.css

<slide class="bg-trans-dark aligncenter move-bg" image="./images/bg.jpg .dark">

# web安全知多少 {.text-landing.text-shadow}

By 蔡诗茵 {.text-intro}


<slide class="bg-black-blue aligncenter" :class="size-80" image="./images/heike.jpg .dark">

## 说到web安全，大家会马上脑补到什么？

:::note
接触过这方面知识的小伙伴，初识这俩字，可能立马就浮现的是一个带着宽大帽子看不见脸的人坐在满是代码的屏幕前的黑客形象。

我们可能在书本中抑或是平时工作中，甚至是网上冲浪时，有机会看见诸如SQL注入，缓冲区溢出，DDoS，CC攻击等此类的词，知道这是和网络安全相关，但是好像和前端没什么关系，久而久之会觉得这些都是后端同学应该考虑的事情。
:::

<slide class="bg-apple aligncenter">

> 什么是web安全？
> {.text-quote}

> 会造成什么后果？
> {.text-quote}

> 如何防范？
> {.text-quote}

:::note
那什么事web安全呢？以及这些安全攻击会造成什么样的一个后果，我们又该如何防范，这是我们今天分享的重点。

首先什么是web安全？很简单，将安全问题按照发生的区域来分类，发生在浏览器、Web页面中的安全问题就是Web安全问题。

Web安全问题可轻可重，最直观的影响是会造成个人信息或者是企业信息泄漏，造成人身财产损失。

下面介绍一下几种常见的攻击的类型。
:::

<slide class="bg-trans-light" :class="size-80 aligncenter" image="./images/bg2.jpg .dark">

## 常见web安全攻击类型
---

* 1 XSS(Cross-Site Scripting，跨站脚本攻击){.animated.fadeInUp.text-nomal}
* 2 CSRF(Cross-Site Request Forgery，跨站请求伪造){.animated.fadeInUp.delay-400.text-nomal}
* 3 点击劫持{.animated.fadeInUp.delay-800.text-nomal}
* 4 URL跳转漏洞{.animated.fadeInUp.delay-1200.text-nomal}
* 5 SQL注入{.animated.fadeInUp.delay-1600.text-nomal}
* 6 上传问题{.animated.fadeInUp.delay-2s.text-nomal}

:::note
以下这六种就是我们平时比较常见的web安全攻击类型，其中除了XSS和CSRF是因为缩写不太容易一眼就明白之外，其他的看名字就能略微猜个一二啦。一个个介绍一下。
:::

<slide class="no-padding bg-trans-light" :class="size-70" image="./images/bg2.jpg .light">

## XSS

---

:::shadowbox

## XSS的全称是 Cross-Site Scripting

跨站脚本攻击。

---

## 是指通过利用网页开发时留下的漏洞，通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序。

通俗地说就是页面被注入了恶意的代码，攻击者让用户在访问的网页里运行自己写的攻击代码，以达到窃取用户敏感信息等的目的。

---

## 根据攻击的来源细分

可以大致分为**DOM型、反射型、存储型**三种。

:::

:::note
首先是XSS，XSS全程是跨站脚本攻击，因为缩写和 CSS重叠，所以只能叫 XSS。跨站脚本攻击是指通过存在安全漏洞的Web网站注册用户的浏览器内运行非法的HTML标签或JavaScript进行的一种攻击。简单滴说就是页面被注入了恶意的代码，当用户浏览该页之时，恶意代码被执行从而窃取用户敏感信息。

XSS 的攻击方式千变万化，但还是可以大致细分为几种类型。
:::

<slide class="no-padding bg-white" :class="size-80">

!![](/images/page5.png .aligncenter)

:::note
第一种是DOM型攻击，顾名思义就是通过修改页面的DOM节点形成的XSS，这个攻击是不经过后端的。下面给大家演示一下，这是一个模拟XSS攻击的通关小游戏网站(https://xss-game.appspot.com/level1)。

看下这个页面，点击相应的tab会去切换图片，可以看一下dom结构，可以看到是截取了地址上从#开始的字符串拼接到这个图片链接上的，那我们可以改造一下链接。给他输入一段可以执行的代码' onerror='alert("xss")'，点击确定。看，是不是就执行成功了，这是利用了image这个dom的onerror属性哈，这个图片是一个加载不出来的图片，那么就会触发onerr方法，从而就会去执行这个alert的代码。如果这里注入的是一段恶意代码，那就牙白了，攻击者的目的就达到了。

第二种就是反射型XSS，也叫做非持久性XSS，将用户输入的数据反射给浏览器，经过后端，不经过数据库。通俗来说就是A给B发送一个恶意构造的URL，B点击URL后跳转到具有漏洞的HTML页面，网站服务端将恶意代码从 URL 中取出，拼接在 HTML 中返回给浏览器。B浏览器接收到响应后解析执行，混在其中的恶意代码也被执行。恶意代码窃取用户数据并发送到攻击者的网站，或者冒充用户的行为，调用目标网站接口执行攻击者指定的操作。

这个也给大家演示一遍，这是一个搜索输入框，如果在这里输入关键字的话，就会拼接成成一个链接，然后跳转，那当我们在这里输入的是一段可执行的代码\<script\>alert('xss')\<\/script\>的话，可以看见，这就很容易被攻击了。

最后一种是存储型XSS又被称为持久性XSS，代码储存在数据库中，经过后端，经过数据库。它是最危险的一种跨站脚本，相比反射型XSS和DOM型XSS具有更高的隐蔽性，所以危害更大，它不需要用户手动触发。
当攻击者提交一段XSS代码后，被服务器端接收并存储，当所有浏览者访问某个页面时都会被XSS，其中最典型的例子就是留言板。

:::

<slide class="bg-trans-light" :class="size-80 frame" image="./images/bg2.jpg .light">

## 如何防范? {.aligncenter}

\* \* \* \* {.text-symbols}


- 输入侧过滤；{.text-nomal}
- 防止 HTML 中出现注入；{.text-nomal}
- 防止 JavaScript 执行时，执行恶意代码；{.text-nomal}

:::note
通过前面的介绍可以知道，xss攻击最主要的核心就是两个方面1、攻击者提交恶意代码2、浏览器执行恶意代码。所以对xss攻击的防范，可以从这两方面着手。
:::

<slide class="bg-trans-light" :class="size-85" image="./images/bg2.jpg .dark">

## 具体实现

:::column{.column-box}

### 输入侧过滤

- 1、转义字符{.text-nomal}
- 2、输入内容长度控制{.text-nomal}
- 3、验证码{.text-nomal}
---

### 防止 HTML 中出现注入

- 1、纯前端渲染{.text-nomal}
- 2、转义 HTML{.text-nomal}
- 3、避免拼接HTML或者使用内联事件{.text-nomal}

---

### 防止 JavaScript 执行时，执行恶意代码

- 1、开启CSP网页安全政策（Content Security Policy）{.text-nomal}
- 2、使用HTTPS、使用HttpOnly的cookie。{.text-nomal}
- 3、不混用GET与POST请求，严格遵守规范，不要将一些危险的提交使用JSONP完成。{.text-nomal}

:::

:::note
刚刚才讲过的攻击的其中一个核心就是来自于攻击者提交的恶意代码，以这个为出发点，那我们是不是可以去把输入先在前端过滤一遍，对输入内容做校验的同时，可以限制输入的内容是否为可执行代码，最简单的可以讲输入的内容进行转义，比如说我们前面讲到的，在搜索输入框输入了一段可执行代码后，但是在执行后续逻辑之前，对该内容先进行一个转义，将那些尖括号、单双引号之类进行转义，是不是就避免了它被执行。

当然这种方式其实是远远不够的，一旦攻击者绕过前端过滤，直接构造请求，就可以提交恶意代码了。而且对内容进行转义，还要担心乱码问题。

这个时候再回想一下另外一个核心是什么，浏览器执行恶意代码。既然输入过滤并非完全可靠，我们就要通过“防止浏览器执行恶意代码”来防范 XSS。

讲一下这个CSP，内容安全策略 (CSP) 是一个额外的安全层，用于检测并削弱某些特定类型的攻击，包括跨站脚本 (XSS) 和数据注入攻击等。通过在HTTP头部中设置Content-Security-Policy，或者是通过 html meta 标签使用，就可以配置该策略。配置了csp防护后，网站不允许内联脚本执行;禁止加载外域代码;禁止外域提交;

使用HttpOnly的cookie无法通过JS获取，也就降低了XSS攻击时用户凭据隐私泄漏的风险。

第三点就是不要混用get、post请求，一些重要的操作不要通过jsonp去完成，假如提供jsonp的服务存在页面注入漏洞，即它返回的javascript的内容被人控制的。那么结果是什么？所有调用这个jsonp的网站都会存在漏洞。

:::

<slide class="fullscreen">

:::card


![](/images/example2.jpg)

---

## 商城案例

---

确认订单页被集团的安全部门扫出XSS漏洞，具体页面是订单详情里面查看增值税发票详情的页面。{.text-nomal}

页面使用了html方法赋值而非text方法，而且没有做XSS过滤，导致了存在有xss漏洞。{.text-nomal}

:::

:::note
讲一下现在最接近的商城经历过的xss漏洞。
:::

<slide class="bg-black" :class="size-60" video="./working.mp4 poster='./images/working.jpg' .dark">

# 课后小作业 

#### 以下是几个 XSS 攻击小游戏，开发者在网站上故意留下了一些常见的 XSS 漏洞。玩家在网页上提交相应的输入，完成 XSS 攻击即可通关。

---


* [XSS挑战](https://xss-game.appspot.com/){.text-nomal}

* [进阶游戏](http://prompt.ml/0){.text-nomal}


:::note
这里给大家布置一个小作业啦，我收集到两个网页小游戏，有助于大家进一步理解xss的概念，大家课后闲暇之余可以去通关看看。
:::

<slide class="no-padding bg-gray" :class="size-70" image="./images/mGFHA_0TWnA.jpg .dark">

## CSRF

---

:::shadowbox{.bg-trans-drak}

## CSRF的全称是 Cross Site Request Forgery{.text-nomal}

跨站请求伪造。{.text-nomal}

---

## 是指攻击者诱导受害者进入第三方网站，在第三方网站中，向被攻击网站发送跨站请求。{.text-nomal}

利用受害者在被攻击网站已经获取的注册凭证，绕过后台的用户验证，达到冒充用户对被攻击的网站执行某项操作的目的。{.text-nomal}

:::

:::note
接下来介绍一下另外一个相比xss来说名气没有那么大，但是破坏力丝毫不减的攻击，csrf。csrf也叫跨站请求伪造，它是指攻击者诱导用户进入钓鱼网站，在钓鱼网站里获取被攻击网站已经存在的注册凭证，然后可以披着这个马甲去向我们被攻击的网站执行一些操作。

举个例子吧，某天A同学收到了一个未知邮件，并且点击了邮件里甩出的链接。点击链接跳转到了一个空白页面，什么都没有发生。殊不知这个链接就是个钓鱼链接，这个空白页面只要被打开，就会向邮箱发送一个post请求，这个请求是一段过滤规则，规则内容就是将所有邮件转发到另一个邮箱下。就这样，攻击者就能拿到别人发给A的所有邮件内容，包括一些验证码啊，或者公司内部资料等等等的一些敏感信息就都泄漏了。这就是csrf攻击。

:::

<slide class="no-padding bg-gray" :class="size-82" image="./images/mGFHA_0TWnA.jpg .dark">


:::shadowbox{.bg-trans-drak .page-two}
## 几种常见的CSRF攻击类型{.text-nomal}

1、 **GET类型的CSRF：**`<img src="http://bank.example/withdraw?amount=10000&for=hacker" >`在受害者访问含有这个img的页面后，浏览器会自动向http://bank.example/withdraw?account=xiaoming&amount=10000&for=hacker发出一次HTTP请求。bank.example就会收到包含受害者登录信息的一次跨域请求。

2、**POST类型的CSRF**：通常使用的是一个自动提交的表单;
```
 <form action="http://bank.example/withdraw" method=POST>
    <input type="hidden" name="amount" value="10000" />
</form>
<script> document.forms[0].submit(); </script> 
```
3、 **链接类型的CSRF**：`<a href="http://test.com/csrf/withdraw.php?amount=1000&for=hacker" taget="_blank">重磅消息！！<a/>`这种需要用户点击链接才会触发。这种类型通常是在论坛中发布的图片中嵌入恶意链接，或者以广告的形式诱导用户中招，攻击者通常会以比较夸张的词语诱骗用户点击。

:::

:::note
get类型可以理解为一个简单的http请求，比如这段html代码，一个img标签，如果用户访问了含有这段代码的钓鱼网站，那么这个网站就会向这个地址发起get请求，也就意味着这个网址就会收到包含受害者登录信息（cookie)的一次跨域请求。

post类型也是http请求，但通常下比get请求严格一点，比如空白页的代码可以是一个自动提交的表单。可以理解为向被攻击网站提交了一个表单请求，通过这个请求被攻击者就能冒充受害者提交操作。
:::

<slide class="bg-trans-drak" :class=" aligncenter size-50" image="./images/mGFHA_0TWnA.jpg .dark">

## 特点

----

* CSRF通常发生在第三方域名；{.text-nomal}
* CSRF攻击者不能获取到Cookie等信息，只是使用。{.text-nomal}

:::note
通过上面的介绍，可以总结得出csrf最主要的特点就是，一个这个攻击通常是发生在第三方域名的，二一个是攻击者只能冒用被攻击者，而不能真的获取到cookie，只能披着个马甲去干坏事。

:::

<slide class="bg-gray" :class="size-80 frame" image="./images/mGFHA_0TWnA.jpg .dark">

## 如何防范? {alignenter}

---

- 阻止不明外域的访问{.text-nomal}
- 提交时要求附加本域才能获取的信息{.text-nomal}


:::note
由这两个特点出发，就可以对症下药了，防范csrf攻击可以从阻止不明外域访问和增加本域信息限制这两个方面入手。
:::

<slide class="bg-trans-drak" image="./images/mGFHA_0TWnA.jpg .dark">

## 具体实现

:::column

#### 1 .同源检测

- 在HTTP协议中，每一个异步请求都会携带两个Header，origin和referer，用于标记来源域名；
- 这两个Header在浏览器发起请求时，大多数情况会自动带上，并且不能由前端自定义内容。 服务器可以通过解析这两个Header中的域名，确定请求的来源域。

---

#### 2 .SameSite Cookie

- 浏览器针对cookie提供了SameSite的属性，该属性表示Cookie不随着跨域请求发送。该提案由google提出，目前还在试行阶段，存在兼容性问题。

---

#### 3 .CSRF Token

- 要求所有的用户请求都携带一个CSRF攻击者无法获取到的Token。服务器通过校验请求是否携带正确的Token，来把正常的请求和攻击的请求区分开。

---

#### 4 .增加二次验证

- 针对一些有危险性的请求操作（比如删除账号，提现转账）我们可以增加用户的二次，比如发起手机或者邮箱验证码检验，进而降低CSRF打来的危害。

:::


:::note
我这里简单的介绍下，具体如何实现这里就不详细展开了，有感兴趣的同学私下可以研究下。

同源检测就是服务器可通过 request headers 里 origin 和 referer 两个字段确定请求的来源域。服务器可以通过判断这俩值来判断是否是黑客攻击。


Samesite Cookie是Chrome 51版本之后，浏览器的Cookie 新增加了一个 SameSite 属性限制第三方 Cookie，用来防止 CSRF 攻击和用户追踪。目前兼容性不太好。

而 CSRF 攻击之所以能够成功，是因为服务器误把攻击者发送的请求当成了用户自己的请求。那么我们可以要求所有的用户请求都携带一个 CSRF 攻击者无法获取到的 Token。服务器通过校验请求是否携带正确的 Token，来把正常的请求和攻击的请求区分开，也可以防范 CSRF 的攻击。

利用 CSRF 攻击不能获取到用户 Cookie 的特点，我们可以要求请求携带一个 Cookie 中的值。
或者是增加一步获取验证码，多增加一个字段供后端校验。
这样一来第三方只能携带上 cookie 但是带不上增加的二次验证值，也就预防了 csrf 攻击。

:::

<slide class="aligncenter">
## 点击劫持 (iframe 嵌套)

--- 

点击劫持是一种视觉欺骗的攻击手段。{.text-nomal}

攻击者将需要攻击的网站通过 iframe 嵌套的方式嵌入自己的网页中，并将 iframe 设置为透明，在页面中透出一个按钮诱导用户点击。{.text-nomal}

:::note
点击劫持其实就是通过覆盖不可见的页面，诱导用户点击而造成的攻击行为。稍微高级一点的伪装可以怎么样呢，就是做成一个游戏界面，让你在页面上狂点，而实际上呢，则会触发一些攻击事件，比如打开摄像头、发送邮件之类的。
:::

<slide class="less-padding" :class=" size-95" >
### 点击劫持
`————障眼法`

:::gallery-overlay

![](/images/example4.jpg)

## 实际上的界面

---

![](/images/example3.png)

## 你看到的界面

:::

:::note
这里有一个简单的小例子，这个页面是攻击者构造的一个恶意链接用来诱导用户访问，如果用户不小心打开了这个页面，看到的是一个经过伪装的正常页面，攻击者在钓鱼网站的上方覆盖了一层透明的iframe，被攻击者以为点击的是这个被装饰得按钮，实际上点击的是钓鱼网站。
:::

<slide class="no-padding" :class=" size-80 frame">

## 如何防范? 

---

- 防止其他页面通过iframe引用{.text-nomal}

```
//自己网站添加
if (top.location != self.location) {
  top.location.href = 'http://www.baidu.com'; //若被其他网站引用则强制跳转
}
```
---

- 添加HTTP响应头：X-FRAME-OPTIONS{.text-nomal}

可以指示浏览器是否应该加载一个iframe中的页面。如果服务器响应头信息中没有 X-Frame-Options，则该网站存在点击劫持攻击风险。`setHeader('X-Frame-Options', 'DENY')`


:::note
那么怎么去防止点击劫持的，第一种方法可以通过js代码去防御，在自己的网站添加不能被其他网站内嵌的逻辑。第二种方法就是设置HTTP响应头X-Frame-Options，可以指示浏览器是否应该加载一个iframe中的页面。
:::

<slide class="bg-apple" :class="size-80" image="./images/OHc-XS8ZtG8.jpg .dark">

## URL跳转漏洞

---

其原理是黑客构建恶意链接(链接需要进行伪装,尽可能迷惑),发在QQ群或者是浏览量多的贴吧/论坛中。 安全意识低的用户点击后,经过服务器或者浏览器解析后，跳到恶意的网站中。{.text-nomal}

---

经常的做法是熟悉的链接后面加上一个恶意的网址，这样才迷惑用户。`http://gate.baidu.com/index?act=go&url=http://t.cn/RVTatrd` {.text-nomal}

:::note
第四种常见的web安全攻击是URL跳转漏洞，攻击者抓住了部分用户不会仔细查看链接的小心思，在用户访问的正确链接后面拼接恶意网站的链接，当用户点击了之后，经过解析携带者cookie等信息会跳转至钓鱼页面，攻击者就能通过伪装成受害者来访问目标网站来进行一些骚操作了。
:::

<slide class="bg-apple" :class="size-80 frame" image="./images/OHc-XS8ZtG8.jpg .dark">

## 如何防范? {.aligncenter}

\* \* \* \* {.text-symbols}

- referer的限制{.text-nomal}

如果确定传递URL参数进入的来源，我们可以通过该方式实现安全限制，保证该URL的有效性，避免恶意用户自己生成跳转链接

- 加入有效性验证Token{.text-nomal}

在生成的链接里加入用户不可控的Token对生成的链接进行校验

:::note
那怎么去防范呢，一个就是通过referer 两个字段确定请求的来源域，这个在刚刚讲csrf攻击的时候也有说到。
二一个就是把用户校验凭证拼在链接上，我们现在的商场跳转登录页就是这么做的，这个凭证是唯一并且有时效性的，钓鱼网站是获取不到的。
:::

<slide class="bg-trans-dark" >
## SQL 注入

---

简单的说就是利用潜在的数据库漏洞访问或修改数据。{.text-nomal}

:::note
第五个常见问题就是SQL注入，这个相信蛮多同学都不陌生了。sql指的就是数据库，sql注入就是指在输入的字符串中注入 SQL 语句，如果应用相信用户的输入而对输入的字符串没进行任何的过滤处理，那么这些注入进去的 SQL 语句就会被数据库误认为是正常的 SQL 语句而被执行。
:::

<slide class="bg-trans-dark no-padding">

## 举个栗子

---

:::shadowbox

用户填写了用户名和密码，点击登录发送了一个请求。

---


后端接收到请求并解析参数，将其拼装成一个 SQL 语句执行，形如 `select * from user where username = '${data.username}' and pwd='${data.pwd}'`，并返回登录成功。

---


结果小王在填写密码的时候写上了 `1' or '1'='1`，结果后端一拼接 SQL 语句就变成了 `select * from user where username = 'xiaowang' and pwd = '1' or '1'='1'`，显然这是成立的，也会返回成功。

:::

:::note
:::

<slide class="bg-trans-dark" :class=" size-50 aligncenter" >

## 防御措施
---

* 不要给出过于具体的错误信息 {.animated.fadeInUp.text-nomal}
* 检查数据类型 {.animated.fadeInUp.delay-400.text-nomal}
* 对数据进行转义 {.animated.fadeInUp.delay-800.text-nomal}
* 使用参数化查询{.animated.fadeInUp.delay-1200.text-nomal}
* 使用 ORM（对象关系映射） {.animated.fadeInUp.delay-1600.text-nomal}

:::note
这个问题一般情况下是交给后台同学去考虑了，因为现在前后端分离了嘛，不过老代码中，PHP里是有操作数据库的逻辑的，可以适当的了解下，那么怎么去预防了，大致可以从这几个方向出发。

什么是参数化查询呢，相当于分成两条语句，第一步明确目的，不能再被修改；第二步不管传啥只当作数据处理

使用 ORM简单的可以理解为，不用写原声sql语法，通过ORM语法来操作数据库，这种集成的框架一般都已经做好了防sql注入的功能。
:::

<slide class="bg-black" image="./images/bg3.jpg .dark">
## 上传问题

---

上传的文件被当做程序解析执行。{.text-nomal}

:::note
最后一个就是上传问题，我们平时都有用到过上传文件的功能吧，上传图片啊，Excel表格啥的，如果此时我们上传了一个含有可执行代码片段的文件，当我们点击下载该文件的时候，恶意代码片段就会被执行，
:::

<slide class="bg-black slide-center" image="./images/bg3.jpg  .dark">
## 防御措施 :fa-tree: 
---
* 限制上传后缀 {.animated.fadeInUp.text-nomal}
* 文件类型检测 {.animated.fadeInUp.delay-400.text-nomal}
* 检查文件内容以什么开头 {.animated.fadeInUp.delay-800.text-nomal}
* 权限控制：可写可执行互斥原则{.animated.fadeInUp.delay-1200.text-nomal}
* 程序输出：就是不运行，有个读写的过程 {.animated.fadeInUp.delay-1600.text-nomal}

:::note
这个问题也比较简单去避免。一个就是增加校验规则，对文件类型进行检测以及文件后缀名进行限制，通过了这个限制之后，我们还可以对文件的内容头部进行验证，确保该文件不是被修改过的伪装文件。
:::

<slide class="bg-black-blue aligncenter" image="./images/VW-pFREtl0k.jpg .dark">

# 谢谢观看~~ {.text-landing}