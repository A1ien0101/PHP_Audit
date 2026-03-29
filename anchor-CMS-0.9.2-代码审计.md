# Anchor CMS 0.9.2 -- filter_var()

当用户访问了不存在的资源时, 程序调用了 themes/default 下的 404.php 模板文件

```php
<?php theme_include('header'); ?>

    <section class="content wrap">
        <h1>Page not found</h1>

        <p>Unfortunately, the page <code>/<?php echo current_url(); ?></code> could not be found. Your best bet is either to try the <a href="<?php echo base_url(); ?>">homepage</a>, try <a href="#search">searching</a>, or go and cry in a corner (although I don’t recommend the latter).</p>
    </section>

<?php theme_include('footer'); ?>
```

能够注意到 404.php 中的 `<code>` 标签中的 current_url() 函数, 通过vscode(Ctrl+Shit+F 和 .* 正则匹配模式), 在 anchor/functions/helpers.php 找到了 current_url() 函数
它是由Uri类的current方法实现

```php
function current_url() {
    return Uri::current();
}
```

继续跟进 Uri 与 current(), 在 /system/uri.php 中发现 current() 调用了 static::detect() 方法

```php
    /**
     * Get the current uri string
     *
     * @return string
     */
    public static function current() {
        if(is_null(static::$current)) static::$current = static::detect();

        return static::$current;
    }
```

在 current() 方法下方, 能够直接找到 detect() 方法, 其中 $server 能够得到 'REQUEST_URI', 'PATH_INFO', 'ORIG_PATH_INFO' 的值, 如果存在其中的某一个值, 并且符合 filter_var($uri, FILTER_SANITIZE_URL)) 和 parse_url($uri, PHP_URL_PATH)), $uri将会作为值传入 static::format() 中

```php
    /**
     * Try and detect the current uri
     *
     * @return string
     */
    public static function detect() {
        // create a server object from global
        $server = new Server($_SERVER);

        $try = array('REQUEST_URI', 'PATH_INFO', 'ORIG_PATH_INFO');

        foreach($try as $method) {

            // make sure the server var exists and is not empty
            if($server->has($method) and $uri = $server->get($method)) {

                // apply a string filter and make sure we still have somthing left
                if($uri = filter_var($uri, FILTER_SANITIZE_URL)) {

                    // make sure the uri is not malformed and return the pathname
                    if($uri = parse_url($uri, PHP_URL_PATH)) {
                        return static::format($uri, $server);
                    }

                    // woah jackie, we found a bad'n
                    throw new ErrorException('Malformed URI');
                }
            }
        }

        throw new OverflowException('Uri was not detected. Make sure the REQUEST_URI is set.');
    }
```

继续跟进 static::format() 方法(位于 current() 方法下方), 能够发现程序进行了 3 次过滤, 但是没有针对XSS攻击形式进行任何过滤(过滤了非法字符, 但是允许了所有的字符, 数字, 和`$-_.+!*'(),{}|\\^~[]`<>#%";/?:@&=`), 只是获取了用户访问的文件名

```php
    /**
     * Format the uri string remove any malicious
     * characters and relative paths
     *
     * @param string
     * @return string
     */
    public static function format($uri, $server) {
        // Remove all characters except letters,
        // digits and $-_.+!*'(),{}|\\^~[]`<>#%";/?:@&=.
        $uri = filter_var(rawurldecode($uri), FILTER_SANITIZE_URL);

        // remove script path/name
        $uri = static::remove_script_name($uri, $server);

        // remove the relative uri
        $uri = static::remove_relative_uri($uri);

        // return argument if not empty or return a single slash
        return trim($uri, '/') ?: '/';
    }
```

也能够构造出XSS Payload

```
index.php/<script>alert('www.sec-redclub.com')</script>

// phptest.auti/index.php/%3Cscript%3Ealert(1)%3C/script%3E
// phptest.auti/index.php/<script>Ealert(1)</script>
```

