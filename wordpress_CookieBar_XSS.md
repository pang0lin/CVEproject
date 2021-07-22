# Cookie Bar<=1.8.8 Authenticated Stored Cross-Site Scripting(XSS)
## Description
    The plugin doesn't properly sanitise Cookie Bar Message	setting, which result into a Stored Cross-Site Scripting(XSS).
## Affects Plugins
    Cookie Bar<=1.8.8
    https://wordpress.org/plugins/cookie-bar/
## Author
    pang0lin@webray.com.cn inc  
## Proof of Concept
Edit the "Cookie Bar Message" text area to "asdasdasd<img src=1 onerror=alert(1)>"
![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/wordpress_cookie-bar_xss1.png "Wordpress plugin cookie-bar XSS")
Visit the home page. We can see the alert page.
![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/wordpress_cookie-bar_xss2.png "Wordpress plugin cookie-bar XSS")
