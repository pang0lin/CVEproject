## SP Project & Document Manager <= 4.22 - Authenticated Shell Upload

## Description
    This issue is the bypass for https://wpscan.com/vulnerability/8f6e82d5-c0e9-468e-acb8-7cd549f6a45a. The author has limited to upload a file of 'x.pHp', but we can upload a file like '1.php.' .If the target is running on windows environment， it will save as '1.php'

## Affects Plugins
    sp-client-document-manager <= 4.22
    https://wordpress.org/plugins/sp-client-document-manager/
    
## Author
    pang0lin@webray.com.cn inc 
    
## Condition
    Windows environment

## Proof of Concept
1. Create the SP Project & Document Manager page such as 'sp-document'
2. Upload a file and intercept the request.
3. Rename the dlg-upload-file[] parameter from '1.txt' with '1.php.' , it is very important the filename endswith 'php.' .
![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/wordpress_SP-Project_fileupload_1.png "wordpress_SP-Project_fileupload_1")
4. Visit your webshell http://xxx.com/wp-content/uploads/sp-client-document-manager/[user's uid]/1.php
![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/wordpress_SP-Project_fileupload_2.png "wordpress_SP-Project_fileupload_2")
