<?php
/**
 * @author Arkadiusz Bisaga <abisaga@telaxus.com>
 * @copyright Copyright &copy; 2006, Telaxus LLC
 * @version 1.0
 * @license SPL
 * @package epesi-libs
 * @subpackage exportxls
 */
defined("_VALID_ACCESS") || die('Direct access forbidden');

class Libs_ExportXLS extends Module {
	public function create_xls_href($callback, $args=array(), $dlfilename=null) {
		$xls_id = $this->get_path();
		$this->set_module_variable('callback', $callback);
		if($dlfilename==null) $dlfilename='download';
		return 'href="modules/Libs/ExportXLS/download.php?'.http_build_query(array('id'=>CID,'xls'=>$xls_id,'args'=>$args,'filename'=>$dlfilename.'.xls')).'" target="_blank"';
	}
}

?>