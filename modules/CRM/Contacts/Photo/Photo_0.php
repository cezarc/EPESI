<?php
/**
 * Activities history for Company and Contacts
 * @author Arkadiusz Bisaga <abisaga@telaxus.com>
 * @copyright Copyright &copy; 2008, Telaxus LLC
 * @license MIT
 * @version 1.0
 * @package epesi-crm
 * @subpackage contacts-photo
 */
defined("_VALID_ACCESS") || die('Direct access forbidden');

class CRM_Contacts_Photo extends Module {
	private $submitted = false;

	public function body($record) {
		$form = & $this->init_module('Utils/FileUpload',array(false));
		$form->addElement('header', 'upload', $this->t('Upload new photo').': '.$record['last_name'].' '.$record['first_name']);
		
		$form->set_upload_button_caption('Save');

		$form->add_upload_element();
		
		Base_ActionBarCommon::add('save','Save',$form->get_submit_form_href());
		Base_ActionBarCommon::add('delete', 'Cancel', $this->create_back_href());

		$this->display_module($form, array( array($this,'submit_attach'), $record));

		if ($this->is_back() || $this->submitted) {
			$x = ModuleManager::get_instance('/Base_Box|0');
			if(!$x) trigger_error('There is no base box module instance',E_USER_ERROR);
			return $x->pop_main();
		}
	}

	public function submit_attach($file,$oryg,$data,$record) {	
		$local = $this->get_data_dir();
		$i = 0;
		$pattern = $local.'/'.$record['id'].'_';
		while (file_exists($pattern.$i)) $i++;
		$dest_file = $pattern.$i;
		if ($file) {
			rename($file,$dest_file);
		}
		$this->submitted = true;
	}
}

?>