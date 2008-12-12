<?php
/**
 * Apps/MailClient and other CRM functions connector
 * @author pbukowski@telaxus.com
 * @copyright pbukowski@telaxus.com
 * @license SPL
 * @version 0.1
 * @package crm-mailclient
 */
defined("_VALID_ACCESS") || die('Direct access forbidden');

class CRM_MailClientCommon extends ModuleCommon {
	private static $my_rec;

	public static function move_action($msg, $dir) {
		$sent = false;
		if(ereg('^(Drafts|Sent)',$dir))
			$sent = true;

		if($sent) {
			$addr = $msg['headers']['to'];
		} else {
			$addr = $msg['headers']['from'];
		}
		if(ereg('^[^<]*<(.+)>$',$addr,$reqs))
			$addr = $reqs[1];
		if(is_numeric($addr))
			$c = CRM_ContactsCommon::get_contacts(array('login'=>$addr));
		else
			$c = CRM_ContactsCommon::get_contacts(array('email'=>$addr));
		if(empty($c)) {
			Epesi::alert(Base_LangCommon::ts('CRM_MailClient','Contact not found'));
			return false;
		}
		
		$headers = '';
		foreach($msg['headers'] as $cap=>$h)
			$headers .= $cap.': '.$h."\n";
			
		$data_dir = self::Instance()->get_data_dir();
		foreach($c as $i) {
			if($sent) {
				$to = $i['id'];
				$from = self::$my_rec['id'];
			} else {
				$to = self::$my_rec['id'];
				$from = $i['id'];
			}
			DB::Execute('INSERT INTO crm_mailclient_mails(from_contact_id,to_contact_id,subject,headers,body,body_type,body_ctype,delivered_on) VALUES(%d,%d,%s,%s,%s,%s,%s,%T)',array($from,$to,$msg['subject'],$headers,$msg['body'],$msg['type'],$msg['ctype'],strtotime($msg['headers']['date'])));
			$mid = DB::Insert_ID('crm_mailclient_mails','id');
			foreach($msg['attachments'] as $k=>$a) {
				DB::Execute('INSERT INTO crm_mailclient_attachments(mail_id,name,type,cid,disposition) VALUES(%d,%s,%s,%s,%s)',array($mid,$k,$a['type'],$a['id'],$a['disposition']));
				$aid = DB::Insert_ID('crm_mailclient_mails','id');
				file_put_contents($data_dir.$aid,$a['body']);
			}
			Utils_WatchdogCommon::new_event('contact',$to,'N_New mail');
			Utils_WatchdogCommon::new_event('contact',$from,'N_New mail');
		}
		return true;
	}
	
	public static function goto_action($msg,$dir) {
		$sent = false;
		if(ereg('^(Drafts|Sent)',$dir))
			$sent = true;

		if($sent)
			$addr = $msg['headers']['to'];
		else
			$addr = $msg['headers']['from'];
		if(ereg('^[^<]*<(.+)>$',$addr,$reqs))
			$addr = $reqs[1];
		if(is_numeric($addr))
			$c = CRM_ContactsCommon::get_contacts(array('login'=>$addr));
		else
			$c = CRM_ContactsCommon::get_contacts(array('email'=>$addr));
		if(empty($c)) {
			Epesi::alert(Base_LangCommon::ts('CRM_MailClient','Contact not found'));
			return false;
		}
		if(count($c)!==1) {
			Epesi::alert(Base_LangCommon::ts('CRM_MailClient','Found more then one contact with specified mail address'));
			return false;
		}
		$c = array_pop($c);
		$x = ModuleManager::get_instance('/Base_Box|0');
		if (!$x) trigger_error('There is no base box module instance',E_USER_ERROR);
		$x->push_main('Utils/RecordBrowser','view_entry',array('view', $c['id']),array('contact'));
		return true;
	}

	public static function mail_actions() {
		$ret = array('Go to contact'=>array('func'=>array('CRM_MailClientCommon','goto_action'),'delete'=>0));
		self::$my_rec = CRM_ContactsCommon::get_my_record();
		if(self::$my_rec['id']!==-1)
			$ret['Move to CRM']=array('func'=>array('CRM_MailClientCommon','move_action'),'delete'=>1);
		return $ret;
	}
}

?>